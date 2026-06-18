"""Graph-based vulnerability backtracking analyzer.

Operates on an already-built igraph AST graph (with ast/own/cg/dfg edges)
to perform taint analysis.  Graph-native replacement for the legacy
``_parameters_back_impl`` and ``function_back`` in php/parser.py.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

import igraph as ig

from core.graph.node_edge_schema import (
    EdgeLabel, NodeLabel, OperatorType,
)

__all__ = ["GraphAnalyzer", "AnalysisResult"]
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# igraph 1.0 helper — Vertex / Edge lack dict-style .get()
# ---------------------------------------------------------------------------

def _vattr(vertex_or_edge, key: str, default=None):
    """Safely read an igraph Vertex / Edge attribute (equiv to dict.get)."""
    try:
        return vertex_or_edge[key]
    except (KeyError, TypeError):
        return default

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPERGLOBALS: frozenset[str] = frozenset({
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER",
    "$_SESSION", "$_ENV", "$HTTP_RAW_POST_DATA", "$argc", "$argv",
})

_REPAIR_FUNCTIONS: frozenset[str] = frozenset({
    "htmlspecialchars", "htmlentities", "strip_tags", "urlencode",
    "rawurlencode", "addslashes", "intval", "floatval",
    "escapeshellarg", "escapeshellcmd",
    "mysql_real_escape_string", "mysqli_real_escape_string",
    "pg_escape_string", "pg_escape_bytea",
    "SQLite3::escapeString", "PDO::quote",
    "trim", "stripslashes", "filter_var", "filter_input",
    "htmlspecialchars_decode", "basename", "realpath",
    "ctype_alnum", "ctype_digit", "ctype_alpha",
    "is_numeric", "json_encode", "serialize",
})

_SINK_FUNCTIONS: frozenset[str] = frozenset({
    "system", "exec", "passthru", "shell_exec", "popen", "proc_open",
    "eval", "assert", "preg_replace", "create_function",
    "call_user_func", "call_user_func_array",
    "usort", "uasort", "array_map", "array_filter",
    "echo", "print", "printf", "vprintf", "sprintf", "vsprintf",
    "file_put_contents", "file_get_contents", "fopen", "readfile",
    "include", "require", "include_once", "require_once",
    "header", "setcookie", "mail",
    "unlink", "rmdir", "mkdir", "rename", "copy", "move_uploaded_file",
    "chmod", "chown", "chgrp", "symlink", "link",
    "curl_exec", "curl_setopt",
    "mysqli_query", "mysql_query", "pg_query", "sqlite_query",
    "unserialize",
})

_TYPE_VALIDATION_FUNCS: frozenset[str] = frozenset({
    "is_numeric", "is_int", "is_integer", "is_float", "is_double",
    "ctype_digit", "ctype_alnum", "ctype_alpha", "ctype_xdigit",
})

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
}

# ---------------------------------------------------------------------------
# AnalysisResult
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    """Unified analysis result — replaces legacy (code, cp, expr_lineno).

    code values: 1=controllable, 2=repaired, 3=inconclusive, -1=uncontrollable,
    'deps'=depends on caller variables.
    """
    code: int | str = 3
    reason: str = ""
    chain: list[dict] = field(default_factory=list)
    path: list[int] = field(default_factory=list)
    deps: list[str] = field(default_factory=list)
    expr_lineno: int = 0

    @property
    def is_controllable(self) -> bool: return self.code == 1
    @property
    def is_repaired(self) -> bool: return self.code == 2
    @property
    def is_inconclusive(self) -> bool: return self.code == 3
    @property
    def is_uncontrollable(self) -> bool: return self.code == -1
    @property
    def has_deps(self) -> bool: return self.code == "deps"

    def __repr__(self) -> str:
        return (f"AnalysisResult(code={self.code!r}, reason={self.reason!r}, "
                f"path_len={len(self.path)}, deps={self.deps})")

# ---------------------------------------------------------------------------
# GraphAnalyzer
# ---------------------------------------------------------------------------

class GraphAnalyzer:
    """Vulnerability backtracking on an igraph AST graph.

    Usage::

        analyzer = GraphAnalyzer(graph, language="php")
        sinks = analyzer.find_sinks()
        for sink in sinks:
            result = analyzer.parameters_back(sink["vid"])
    """

    def __init__(self, graph: ig.Graph, language: str = "php") -> None:
        self.graph = graph
        self.language = language
        self._decision_cache: dict[int, AnalysisResult] = {}
        self._call_stack: list[str] = []

    # --- Sink discovery ---------------------------------------------------

    def find_sinks(self, sink_names: list[str] | None = None) -> list[dict]:
        """Locate sink operator nodes (call/static_call/method_call matching
        *sink_names*, defaulting to built-in _SINK_FUNCTIONS).

        Returns list of dicts with keys: vid, name, lineno, file_path, type,
        arg_vids (list of argument vertex ids).
        """
        if sink_names is None:
            sink_names = sorted(_SINK_FUNCTIONS)
        name_set = set(sink_names)
        results: list[dict] = []

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in _CALL_TYPES:
                continue
            callee_name = self._resolve_callee_name(v.index)
            if not callee_name:
                continue
            if callee_name.startswith("\\"):
                callee_name = callee_name[1:]
            if callee_name not in name_set:
                continue
            # Collect argument vids via ast[role=arg] edges
            arg_vids = [
                e.target for e in self.graph.es.select(_source=v.index, label="ast")
                if _vattr(e, "role") == "arg"
            ]
            results.append({
                "vid": v.index, "name": callee_name,
                "lineno": _vattr(v, "lineno", 0),
                "file_path": _vattr(v, "file_path", ""),
                "type": _vattr(v, "type", ""),
                "arg_vids": arg_vids,
            })
        logger.debug("find_sinks found %d sink node(s)", len(results))
        return results

    # --- Controllability backtracking (core) ------------------------------

    def parameters_back(self, start_vid: int, context_vid: int | None = None,
                       max_depth: int = 50) -> AnalysisResult:
        """BFS backward along dfg edges to determine controllability.

        Classification per upstream node:
        1. Superglobal source (``$_GET`` etc.) → code=1
        2. Repair function in chain → code=2
        3. Constant / literal → skip (not controllable)
        4. Function call → delegate to analyze_function_return
        5. Ordinary identifier → continue BFS
        6. Max depth / no more upstream → code=3
        """
        cache_key = (start_vid, context_vid)
        if cache_key in self._decision_cache:
            return self._decision_cache[cache_key]

        sv = self.graph.vs[start_vid]
        sname = _vattr(sv, "name", "")

        # Quick checks on start node itself
        if self._is_source_variable(sname):
            return self._cached(cache_key, AnalysisResult(
                code=1, reason=f"'{sname}' is a superglobal",
                chain=[{"step": "source", "vid": start_vid, "name": sname, "code": 1}],
                path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        if _vattr(sv, "label") == NodeLabel.CONST.value:
            return self._cached(cache_key, AnalysisResult(
                code=-1, reason=f"'{sname}' is a constant",
                chain=[{"step": "const", "vid": start_vid, "name": sname, "code": -1}],
                path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # Check member access on start node: $_GET['cmd'] / $obj->prop
        if _vattr(sv, "type") == "property":
            for me in self.graph.es.select(_target=start_vid, label="member"):
                obj_vid = me.source
                obj_v = self.graph.vs[obj_vid]
                obj_name = _vattr(obj_v, "name", "")
                if self._is_source_variable(obj_name):
                    return self._cached(cache_key, AnalysisResult(
                        code=1,
                        reason=f"superglobal '{obj_name}' via member access",
                        chain=[{"step": "member_source", "vid": obj_vid,
                                "name": obj_name, "code": 1}],
                        path=[start_vid, obj_vid],
                        expr_lineno=_vattr(obj_v, "lineno", 0)))

        if _vattr(sv, "label") == NodeLabel.OPERATOR.value \
                and _vattr(sv, "type") in _CALL_TYPES:
            callee = self._resolve_callee_name(start_vid)
            if callee and self._is_repair_function(callee):
                return self._cached(cache_key, AnalysisResult(
                    code=2, reason=f"calls repair '{callee}'",
                    chain=[{"step": "repair", "vid": start_vid, "name": callee, "code": 2}],
                    path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

        # BFS backward along dfg edges
        visited: set[int] = {start_vid}
        queue: deque[tuple[int, int, list[int]]] = deque()
        queue.append((start_vid, 0, [start_vid]))

        while queue:
            cur_vid, depth, path = queue.popleft()
            for up_vid in self._get_dfg_sources(cur_vid):
                if up_vid in visited:
                    continue
                visited.add(up_vid)
                uv = self.graph.vs[up_vid]
                uname = _vattr(uv, "name", "")
                ulabel = _vattr(uv, "label", "")
                utype = _vattr(uv, "type", "")
                new_path = path + [up_vid]

                # Rule 1: superglobal
                if self._is_source_variable(uname):
                    logger.debug("source found '%s' vid=%d", uname, up_vid)
                    return self._cached(cache_key, AnalysisResult(
                        code=1, reason=f"superglobal '{uname}'",
                        chain=[{"step": "dfg", "vid": up_vid, "name": uname, "code": 1}],
                        path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 2: constant — skip, keep searching
                if ulabel == NodeLabel.CONST.value:
                    continue

                # Rule 3: repair function
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)
                    if callee and self._is_repair_function(callee):
                        return self._cached(cache_key, AnalysisResult(
                            code=2, reason=f"repair '{callee}'",
                            chain=[{"step": "dfg", "vid": up_vid, "name": callee, "code": 2}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 4: function call — trace return value
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)
                    if callee and callee not in self._call_stack:
                        func_vids = self.find_function_def(callee, from_vid=up_vid)
                        if func_vids:
                            self._call_stack.append(callee)
                            try:
                                ret = self.analyze_function_return(up_vid, func_vids[0])
                            finally:
                                self._call_stack.pop()
                            if ret.is_controllable or ret.is_repaired:
                                ret.path = new_path + ret.path
                                return self._cached(cache_key, ret)
                            if ret.has_deps:
                                for dep_name in ret.deps:
                                    dep_vid = self._find_identifier_by_name(
                                        dep_name, context_vid)
                                    if dep_vid is not None:
                                        dep_res = self.parameters_back(
                                            dep_vid, context_vid, max_depth - depth)
                                        if dep_res.is_controllable:
                                            return self._cached(cache_key, dep_res)

                # Continue BFS
                if ulabel in (NodeLabel.IDENTIFIER.value,
                              NodeLabel.OPERATOR.value,
                              NodeLabel.RETURN.value):
                    if depth + 1 < max_depth:
                        queue.append((up_vid, depth + 1, new_path))

                # Rule 5: member access — e.g. $_GET['id'] or $obj->prop
                # The identifier 'id' is the property/key, track back via
                # member edge to find the object node ($_GET).
                if ulabel == NodeLabel.IDENTIFIER.value and _vattr(uv, "type") == "property":
                    for me in self.graph.es.select(_target=up_vid, label="member"):
                        obj_vid = me.source
                        obj_v = self.graph.vs[obj_vid]
                        obj_name = _vattr(obj_v, "name", "")
                        if self._is_source_variable(obj_name):
                            return self._cached(cache_key, AnalysisResult(
                                code=1,
                                reason=f"superglobal '{obj_name}' via member access",
                                chain=[{"step": "member_source", "vid": obj_vid,
                                        "name": obj_name, "code": 1}],
                                path=new_path + [obj_vid],
                                expr_lineno=_vattr(obj_v, "lineno", 0)))

        # Exhausted
        return self._cached(cache_key, AnalysisResult(
            code=3,
            reason=f"Inconclusive for vid={start_vid} ('{sname}') after {max_depth} hops",
            chain=[{"step": "exhausted", "vid": start_vid, "name": sname, "code": 3}],
            path=[start_vid] + list(visited), expr_lineno=_vattr(sv, "lineno", 0)))

    # --- Function definition lookup --------------------------------------

    def find_function_def(self, func_name: str,
                           from_vid: int | None = None) -> list[int]:
        """Find function/method definition node(s).  Prefers same-file matches."""
        scope_path: str | None = None
        if from_vid is not None:
            scope_path = _vattr(self.graph.vs[from_vid], "file_path", None)

        results: list[int] = []
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.FUNCTION.value:
                continue
            vn = _vattr(v, "name", "")
            vf = _vattr(v, "fullname", "")
            if not (vn == func_name or vf.endswith("\\" + func_name) or vf == func_name):
                continue
            if scope_path:
                (results.insert if _vattr(v, "file_path") == scope_path
                 else results.append)(v.index)
            else:
                results.append(v.index)
        logger.debug("find_function_def('%s', from=%s) → %s",
                      func_name, from_vid, results)
        return results

    # --- Function return analysis -----------------------------------------

    def analyze_function_return(self, call_vid: int,
                                  func_vid: int) -> AnalysisResult:
        """Analyze whether a function's return value is controllable.

        1. Map formal params to actual args (positional).
        2. Find return nodes and trace their expressions backward.
        3. If return depends on a controllable param → code=1.
           If return depends on a caller variable → code='deps'.
        """
        call_v = self.graph.vs[call_vid]

        # Formal params: own children with label=parameter
        param_vids = self._find_own_children(func_vid, child_label=NodeLabel.PARAMETER.value)
        formal: dict[int, tuple[int, str]] = {}
        for pvid in param_vids:
            pv = self.graph.vs[pvid]
            pidx = _vattr(pv, "index", len(formal))
            formal[int(pidx)] = (pvid, _vattr(pv, "name", ""))

        # Actual args: ast edges with role=arg from the call operator
        actual_args: dict[int, int] = {}
        arg_counter = 0
        for e in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(e, "role") == "arg":
                idx = _vattr(e, "index")
                actual_args[int(idx) if idx is not None else arg_counter] = e.target
                arg_counter += 1

        # Classify formal params by actual arg controllability
        controllable_indices: set[int] = set()
        caller_deps: list[str] = []
        for fidx, (pvid, pname) in formal.items():
            if fidx not in actual_args:
                continue
            av = self.graph.vs[actual_args[fidx]]
            aname = _vattr(av, "name", "")
            if self._is_source_variable(aname):
                controllable_indices.add(fidx)
            elif _vattr(av, "label") == NodeLabel.CONST.value:
                pass
            else:
                caller_deps.append(aname)

        # Find return children
        return_vids = self._find_own_children(func_vid, child_label=NodeLabel.RETURN.value)
        if not return_vids:
            return AnalysisResult(code=3,
                                  reason=f"No return in func vid={func_vid}",
                                  expr_lineno=_vattr(call_v, "lineno", 0))

        for ret_vid in return_vids:
            rv = self.graph.vs[ret_vid]
            # Find return expression via ast[role=value/rhs] or dfg backward
            expr_vid: int | None = None
            for e in self.graph.es.select(_source=ret_vid, label="ast"):
                if _vattr(e, "role") in ("value", "rhs"):
                    expr_vid = e.target
                    break
            if expr_vid is None:
                ups = self._get_dfg_sources(ret_vid)
                expr_vid = ups[0] if ups else None
            if expr_vid is None:
                continue

            ev = self.graph.vs[expr_vid]
            ename = _vattr(ev, "name", "")

            # Check if expr directly names a controllable formal param
            for fidx, (pvid, pname) in formal.items():
                if ename == pname:
                    if fidx in controllable_indices:
                        return AnalysisResult(
                            code=1,
                            reason=f"Returns controllable param '{pname}'",
                            path=[call_vid, func_vid, ret_vid, expr_vid],
                            expr_lineno=_vattr(rv, "lineno", 0))
                    caller_deps.append(pname)

            # Recurse into return expression
            sub = self.parameters_back(expr_vid, context_vid=func_vid, max_depth=20)
            if sub.is_controllable:
                return sub
            if sub.has_deps:
                caller_deps.extend(sub.deps)

        if controllable_indices:
            return AnalysisResult(code=1, reason="Return depends on controllable params",
                                  deps=caller_deps,
                                  expr_lineno=_vattr(call_v, "lineno", 0))
        if caller_deps:
            return AnalysisResult(code="deps",
                                  reason=f"Return depends on caller vars: {caller_deps}",
                                  deps=caller_deps,
                                  expr_lineno=_vattr(call_v, "lineno", 0))
        return AnalysisResult(code=3,
                              reason=f"Return inconclusive (call={call_vid}, func={func_vid})",
                              expr_lineno=_vattr(call_v, "lineno", 0))

    # --- Branch constraint analysis ---------------------------------------

    def analyze_branch_constraint(self, sink_vid: int) -> dict:
        """Check if sink is protected by a branch condition.

        Walks up own edges to find enclosing branch nodes, then checks
        their condition for type-validation, strict regex, etc.

        Returns: {"protected": bool, "constraints": [...], "reason": str}
        """
        constraints: list[dict] = []
        protected = False

        for bvid in self._find_enclosing_branches(sink_vid):
            bv = self.graph.vs[bvid]
            cond = _vattr(bv, "condition", "")
            btype = _vattr(bv, "type", "")
            if not cond:
                continue
            for func in _TYPE_VALIDATION_FUNCS:
                if func in cond:
                    constraints.append({"type": "type_validation",
                                        "function": func, "branch_type": btype})
                    protected = True
            if "preg_match" in cond and self._has_strict_regex(cond):
                constraints.append({"type": "regex_validation",
                                    "pattern": cond, "branch_type": btype})
                protected = True
            if "===" in cond or "==" in cond:
                constraints.append({"type": "equality_check",
                                    "condition": cond, "branch_type": btype})

        return {
            "protected": protected,
            "constraints": constraints,
            "reason": (f"Protected: {constraints}" if protected
                       else f"No protective constraints for vid={sink_vid}"),
        }

    # --- Decision marking -------------------------------------------------

    def mark_decision(self, vid: int, decision: dict) -> None:
        """Append analysis decision to vertex's 'analysis_decisions' attribute."""
        v = self.graph.vs[vid]
        existing: list = _vattr(v, "analysis_decisions", [])
        if not isinstance(existing, list):
            existing = []
        existing.append(decision)
        v["analysis_decisions"] = existing

    # --- Taint path search ------------------------------------------------

    def find_taint_paths(self, source_vid: int, sink_vid: int,
                         max_depth: int = 20) -> list[dict]:
        """BFS forward along dfg edges from source to sink.

        Returns list of dicts: {"path": [vid...], "length": int, "decisions": []}
        """
        results: list[dict] = []
        visited: set[int] = set()
        queue: deque[tuple[int, int, list[int]]] = deque()
        queue.append((source_vid, 0, [source_vid]))

        while queue:
            cur_vid, depth, path = queue.popleft()
            if depth > max_depth:
                continue
            if cur_vid == sink_vid:
                results.append({"path": path, "length": len(path), "decisions": []})
                continue
            for e in self.graph.es.select(_source=cur_vid, label="dfg"):
                tgt = e.target
                if tgt not in visited:
                    visited.add(tgt)
                    queue.append((tgt, depth + 1, path + [tgt]))
        return results

    # --- Internal helpers -------------------------------------------------

    def _cached(self, key, result: AnalysisResult) -> AnalysisResult:
        self._decision_cache[key] = result
        return result

    def _is_source_variable(self, name: str) -> bool:
        if not name:
            return False
        if name in _SUPERGLOBALS:
            return True
        if "[" in name:
            return name.split("[", 1)[0] in _SUPERGLOBALS
        return False

    def _is_repair_function(self, name: str) -> bool:
        if not name:
            return False
        clean = name.lstrip("\\")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        return clean in _REPAIR_FUNCTIONS

    def _is_sink_function(self, name: str) -> bool:
        if not name:
            return False
        clean = name.lstrip("\\")
        if "\\" in clean:
            clean = clean.rsplit("\\", 1)[-1]
        return clean in _SINK_FUNCTIONS

    def _get_dfg_sources(self, vid: int) -> list[int]:
        """Upstream vertices via dfg edges (target=vid → source)."""
        return [e.source for e in self.graph.es.select(_target=vid, label="dfg")]

    def _get_context(self, vid: int) -> int | None:
        """Walk up own edges to find enclosing function/file vid."""
        cur, seen = vid, set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return cur
            inc = self.graph.es.select(_target=cur, label="own")
            cur = inc[0].source if inc else None
        return None

    def _find_own_children(self, parent_vid: int,
                           child_label: str | None = None,
                           index: int | None = None) -> list[int]:
        """Vertex IDs of children linked via own edges."""
        children: list[int] = []
        for e in self.graph.es.select(_source=parent_vid, label="own"):
            child = self.graph.vs[e.target]
            if child_label and _vattr(child, "label") != child_label:
                continue
            if index is not None and _vattr(e, "index") != index:
                continue
            children.append(e.target)
        return children

    def _resolve_callee_name(self, op_vid: int) -> str | None:
        """Resolve callee name from call operator.

        Strategy:
        1. Look for ast[role=callee] edge → target name.
        2. Fall back to cg edge → target function node name.
        3. Fall back to operator node's own ``name`` attribute.
        """
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                t = self.graph.vs[e.target]
                return _vattr(t, "name") or _vattr(t, "value")
        # Fallback: cg edge target
        for e in self.graph.es.select(_source=op_vid, label="cg"):
            return _vattr(self.graph.vs[e.target], "name")
        # Last resort: operator's own name
        return _vattr(self.graph.vs[op_vid], "name")

    def _find_identifier_by_name(self, name: str,
                                  context_vid: int | None = None) -> int | None:
        """Find identifier vertex by name, preferring same-file matches."""
        scope = None
        if context_vid is not None:
            scope = _vattr(self.graph.vs[context_vid], "file_path", None)
        candidates: list[int] = []
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.IDENTIFIER.value:
                continue
            if _vattr(v, "name") == name:
                if scope and _vattr(v, "file_path") == scope:
                    return v.index
                candidates.append(v.index)
        return candidates[0] if candidates else None

    def _find_enclosing_branches(self, vid: int) -> list[int]:
        """Find all branch ancestor nodes via own edges."""
        result: list[int] = []
        cur, seen = vid, set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            if _vattr(self.graph.vs[cur], "label") == NodeLabel.BRANCH.value:
                result.append(cur)
            inc = self.graph.es.select(_target=cur, label="own")
            cur = inc[0].source if inc else None
        return result

    @staticmethod
    def _has_strict_regex(condition: str) -> bool:
        """Check if condition contains a strict anchored regex (no wildcard .)."""
        m = re.search(r"""['"](/[^'"]*?)['"]""", condition)
        if not m:
            return False
        pat = m.group(1)
        if len(pat) < 4 or not pat.startswith("^") or not pat.endswith("$"):
            return False
        return "." not in pat[1:-1].replace("\\.", "")

    def reset(self) -> None:
        """Clear decision cache and call stack."""
        self._decision_cache.clear()
        self._call_stack.clear()
        logger.debug("GraphAnalyzer state reset")
