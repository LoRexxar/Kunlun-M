"""Graph-based vulnerability backtracking analyzer.

Operates on an already-built igraph AST graph (with ast/own/use/cg/dfg edges)
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
from utils.igraph_compat import _vattr

__all__ = ["GraphAnalyzer", "AnalysisResult"]
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPERGLOBALS: frozenset[str] = frozenset({
    # PHP superglobals
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER",
    "$_SESSION", "$_ENV", "$HTTP_RAW_POST_DATA", "$argc", "$argv",
    # Python web framework sources (object names)
    "request.GET", "request.POST", "request.REQUEST", "request.COOKIES",
    "request.FILES", "request.data", "request.body", "request.query_params",
    "request.query_string", "request.form",
    # Flask/WSGI
    "flask.request", "django.http.HttpRequest",
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
    "extract", "parse_str",
    "highlight_file", "show_source", "php_strip_whitespace",
    "simplexml_load_string", "simplexml_load_file",
    # Python
    "HttpResponse", "JsonResponse", "render", "render_to_string",
    "write", "writelines",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "pickle.loads", "yaml.load", "exec", "eval",
    # Java
    "start", "ProcessBuilder",
    # Go
    "exec.Command", "Output", "Run",
    # C / C++
    "system", "popen", "pclose",
    # JavaScript
    "write", "eval",
})

_TYPE_VALIDATION_FUNCS: frozenset[str] = frozenset({
    # PHP
    "is_numeric", "is_int", "is_integer", "is_float", "is_double",
    "ctype_digit", "ctype_alnum", "ctype_alpha", "ctype_xdigit",
    "ctype_lower", "ctype_upper", "ctype_graph", "ctype_print",
    "ctype_punct", "ctype_space", "ctype_cntrl",
    # Python
    "isinstance", "issubclass", "hasattr", "callable",
    "isdigit", "isalpha", "isalnum", "isdecimal", "isnumeric",
    "isupper", "islower", "istitle", "isspace",
    "isascii", "isidentifier", "isprintable",
    "isfinite", "isinf", "isnan",
})

_SAFE_CONSTRAINT_OPS: frozenset[str] = frozenset({"==", "==="})

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
    def is_controllable(self) -> bool: return self.code in (1, 4)
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

    图上的 function 节点可携带 taint_type 属性（由 knowledge_bridge 在
    构建阶段标注）。parameters_back 遇到 call 时沿 cg 边找到 function，
    直接根据 function 节点的 taint_type 判定可控性，无需运行时查询知识库。
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
                # 后缀匹配：qualified name "ioutil.ReadFile" 匹配 sink "ReadFile"
                if not any(callee_name.endswith("." + sn) for sn in name_set):
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

        # Pre-check: branch constraint on start node
        if _vattr(sv, "label") == NodeLabel.IDENTIFIER.value and sname:
            branch_chain = self.get_branch_chain(start_vid)
            if branch_chain:
                innermost_branch = branch_chain[-1]
                if self.check_branch_constraint(innermost_branch, sname):
                    return self._cached(cache_key, AnalysisResult(
                        code=-1,
                        reason=f"branch constraint on '{sname}' in "
                               f"{_vattr(self.graph.vs[innermost_branch], 'type', '')} "
                               f"('{_vattr(self.graph.vs[innermost_branch], 'condition', '')}')",
                        chain=[{"step": "branch_constraint", "vid": innermost_branch,
                                "name": sname, "code": -1}],
                        path=[start_vid], expr_lineno=_vattr(sv, "lineno", 0)))

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

        # Pre-compute branch chain for the sink arg (start_vid).
        # Branch constraints protect the sink location, not intermediate
        # trace nodes.  A variable assigned before a match/case but used
        # inside a specific case body must be checked against that case
        # constraint, not against the assignment's location.
        sink_branch_chain = self.get_branch_chain(start_vid)
        sink_branch_set: set[int] = set(sink_branch_chain)

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

                # Rule 0: function parameter (entry point) — assume controllable
                if ulabel == "parameter":
                    # If this parameter has no DFG upstream, it's an entry point
                    if not list(self._get_dfg_sources(up_vid)):
                        logger.debug("entry parameter '%s' vid=%d", uname, up_vid)
                        return self._cached(cache_key, AnalysisResult(
                            code=4, reason=f"entry parameter '{uname}'",
                            chain=[{"step": "entry_param", "vid": up_vid, "name": uname, "code": 4}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

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

                # Rule 3b: superglobal method call (e.g., request.GET.get() in Python)
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    is_sg, sg_name = self._is_superglobal_method_call(up_vid)
                    if is_sg:
                        callee = self._resolve_callee_name(up_vid)
                        return self._cached(cache_key, AnalysisResult(
                            code=1,
                            reason=f"superglobal '{sg_name}' via method '{callee}'",
                            chain=[{"step": "sg_method", "vid": up_vid,
                                    "name": f"{sg_name}.{callee}", "code": 1}],
                            path=new_path, expr_lineno=_vattr(uv, "lineno", 0)))

                # Rule 4: function call — cg → function(taint_type) → parameter(passthrough_arg)
                if ulabel == NodeLabel.OPERATOR.value and utype in _CALL_TYPES:
                    callee = self._resolve_callee_name(up_vid)

                    # 沿 use 边找到 function 节点，读 taint_type
                    func_taint = ""
                    func_vid = None
                    for ce in self.graph.es.select(_source=up_vid, label="use"):
                        fv = self.graph.vs[ce.target]
                        if _vattr(fv, "label") == NodeLabel.FUNCTION.value:
                            func_vid = ce.target
                            func_taint = _vattr(fv, "taint_type", "")
                            break

                    # 4a: source — 函数本身产生可控数据
                    if func_taint == "source":
                        return self._cached(cache_key, AnalysisResult(
                            code=1, reason=f"taint source '{callee}'",
                            chain=[{"step": "taint_source", "vid": func_vid,
                                    "name": callee, "code": 1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))

                    # 4b: safe — 函数过滤，不可控
                    if func_taint == "safe":
                        return self._cached(cache_key, AnalysisResult(
                            code=-1, reason=f"taint safe '{callee}'",
                            chain=[{"step": "taint_safe", "vid": func_vid,
                                    "name": callee, "code": -1}],
                            path=new_path,
                            expr_lineno=_vattr(uv, "lineno", 0)))

                    # 4c: passthrough — 读 function.taint_passthrough 常驻属性
                    #     function.taint_passthrough 与 parameter.taint_type="passthrough_arg"
                    #     是同一数据的两个视图：反向分析走 function，正向分析走 parameter
                    #     形参 index → 映射到 call 的 ast[role=arg] → 追踪实参
                    if func_taint == "passthrough" and func_vid is not None:
                        # 直接读 function 节点的常驻属性
                        tp = _vattr(self.graph.vs[func_vid], "taint_passthrough", [])
                        pt_param_indices: set[int] = set(
                            int(i) for i in tp if isinstance(i, int)
                        )
                        # 映射到 call 的实参
                        if pt_param_indices:
                            arg_counter = 0
                            for ae in self.graph.es.select(_source=up_vid, label="ast"):
                                if _vattr(ae, "role") != "arg":
                                    continue
                                idx = _vattr(ae, "index")
                                actual_idx = int(idx) if idx else arg_counter
                                if actual_idx in pt_param_indices:
                                    arg_vid = ae.target
                                    arg_name = _vattr(self.graph.vs[arg_vid], "name", "")
                                    if arg_name:
                                        dep_vid = self._find_identifier_by_name(
                                            arg_name, context_vid)
                                        if dep_vid is not None:
                                            dep_res = self.parameters_back(
                                                dep_vid, context_vid,
                                                max_depth - depth)
                                            if dep_res.is_controllable:
                                                return self._cached(cache_key, dep_res)
                                arg_counter += 1

                    # 4d: graph-based function trace (unknown or no taint attribute)
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

                # Rule 6: branch constraint — identifier inside a branch
                # whose condition constrains this variable to a safe value
                # Use the sink arg's branch chain (pre-computed), not the
                # current BFS node's chain, because constraints protect the
                # sink location.
                if ulabel == NodeLabel.IDENTIFIER.value and uname:
                    # Branch constraint check.
                    # If the sink arg is inside a branch, use sink's chain.
                    # If not (empty chain), fall back to current BFS node's
                    # chain — needed for ternary where the tainted identifier
                    # is inside the ternary but the sink arg is outside.
                    if sink_branch_chain:
                        # Check if current node is inside a ternary iffalse
                        cur_branch_chain = self.get_branch_chain(up_vid)
                        in_ternary_false = False
                        if cur_branch_chain:
                            innermost_cur = cur_branch_chain[0]
                            cbtype = _vattr(self.graph.vs[innermost_cur],
                                           "type", "").lower()
                            if cbtype == "ternary" and self._is_in_ternary_iffalse(
                                    up_vid, innermost_cur):
                                in_ternary_false = True

                        if not in_ternary_false:
                            innermost_branch = sink_branch_chain[0]
                            btype = _vattr(self.graph.vs[innermost_branch],
                                           "type", "").lower()
                            # Ternary: iffalse 分支不受 condition 约束
                            if btype == "ternary" and self._is_in_ternary_iffalse(
                                    up_vid, innermost_branch):
                                pass  # 不阻断，继续 BFS
                            elif self.check_branch_constraint(innermost_branch, uname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"branch constraint on '{uname}' in "
                                           f"{_vattr(self.graph.vs[innermost_branch], 'type', '')} "
                                           f"('{_vattr(self.graph.vs[innermost_branch], 'condition', '')}')",
                                    chain=[{"step": "branch_constraint", "vid": innermost_branch,
                                            "name": uname, "code": -1}],
                                    path=new_path,
                                    expr_lineno=_vattr(uv, "lineno", 0)))
                    else:
                        # Fallback: use current BFS node's branch chain
                        branch_chain = self.get_branch_chain(up_vid)
                        if branch_chain:
                            innermost_branch = branch_chain[0]
                            btype = _vattr(self.graph.vs[innermost_branch],
                                           "type", "").lower()
                            if btype == "ternary" and self._is_in_ternary_iffalse(
                                    up_vid, innermost_branch):
                                pass  # 不阻断，继续 BFS
                            elif self.check_branch_constraint(innermost_branch, uname):
                                return self._cached(cache_key, AnalysisResult(
                                    code=-1,
                                    reason=f"branch constraint on '{uname}' in "
                                           f"{_vattr(self.graph.vs[innermost_branch], 'type', '')} "
                                           f"('{_vattr(self.graph.vs[innermost_branch], 'condition', '')}')",
                                    chain=[{"step": "branch_constraint", "vid": innermost_branch,
                                            "name": uname, "code": -1}],
                                    path=new_path,
                                    expr_lineno=_vattr(uv, "lineno", 0)))

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
            vn = _vattr(v, "name", "") or ""
            vf = _vattr(v, "fullname", "") or ""
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
            formal[int(pidx) if pidx else len(formal)] = (pvid, _vattr(pv, "name", ""))

        # Actual args: ast edges with role=arg from the call operator
        actual_args: dict[int, int] = {}
        arg_counter = 0
        for e in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(e, "role") == "arg":
                idx = _vattr(e, "index")
                actual_args[int(idx) if idx else arg_counter] = e.target
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
        if "." in name:
            # Support dotted paths like "request.GET"
            return name in _SUPERGLOBALS
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

    def _is_superglobal_method_call(self, call_vid: int) -> tuple[bool, str]:
        """Check if a call operator's callee is a method on a superglobal object.

        Walks member edges from the callee identifier to reconstruct the
        object chain (e.g., request.GET.get → check if 'request.GET' is superglobal).

        Returns (is_superglobal, superglobal_name).
        """
        # Find callee identifier via ast[role=callee]
        callee_vid = None
        for ae in self.graph.es.select(_source=call_vid, label="ast"):
            if _vattr(ae, "role") == "callee":
                callee_vid = ae.target
                break
        if callee_vid is None:
            return False, ""

        callee_name = _vattr(self.graph.vs[callee_vid], "name", "")
        callee_type = _vattr(self.graph.vs[callee_vid], "type", "")

        # If callee is a property (method call like .get()), walk member chain
        if callee_type == "property":
            # Collect member chain: callee → parent → grandparent...
            chain = [callee_name]
            current = callee_vid
            visited_members: set[int] = {callee_vid}
            while True:
                found_member = False
                for me in self.graph.es.select(_target=current, label="member"):
                    obj_vid = me.source
                    if obj_vid in visited_members:
                        continue
                    visited_members.add(obj_vid)
                    obj_name = _vattr(self.graph.vs[obj_vid], "name", "")
                    obj_type = _vattr(self.graph.vs[obj_vid], "type", "")
                    chain.append(obj_name)
                    current = obj_vid
                    found_member = True

                    # Build all possible prefix paths and check
                    # Chain: [get, GET, request] → check "request.GET.get", "request.GET", "request"
                    reversed_chain = list(reversed(chain))
                    for i in range(len(reversed_chain)):
                        prefix = ".".join(reversed_chain[:i+1])
                        if prefix in _SUPERGLOBALS:
                            return True, prefix

                    # Check if the object itself is a superglobal (non-property)
                    if obj_type != "property" and self._is_source_variable(obj_name):
                        return True, obj_name

                    # If object is not a property, stop traversing further
                    if obj_type != "property":
                        break
                if not found_member:
                    break

        return False, ""

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

    def _get_ast_parent(self, vid: int) -> int | None:
        """从 vid 沿 ast 边反向找直接父节点（ast[source=parent, target=vid]）。"""
        inc = self.graph.es.select(_target=vid, label="ast")
        return inc[0].source if inc else None

    def get_enclosing_branch(self, vid: int) -> int | None:
        """从 vid 向上搜索，返回包含该节点最近的 branch 节点 vid。

        搜索逻辑：
        1. 先沿 ast 反向走到 own 边的 target（顶层语句）
        2. 再沿 own 反向找到最近的 branch
        3. 如果中间遇到 branch/function/file，直接判定

        own 边方向是 parent own→ child，反向查找即 _target=cur 的 own 边。
        ast 边方向是 parent ast→ child，反向查找即 _target=cur 的 ast 边。
        """
        cur, seen = vid, set()
        for _ in range(30):
            if cur is None or cur in seen:
                return None
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label == NodeLabel.BRANCH.value:
                return cur
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return None
            # 先检查是否是 own target（顶层语句），沿 own 反向
            own_inc = self.graph.es.select(_target=cur, label="own")
            if own_inc:
                cur = own_inc[0].source
            else:
                # 不在 own target 上，沿 ast 反向找父节点
                cur = self._get_ast_parent(cur)
        return None

    _NEGATED_BRANCH_TYPES = frozenset({"else", "default"})

    def get_branch_chain(self, vid: int) -> list[int]:
        """从 vid 向上搜索，返回 vid 到最近的 function/file 之间
        经过的所有 branch 节点（按从内到外排序）。

        注意：else/default 分支不会继承其父 if/switch 的条件约束，
        所以遇到 else/default 时停止向上收集（不包含父 if/switch）。

        例如：vid 在 else 内部，返回 [else_branch_vid]（不含 if_branch）。
        """
        result: list[int] = []
        cur, seen = vid, set()
        stop_at_parent = False
        for _ in range(30):
            if cur is None or cur in seen:
                break
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                break
            if label == NodeLabel.BRANCH.value:
                btype = _vattr(self.graph.vs[cur], "type", "").lower()
                result.append(cur)
                # else/default 不继承父 if/switch 的条件
                if btype in self._NEGATED_BRANCH_TYPES:
                    break
            own_inc = self.graph.es.select(_target=cur, label="own")
            if own_inc:
                cur = own_inc[0].source
            else:
                cur = self._get_ast_parent(cur)
        return result

    def is_inside_branch(self, vid: int, branch_type: str | None = None) -> bool:
        """判断 vid 是否在 branch 节点内部。

        可选参数 ``branch_type`` 用于过滤特定类型的 branch，匹配逻辑为
        大小写不敏感地比较 branch 节点 ``attrs.type``（如 "if"/"switch"）
        或 ``attrs.raw_type``（如 "If"/"Switch"）。未指定则只要在任意 branch
        内即返回 True。
        """
        chain = self.get_branch_chain(vid)
        if not branch_type:
            return bool(chain)
        wanted = branch_type.lower()
        for bvid in chain:
            attrs = _vattr(self.graph.vs[bvid], "attrs", {}) or {}
            btype = attrs.get("type") if isinstance(attrs, dict) else None
            rtype = attrs.get("raw_type") if isinstance(attrs, dict) else None
            if (isinstance(btype, str) and btype.lower() == wanted) or \
               (isinstance(rtype, str) and rtype.lower() == wanted):
                return True
        return False

    # -- Branch constraint checking --------------------------------------------

    def _is_in_ternary_iffalse(self, vid: int, ternary_vid: int) -> bool:
        """检查 vid 是否在 ternary branch 的 iffalse 分支下。

        从 ternary 的 iffalse 子节点向下 BFS（沿所有边类型），
        如果能到达 vid 则认为 vid 在 iffalse 分支内。
        """
        # 找到 ternary 的 iffalse 子节点
        iffalse_vids = set()
        for e in self.graph.es.select(
            _source=ternary_vid, label="ast"
        ):
            if _vattr(e, "role", "") == "iffalse":
                iffalse_vids.add(e.target)

        if not iffalse_vids:
            return False

        # BFS 沿所有边（正向）向下
        visited = set(iffalse_vids)
        queue = list(iffalse_vids)
        while queue:
            cur = queue.pop(0)
            if cur == vid:
                return True
            for e in self.graph.es.select(_source=cur):
                if e.target not in visited:
                    visited.add(e.target)
                    queue.append(e.target)
        return False

    def _get_condition_root(self, branch_vid: int) -> int | None:
        """Get the condition expression root node vid from a branch."""
        for e in self.graph.es.select(_source=branch_vid, label="ast"):
            if _vattr(e, "role", "") == "condition":
                return e.target
        return None

    def check_branch_constraint(self, branch_vid: int, var_name: str) -> bool:
        """Check if the branch condition constrains var_name to a safe value.

        Returns True if:
        - $x == "fixed" (variable compared to constant with ==)
        - $x == "a" || $x == "b" (enum via OR of ==)
        - is_numeric($x) / ctype_digit($x) etc. (type validator)
        - switch case with fixed condition value
        - re.match anchored regex, Python str.isdigit etc.
        """
        btype = _vattr(self.graph.vs[branch_vid], "type", "")

        # Wildcard branches never constrain: else, default, case _
        if btype in self._NEGATED_BRANCH_TYPES:
            return False
        if btype == "case":
            cond_vid = self._get_condition_root(branch_vid)
            if cond_vid is not None:
                cond_name = _vattr(self.graph.vs[cond_vid], "name", "")
                cond_label = _vattr(self.graph.vs[cond_vid], "label", "")
                # MatchStar / MatchAs without pattern → wildcard
                if cond_label == NodeLabel.CONST.value and cond_name.strip("'\"") == "_":
                    return False

        cond_vid = self._get_condition_root(branch_vid)
        if cond_vid is None:
            return False
        return self._check_condition_node(cond_vid, var_name, depth=0)

    def _check_condition_node(self, cond_vid: int, var_name: str, depth: int = 0) -> bool:
        """Recursively analyze a condition sub-tree node."""
        if depth > 5:
            return False

        label = _vattr(self.graph.vs[cond_vid], "label", "")
        name = _vattr(self.graph.vs[cond_vid], "name", "")
        ntype = _vattr(self.graph.vs[cond_vid], "type", "")

        # BinaryOp: ==, ===, !=, !==, ||, &&, <, >, etc.
        if label == NodeLabel.OPERATOR.value and ntype == OperatorType.BINARY_OP.value:
            if name in _SAFE_CONSTRAINT_OPS:
                # == or === : one side must be var_name, other must be constant
                left_vid, right_vid = None, None
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    role = _vattr(e, "role", "")
                    if role == "left":
                        left_vid = e.target
                    elif role == "right":
                        right_vid = e.target
                if left_vid is None or right_vid is None:
                    return False
                # Check if either side references var_name
                left_name = _vattr(self.graph.vs[left_vid], "name", "")
                right_name = _vattr(self.graph.vs[right_vid], "name", "")
                right_label = _vattr(self.graph.vs[right_vid], "label", "")
                left_label = _vattr(self.graph.vs[left_vid], "label", "")

                if left_name == var_name and right_label in (NodeLabel.CONST.value, NodeLabel.IDENTIFIER.value):
                    return True  # var == constant
                if right_name == var_name and left_label in (NodeLabel.CONST.value, NodeLabel.IDENTIFIER.value):
                    return True  # constant == var
                return False

            elif name == "||":
                # OR: both sides must constrain → enum pattern
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if not self._check_condition_node(e.target, var_name, depth + 1):
                        return False
                return True

            elif name == "&&":
                # AND: either side constrains → safe
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if self._check_condition_node(e.target, var_name, depth + 1):
                        return True
                return False

            # !=, !==, <, >, <=, >= don't constrain to safe values
            return False

        # FunctionCall: type validator (is_numeric, ctype_digit, etc.)
        if label == NodeLabel.OPERATOR.value and ntype == OperatorType.CALL.value:
            if name in _TYPE_VALIDATION_FUNCS:
                # Check if any arg references var_name
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        arg_name = _vattr(self.graph.vs[e.target], "name", "")
                        if arg_name == var_name:
                            return True
                # Check method receiver via member chain
                # e.g. page.isdigit() → callee 'isdigit' → member → 'page'
                for ae in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(ae, "role", "") == "callee":
                        callee_vid = ae.target
                        for me in self.graph.es.select(_target=callee_vid, label="member"):
                            recv_name = _vattr(self.graph.vs[me.source], "name", "")
                            if recv_name == var_name:
                                return True

            # preg_match: anchored regex without dot wildcard → safe
            if name == "preg_match":
                args = []
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        args.append(e.target)
                # args[0] = pattern, args[1] = subject
                if len(args) >= 2:
                    subject_name = _vattr(self.graph.vs[args[1]], "name", "")
                    if subject_name == var_name:
                        # 检查正则模式是否锚定
                        pat_label = _vattr(self.graph.vs[args[0]], "label", "")
                        pat_name = _vattr(self.graph.vs[args[0]], "name", "")
                        if pat_label == NodeLabel.CONST.value and pat_name:
                            # 去掉 repr 的引号，提取 PHP 正则内容
                            raw = pat_name.strip("'\"")
                            # PHP regex: /pattern/flags → 提取 pattern
                            if len(raw) >= 2 and raw[0] == '/' and raw[-1] == '/':
                                pattern = raw[1:-1]
                            else:
                                pattern = raw
                            # ^ 和 $ 锚定 → 严格匹配整个字符串 → 安全
                            if pattern.startswith("^") and pattern.endswith("$"):
                                return True

            # re.match / re.fullmatch: anchored regex → safe
            if name in ("match", "fullmatch", "search"):
                args = []
                for e in self.graph.es.select(_source=cond_vid, label="ast"):
                    if _vattr(e, "role", "") == "arg":
                        args.append(e.target)
                # args[0] = pattern, args[1] = subject (for re.match/re.fullmatch)
                if len(args) >= 2:
                    subject_name = _vattr(self.graph.vs[args[1]], "name", "")
                    if subject_name == var_name:
                        pat_label = _vattr(self.graph.vs[args[0]], "label", "")
                        pat_name = _vattr(self.graph.vs[args[0]], "name", "")
                        if pat_label == NodeLabel.CONST.value and pat_name:
                            raw = pat_name.strip("'\"")
                            # Python regex: raw string r'...' — already the pattern
                            # ^ and $ anchoring → strict match → safe
                            if raw.startswith("^") and raw.endswith("$"):
                                return True
                            # re.fullmatch always matches the entire string
                            if name == "fullmatch":
                                return True

            return False

        # Identifier in case condition: switch case with fixed value
        # e.g. switch($x) { case "ls": ... } — condition is "ls"
        # The branch is case type, and condition is the matched value
        branch_parent = self._get_ast_parent(cond_vid)
        if branch_parent is not None:
            parent_label = _vattr(self.graph.vs[branch_parent], "label", "")
            parent_type = _vattr(self.graph.vs[branch_parent], "type", "")
            if parent_label == NodeLabel.BRANCH.value and parent_type == "case":
                # case condition is a fixed value — all variables inside
                # this case branch are constrained to that value
                # BUT we need to check if the switch variable is var_name
                # The switch branch owns the case branch, and switch's condition
                # references the variable
                switch_vid = None
                for e in self.graph.es.select(_target=branch_parent, label="own"):
                    switch_vid = e.source
                    break
                if switch_vid is not None:
                    switch_label = _vattr(self.graph.vs[switch_vid], "label", "")
                    switch_type = _vattr(self.graph.vs[switch_vid], "type", "")
                    if switch_label == NodeLabel.BRANCH.value and switch_type in ("switch", "match"):
                        switch_cond = self._get_condition_root(switch_vid)
                        if switch_cond is not None:
                            switch_var = _vattr(self.graph.vs[switch_cond], "name", "")
                            if switch_var == var_name:
                                return True

        return False

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
        1. Look for ast[role=callee] edges → collect callee names.
           For chained method calls (e.g. ``a.b.c()``), the *last*
           callee edge whose target is an ``identifier``/``property``
           is the actual method name (e.g. ``c``).  Intermediate
           operator callee targets (e.g. ``a.b`` as a static_call)
           are skipped so the real method name surfaces.
        2. Fall back to cg/use edge → target function node name.
        3. Fall back to operator node's own ``name`` attribute.
        """
        callee_names: list[tuple[str, int]] = []  # (name, target_vid)
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                t = self.graph.vs[e.target]
                name = _vattr(t, "name") or _vattr(t, "value")
                if name:
                    callee_names.append((name, t.index))
        # Prefer the last identifier callee (actual method name in chains)
        for name, tvid in reversed(callee_names):
            if _vattr(self.graph.vs[tvid], "label") == "identifier":
                resolved = self._resolve_variable_callee(tvid, name)
                if resolved:
                    return resolved
                return name
        # No identifier callee found — return the last callee name overall
        if callee_names:
            return callee_names[-1][0]
        # Fallback: use edge target
        for e in self.graph.es.select(_source=op_vid, label="use"):
            name = _vattr(self.graph.vs[e.target], "name")
            resolved = self._resolve_variable_callee(e.target, name)
            if resolved:
                return resolved
            return name
        # Last resort: operator's own name
        name = _vattr(self.graph.vs[op_vid], "name")
        if name:
            resolved = self._resolve_variable_callee(op_vid, name)
            if resolved:
                return resolved
        return name

    def _resolve_variable_callee(self, start_vid: int, var_name: str, max_depth: int = 5) -> str | None:
        """Resolve variable callee name through DFG backward tracking.

        For indirect function calls like ``$func($cmd)`` or JS ``f(userInput)``
        where ``f = eval``, traces DFG edges backward to find the assigned
        literal value.

        Supports multi-level indirection::

            $func2 = $func;  $func = 'system';  $func2($cmd)
            const f = eval; f(x)

        Args:
            start_vid: The callee identifier vertex index.
            var_name: Variable/function name.
            max_depth: Max hops to follow (default 5).

        Returns:
            Resolved literal callee name, or None.
        """
        if not var_name:
            return None

        visited: set[int] = set()
        current_vid = start_vid

        for _ in range(max_depth):
            if current_vid in visited:
                break
            visited.add(current_vid)

            # Follow DFG edges backward from this identifier
            resolved = False
            for src_vid in self._get_dfg_sources(current_vid):
                sv = self.graph.vs[src_vid]
                slabel = _vattr(sv, "label", "")
                sname = _vattr(sv, "name", "")

                if slabel == NodeLabel.CONST.value and sname:
                    # Strip quotes from string literals
                    return sname.strip("'\"")

                if slabel == NodeLabel.FUNCTION.value and sname:
                    # Direct function reference: f = eval (function node)
                    return sname

                if slabel == NodeLabel.IDENTIFIER.value and sname:
                    # Check if this identifier has further DFG upstream
                    if list(self._get_dfg_sources(src_vid)):
                        # Multi-level: follow the chain
                        current_vid = src_vid
                        resolved = True
                        break
                    else:
                        # Leaf identifier (no DFG upstream) —
                        # treat as function name reference (e.g. const f = eval)
                        return sname

            if not resolved:
                break

        return None

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
