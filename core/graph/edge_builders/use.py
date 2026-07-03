"""UseEdgeBuilder — derives call operator → function use edges from AST.

Runs after DFG builder (needs dfg edges for receiver type resolution).
Before CG builder (cg builder depends on use edges).

This builder replaces the per-normalizer use edge generation that
previously ran during AST mapping (phase 1).  Moving to phase 2
enables:

- Receiver type resolution using java_type / dtype attributes set
  during normalization (field/variable declarations).
- DFG backward tracing for receiver types (assigned from method
  calls or other variables).
- Correct ``fullname`` on external function nodes (e.g.
  ``Unmarshaller.unmarshal`` instead of ``this.um.unmarshal``).
- Future extensibility (return type inference, cross-file resolution).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.base import BaseEdgeBuilder
from core.graph.node_edge_schema import (
    EdgeLabel,
    FunctionType,
    NodeLabel,
    OperatorType,
    CgCallType,
)
from utils.igraph_compat import _vattr

logger = logging.getLogger(__name__)

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
    OperatorType.NEW.value,
}


class UseEdgeBuilder(BaseEdgeBuilder):
    """Derive call→function use edges with receiver type resolution.

    For each call/static_call/method_call operator node:
      1. Extract callee method name from ast[callee] edges.
      2. Determine receiver type (java_type/dtype) for method calls:
         a. Check identifier nodes along callee/member chain.
         b. Trace DFG backward (up to 5 hops) for assignment sources.
      3. Build qualified fullname = ``Type.method`` when type found.
      4. Find or create target function node and add use edge.
    """

    def build(self, graph: "ig.Graph", language: str = "", **kwargs) -> int:
        if graph.vcount() == 0:
            return 0

        # Collect callee_targets set: operator vids that are targets
        # of ast[callee] edges from other operators (chained calls).
        # These are intermediate callee expressions, not real call sites.
        callee_targets: set[int] = set()
        for e in graph.es.select(label="ast"):
            if _vattr(e, "role") == "callee":
                callee_targets.add(e.target)

        # Identify callee_targets that have their own args — these are
        # intermediate call sites in method chains (e.g. Request.Get in
        # Request.Get(url).execute().asString()).  They must NOT be skipped
        # because they are real sink candidates with user-controlled args.
        callee_with_args: set[int] = set()
        for ct_vid in callee_targets:
            has_arg = any(
                _vattr(e, "role") == "arg"
                for e in graph.es.select(_source=ct_vid, label="ast")
            )
            if has_arg:
                callee_with_args.add(ct_vid)

        # Build name → [vid] index for identifier/parameter lookup
        # (parameters carry java_type for receiver type resolution)
        name_index: dict[str, list[int]] = {}
        for v in graph.vs:
            vl = _vattr(v, "label", "")
            if vl in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value):
                name = _vattr(v, "name", "")
                if name:
                    name_index.setdefault(name, []).append(v.index)

        count = 0
        for v in graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in _CALL_TYPES:
                continue
            # Skip intermediate callee expressions (nested in method chains)
            # but NOT those that have their own args — they are real call sites
            if v.index in callee_targets and v.index not in callee_with_args:
                continue

            vid = v.index
            lineno = _vattr(v, "lineno", 0)
            op_name = _vattr(v, "name", "")
            op_type = _vattr(v, "type", "")

            # Determine call_type
            if op_type == OperatorType.STATIC_CALL.value:
                cg_call_type = CgCallType.STATIC.value
            elif op_type == OperatorType.METHOD_CALL.value:
                cg_call_type = CgCallType.METHOD.value
            else:
                cg_call_type = CgCallType.DIRECT.value

            # Extract callee method name and call_type override from qualifier
            callee_name = self._extract_callee_name(graph, vid, op_name)
            if not callee_name:
                continue

            # Resolve receiver type for method/static calls
            resolved_type = None
            if op_type in (OperatorType.METHOD_CALL.value,
                           OperatorType.STATIC_CALL.value):
                resolved_type = self._resolve_receiver_type(
                    graph, vid, callee_name, name_index
                )

            # Build fullname
            if resolved_type:
                fullname = f"{resolved_type}.{callee_name}"
            elif op_type == OperatorType.NEW.value:
                # Constructor call: fullname is the class name itself
                fullname = callee_name
            elif op_name:
                fullname = op_name
            else:
                fullname = callee_name

            # Determine function node name (short)
            func_name = callee_name

            # Find existing function node or create external one
            caller_file = _vattr(graph.vs[vid], "file_path", "")
            target_vid = self._find_or_create_function(
                graph, func_name, fullname, lineno,
                caller_file=caller_file
            )

            if target_vid is not None:
                # Avoid duplicate use edges
                exists = False
                for ue in graph.es.select(_source=vid, _target=target_vid,
                                          label="use"):
                    exists = True
                    break
                if not exists:
                    graph.add_edge(vid, target_vid, label="use",
                                   call_type=cg_call_type,
                                   lineno=lineno)
                    count += 1

        return count

    # -- helpers -----------------------------------------------------------

    def _extract_callee_name(self, graph: "ig.Graph", op_vid: int,
                             op_name: str) -> str:
        """Extract callee method name from ast[callee] edges.

        For chained calls like ``a.b.c()``, returns the last identifier
        callee (``c``), skipping intermediate operator callee targets.
        """
        callee_names: list[tuple[str, int]] = []
        for e in graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                t = graph.vs[e.target]
                name = _vattr(t, "name") or _vattr(t, "value")
                if name:
                    callee_names.append((name, t.index))

        # Prefer the last identifier callee (actual method name in chains)
        for name, tvid in reversed(callee_names):
            if _vattr(graph.vs[tvid], "label") == NodeLabel.IDENTIFIER.value:
                return name
        # Fall back to last callee name overall
        if callee_names:
            return callee_names[-1][0]
        # Fall back to operator's own name (last segment after dot)
        if op_name:
            parts = op_name.replace("::", ".").rsplit(".", 1)
            if len(parts) == 2 and parts[1]:
                return parts[1]
        return ""

    def _resolve_receiver_type(self, graph: "ig.Graph", op_vid: int,
                               callee_name: str,
                               name_index: dict[str, list[int]]) -> str | None:
        """Resolve the declared type of the method call's receiver.

        Returns type name (e.g. ``"Unmarshaller"``) or None.
        """
        # Step 1: Extract receiver identifier name(s) from callee chain
        receiver_names = self._get_receiver_ident_names(graph, op_vid)
        if not receiver_names:
            # Fallback: parse op_name for receiver identifier
            op_name = _vattr(graph.vs[op_vid], "name", "")
            if op_name and "." in op_name:
                parts = op_name.replace("::", ".").rsplit(".", 1)
                prefix = parts[0].rsplit(".", 1)[-1]
                if prefix and prefix not in ("this", "self", "super", "cls"):
                    receiver_names = [prefix]
        if not receiver_names:
            return None

        call_file = _vattr(graph.vs[op_vid], "file_path", "")

        # Determine operator's enclosing function lineno range (for scoped lookup)
        op_scope = self._enclosing_function_lineno(graph, op_vid)

        # Step 2: For each receiver name, search for java_type/dtype
        for qualifier_name in receiver_names:
            candidates = name_index.get(qualifier_name, [])
            # Sort: same-scope first, then same-file, then others
            same_scope: list[int] = []
            same_file: list[int] = []
            other_file: list[int] = []
            for vid in candidates:
                cand_scope = self._enclosing_function_lineno(graph, vid)
                if op_scope and cand_scope and op_scope[0] == cand_scope[0]:
                    same_scope.append(vid)
                else:
                    vfile = _vattr(graph.vs[vid], "file_path", "")
                    if vfile == call_file:
                        same_file.append(vid)
                    else:
                        other_file.append(vid)
            sorted_candidates = same_scope + same_file + other_file

            for vid in sorted_candidates:
                dtype = _vattr(graph.vs[vid], "java_type", "") or \
                        _vattr(graph.vs[vid], "dtype", "")
                if dtype and dtype != "var":
                    return dtype

                # Trace DFG backward to find definition site
                visited: set[int] = set()
                current = vid
                for _ in range(5):
                    if current in visited:
                        break
                    visited.add(current)
                    for src_vid in self._get_dfg_sources(graph, current):
                        sv = graph.vs[src_vid]
                        dtype = _vattr(sv, "java_type", "") or \
                                _vattr(sv, "dtype", "")
                        if dtype:
                            return dtype
                        if _vattr(sv, "label") == NodeLabel.IDENTIFIER.value:
                            current = src_vid
                            break
                    else:
                        break

        # Step 3 (fallback): Chain call return type inference.
        # For ``DocumentBuilderFactory.newDocumentBuilder().parse()``,
        # the receiver is itself a call whose return type we need.
        return self._resolve_chain_receiver_type(graph, op_vid)

    def _resolve_chain_receiver_type(self, graph: "ig.Graph",
                                     op_vid: int) -> str | None:
        """Resolve receiver type from a chained call's return type.

        For ``DocumentBuilderFactory.newDocumentBuilder().parse()``,
        the receiver of ``parse()`` is the return value of
        ``newDocumentBuilder()``.  This method:

        1. Finds the inner call operator from the callee chain.
        2. Looks up the inner call's function node for ``return_type``.
        3. Applies ``newXxx()`` → ``Xxx`` heuristic for Java factory
           methods when no return_type is available.
        """
        for e in graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") != "callee":
                continue
            target = e.target
            target_label = _vattr(graph.vs[target], "label", "")
            if target_label != NodeLabel.OPERATOR.value:
                continue
            inner_type = _vattr(graph.vs[target], "type", "")
            if inner_type not in _CALL_TYPES:
                continue

            inner_op_name = _vattr(graph.vs[target], "name", "")
            inner_callee = self._extract_callee_name(
                graph, target, inner_op_name
            )
            if not inner_callee:
                continue

            # Try to build inner fullname and find existing function node
            if inner_type == OperatorType.STATIC_CALL.value and \
                    "." in inner_op_name:
                qualifier = inner_op_name.split(".")[0]
                inner_fullname = f"{qualifier}.{inner_callee}"
            else:
                inner_fullname = inner_callee

            # Check graph for function node with return_type
            for v in graph.vs.select(label="function"):
                if _vattr(v, "fullname") == inner_fullname:
                    rt = _vattr(v, "return_type", "")
                    if rt and rt != "void":
                        return rt

            # Heuristic: Java factory pattern ``newXxx()`` → ``Xxx``
            if inner_callee.startswith("new") and len(inner_callee) > 3:
                hint = inner_callee[3:]
                # Verify it looks like a type name (starts with uppercase)
                if hint[0:1].isupper():
                    return hint

            return None

        return None

    def _get_receiver_ident_names(self, graph: "ig.Graph",
                                   call_vid: int) -> list[str]:
        """Extract receiver identifier names from callee chain.

        For ``this.unmarshaller.unmarshal()``, follows callee member
        edges to find ``unmarshaller`` (skipping ``this``/``self``
        and the method name itself).
        """
        callee_vids: list[int] = []
        for e in graph.es.select(_source=call_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                callee_vids.append(e.target)

        names: list[str] = []

        for cv in callee_vids:
            cv_label = _vattr(graph.vs[cv], "label", "")
            cv_name = _vattr(graph.vs[cv], "name", "")

            # The callee identifier (e.g. "unmarshal") is the method name,
            # not the receiver. Follow member edges BACK from the callee
            # identifier to find the receiver.
            if cv_label == NodeLabel.IDENTIFIER.value:
                # Check if callee identifier has incoming member edges
                # (meaning it's a member of some expression)
                for me in graph.es.select(_target=cv, label="member"):
                    source = me.source
                    src_label = _vattr(graph.vs[source], "label", "")
                    if src_label == NodeLabel.IDENTIFIER.value:
                        src_name = _vattr(graph.vs[source], "name", "")
                        if src_name and src_name not in ("this", "self"):
                            names.append(src_name)
                    elif src_label == NodeLabel.OPERATOR.value:
                        # Recursively trace operator's callee chain
                        names.extend(self._get_receiver_ident_names(graph, source))
                # No member edges → this is a bare function call, no receiver
                continue

            if cv_label == NodeLabel.OPERATOR.value:
                # The callee target is an operator (chained call like a.b.c())
                # Its name might contain the receiver info
                current = cv
                visited: set[int] = set()
                while current not in visited:
                    visited.add(current)
                    found = False
                    for me in graph.es.select(_target=current, label="member"):
                        source = me.source
                        src_label = _vattr(graph.vs[source], "label", "")
                        if src_label == NodeLabel.IDENTIFIER.value:
                            src_name = _vattr(graph.vs[source], "name", "")
                            src_type = _vattr(graph.vs[source], "type", "")
                            if src_name and src_name not in ("this", "self"):
                                if src_type != "this":
                                    names.append(src_name)
                            found = True
                            break
                        elif src_label == NodeLabel.OPERATOR.value:
                            current = source
                            found = True
                            break
                    if not found:
                        break

        return names

    @staticmethod
    def _get_dfg_sources(graph: "ig.Graph", vid: int) -> list[int]:
        """Get upstream DFG source vertex IDs."""
        sources = []
        for e in graph.es.select(_target=vid, label="dfg"):
            sources.append(e.source)
        return sources

    def _find_or_create_function(self, graph: "ig.Graph",
                                func_name: str, fullname: str,
                                lineno: int = 0,
                                caller_file: str = "") -> int | None:
        """Find an existing function node or create an external one.

        Prefers:
          1. Exact fullname match (non-external declaration).
          2. Same name function node (may be from another call's use edge).
          3. Create new external function node.
        """
        # Try exact fullname match (declaration nodes)
        for v in graph.vs.select(label="function"):
            existing_fn = _vattr(v, "fullname", "")
            if existing_fn == fullname:
                return v.index

        # Try same-file name match (for same-class method calls where
        # fullname may not match exactly, e.g. ".injectableQuery" vs
        # "SqlInjectionLesson5a.injectableQuery")
        if caller_file:
            for v in graph.vs.select(label="function"):
                if _vattr(v, "name") == func_name and not _vattr(v, "is_external", False):
                    vfile = _vattr(v, "file_path", "")
                    if vfile == caller_file:
                        return v.index

        # Try name match (reuse existing external function node)
        for v in graph.vs.select(label="function"):
            if _vattr(v, "name") == func_name:
                # Only reuse external nodes by name when the receiver type
                # matches — prevents cross-type dedup (e.g. SAXParser.parse
                # vs DocumentBuilder.parse).
                if _vattr(v, "is_external", False):
                    existing_fn = _vattr(v, "fullname", "")
                    existing_type = existing_fn.rsplit(".", 1)[0] if "." in existing_fn else ""
                    new_type = fullname.rsplit(".", 1)[0] if "." in fullname else ""
                    if not existing_type or not new_type or existing_type == new_type:
                        return v.index

        # Create new external function node
        new_vid = graph.add_vertex(
            label=NodeLabel.FUNCTION.value,
            name=func_name,
            lineno=0,
            language="",
            fullname=fullname,
            type=FunctionType.FUNCTION.value,
            is_external=True,
        )
        return new_vid

    @staticmethod
    def _enclosing_function(graph: "ig.Graph", vid: int) -> int | None:
        """Find the ancestor function node of *vid* via ``own`` edges."""
        visited: set[int] = set()
        current = vid
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            for e in graph.es.select(_target=current, label="own"):
                parent = graph.vs[e.source]
                if _vattr(parent, "label") == NodeLabel.FUNCTION.value:
                    return e.source
                current = e.source
                break
            else:
                break
        return None

    @staticmethod
    def _enclosing_function_lineno(graph: "ig.Graph", vid: int) -> tuple[int, int] | None:
        """Find the enclosing function's lineno range for *vid*.

        Walks ``own`` edges from *vid* upward.  Returns ``(start, end)`` or
        ``None``.  ``end`` is set to ``start + 200`` as a rough upper bound
        (AST doesn't record end_lineno).
        """
        fn_vid = UseEdgeBuilder._enclosing_function(graph, vid)
        if fn_vid is None:
            # Try walking both own and ast edges (identifiers may only have
            # ast edges to intermediate operator nodes).
            visited: set[int] = set()
            current = vid
            for _ in range(15):
                if current in visited:
                    break
                visited.add(current)
                found = False
                for e in graph.es.select(_target=current):
                    parent = graph.vs[e.source]
                    if _vattr(parent, "label") == NodeLabel.FUNCTION.value:
                        fn_vid = e.source
                        found = True
                        break
                if found:
                    break
                # Move up one level via own/ast
                for e in graph.es.select(_target=current):
                    if _vattr(e, "label") in ("own", "ast"):
                        current = e.source
                        break
                else:
                    break
        if fn_vid is None:
            return None
        start = int(_vattr(graph.vs[fn_vid], "lineno", 0) or 0)
        return (start, start + 200)
