"""Alias edge builder - resolves indirect function call chains.

After DFG and CG builders have run, this builder identifies call operators
whose use->function target is an external placeholder (no own children)
and traces the DFG chain backward from the callee identifier to discover
the real target function.

Creates alias edges: identifier -> function (placeholder or existing).

Triggers:
- CG builder created use -> function(is_external=True, no own children)
- The callee identifier has incoming DFG edges (meaning it was assigned)
- DFG backward tracking can resolve to a real function name

Resolution strategies (in order):
1. DFG chain ends at identifier with member edge -> compose qualified name
   (e.g. os -> system via member -> os.system)
2. DFG chain ends at identifier leaf -> return name as function reference
   (e.g. func = eval -> name is eval)
3. DFG chain passes through known resolver operators (getattr, globals().get)
   -> extract string argument as target name
4. DFG chain ends at const(string) -> use string value as function name
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.graph.node_edge_schema import (
    AliasType,
    EdgeLabel,
    NodeLabel,
    OperatorType,
)
from utils.igraph_compat import _vattr

if TYPE_CHECKING:
    import igraph

logger = logging.getLogger(__name__)


class AliasBuilder:
    """Build alias edges for indirect function calls.

    Runs after DFG and CG builders.  Scans all call operators whose
    use->function target is an external placeholder and attempts
    DFG backward resolution.
    """

    def __init__(self) -> None:
        self.graph = None
        self.language = ""
        self._alias_count = 0

    # -- public entry ---------------------------------------------------------

    def build(self, graph: "ig.Graph", language: str, **kwargs) -> int:
        """Main entry: scan all call operators and create alias edges."""
        self.graph = graph
        self.language = language
        self._alias_count = 0
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        for v in self.graph.vs:
            if v["label"] != NodeLabel.OPERATOR.value:
                continue
            if v["type"] not in call_types:
                continue

            op_vid = v.index
            use_func = self._find_use_function(op_vid)
            if use_func is None:
                continue

            func_vid, func_name = use_func

            # Skip if function has own children (real definition)
            if list(self.graph.es.select(_source=func_vid, label="own")):
                continue

            # Check for method_call indirect invocation patterns:
            # Ruby: op.call(arg), PHP: $func(), etc.
            # When the method name is a generic call mechanism ('call', '__call__'),
            # the real function reference is in the operand (receiver).
            op_type = _vattr(v, "type", "")
            callee_id = self._find_callee_identifier(op_vid, func_name)
            if callee_id is None and op_type == OperatorType.METHOD_CALL.value:
                callee_id = self._find_operand_identifier(op_vid)

            if callee_id is None:
                continue

            # Resolve through DFG backward tracking
            resolved_name, alias_type, target_func_vid = self._resolve_alias(
                callee_id, func_name
            )

            if resolved_name is None:
                continue

            # Create alias edge: use->function target -> resolved_function
            # This ensures _resolve_callee_name's use-fallback path can find it.
            self._create_alias_edge(
                func_vid, resolved_name, alias_type, target_func_vid
            )

        if self._alias_count:
            logger.info(
                "[ALIAS] Created %d alias edges for %s",
                self._alias_count,
                self.language,
            )
        return self._alias_count

    # -- internal helpers -----------------------------------------------------

    def _find_use_function(self, op_vid: int) -> tuple[int, str] | None:
        """Find the use->function edge target from a call operator."""
        for e in self.graph.es.select(_source=op_vid, label="use"):
            target = self.graph.vs[e.target]
            if target["label"] == NodeLabel.FUNCTION.value:
                return e.target, target["name"]
        return None

    def _find_callee_identifier(self, op_vid: int, func_name: str) -> int | None:
        """Find the callee identifier vertex for a call operator."""
        # Look for ast[role=callee] child that is an identifier
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "callee":
                t = self.graph.vs[e.target]
                if t["label"] == NodeLabel.IDENTIFIER.value:
                    return e.target
        # Fallback: find identifier or parameter by name.
        # Prefer same-scope (same own-parent function) to avoid shadowing bugs.
        enclosing_func = self._find_own_parent_function(op_vid)
        same_scope = []
        cross_scope = []
        for vid in range(self.graph.vcount()):
            v = self.graph.vs[vid]
            if (
                v["label"] in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value)
                and _vattr(v, "name") == func_name
            ):
                if enclosing_func and self._find_own_parent_function(vid) == enclosing_func:
                    same_scope.append(vid)
                else:
                    cross_scope.append(vid)
        if same_scope:
            return same_scope[0]
        if cross_scope:
            return cross_scope[0]
        return None

    def _find_own_parent_function(self, vid: int) -> int | None:
        """Find the nearest function/file ancestor via incoming own/ast edges."""
        visited: set[int] = set()
        queue = [vid]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            # Walk up own chain, then AST chain from intermediate nodes
            for e in self.graph.es.select(_target=current, label="own"):
                parent_label = self.graph.vs[e.source]["label"]
                if parent_label in ("function", "file"):
                    return e.source
                queue.append(e.source)
            for e in self.graph.es.select(_target=current, label="ast"):
                parent_label = self.graph.vs[e.source]["label"]
                if parent_label in ("function", "file"):
                    return e.source
                queue.append(e.source)
        return None

    def _find_operand_identifier(self, op_vid: int) -> int | None:
        """Find the operand (receiver) identifier for a method_call operator.

        Used for indirect call patterns like Ruby's ``obj.call(arg)`` where
        the method name ``call`` is a generic dispatch mechanism and the real
        function reference is the receiver object.
        """
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "operand":
                t = self.graph.vs[e.target]
                if t["label"] in (
                    NodeLabel.IDENTIFIER.value,
                    NodeLabel.PARAMETER.value,
                ):
                    return e.target
        return None

    def _resolve_alias(
        self, callee_id: int, callee_name: str, max_depth: int = 8
    ) -> tuple[str | None, str | None, int | None]:
        """Trace DFG backward from callee identifier to resolve real function.

        Uses iterative DFS with backtracking to explore all DFG source paths
        when a node has multiple incoming DFG edges.

        Returns:
            (resolved_name, alias_type, target_func_vid or None)
        """
        visited: set[int] = set()

        def _try(current: int, depth: int) -> tuple[str | None, str | None, int | None]:
            if depth > max_depth or current in visited:
                return None, None, None
            visited.add(current)

            cur_v = self.graph.vs[current]
            cur_label = cur_v["label"]
            cur_name = _vattr(cur_v, "name", "")

            # Terminal: identifier
            if cur_label == NodeLabel.IDENTIFIER.value and cur_name:
                # Check if any member edge points TO this identifier
                member_from = list(
                    self.graph.es.select(_target=current, label="member")
                )
                if member_from:
                    parent_vid = member_from[0].source
                    parent_name = _vattr(self.graph.vs[parent_vid], "name", "")
                    composed = f"{parent_name}.{cur_name}"
                    func_vid = self._find_or_create_function(composed)
                    return composed, AliasType.VIA_MEMBER.value, func_vid

                # Leaf identifier: no DFG upstream
                dfg_sources = list(
                    self.graph.es.select(_target=current, label="dfg")
                )
                if not dfg_sources:
                    # Cross-scope fallback
                    cross_scope_id = self._find_same_name_with_dfg(
                        current, cur_name
                    )
                    if cross_scope_id is not None:
                        result = _try(cross_scope_id, depth + 1)
                        if result[0] is not None:
                            return result

                    # No cross-scope match; treat as direct reference
                    func_vid = self._find_or_create_function(cur_name)
                    atype = (
                        AliasType.VIA_DFG_CHAIN.value
                        if current != callee_id
                        else AliasType.DIRECT.value
                    )
                    return cur_name, atype, func_vid

                # Has DFG upstream — try each path
                for dfg_e in dfg_sources:
                    result = _try(dfg_e.source, depth + 1)
                    if result[0] is not None:
                        return result
                return None, None, None

            # Terminal: const(string)
            if cur_label == NodeLabel.CONST.value and cur_name:
                clean = cur_name.strip("'\"")
                func_vid = self._find_or_create_function(clean)
                return clean, AliasType.DIRECT.value, func_vid

            # Terminal: function node
            if cur_label == NodeLabel.FUNCTION.value and cur_name:
                return cur_name, AliasType.DIRECT.value, current

            # Transit: operator node — check for resolver patterns
            if cur_label == NodeLabel.OPERATOR.value and cur_name:
                string_arg = self._extract_string_arg(current)
                if string_arg:
                    alias_type = (
                        AliasType.VIA_GETATTR.value
                        if "getattr" in cur_name
                        else AliasType.VIA_GLOBALS.value
                    )
                    func_vid = self._find_or_create_function(string_arg)
                    return string_arg, alias_type, func_vid

            # Transit: any other node — follow DFG sources
            dfg_sources = list(
                self.graph.es.select(_target=current, label="dfg")
            )
            for dfg_e in dfg_sources:
                result = _try(dfg_e.source, depth + 1)
                if result[0] is not None:
                    return result

            return None, None, None

        return _try(callee_id, 0)

    def _extract_string_arg(self, op_vid: int) -> str | None:
        """Extract a string argument from an operator's ast[arg] children.

        Used for getattr(obj, 'method_name') and globals().get('func_name').
        """
        for e in self.graph.es.select(_source=op_vid, label="ast"):
            if _vattr(e, "role") == "arg":
                arg_v = self.graph.vs[e.target]
                if arg_v["label"] == NodeLabel.CONST.value:
                    name = _vattr(arg_v, "name", "")
                    if name:
                        return name.strip("'\"")
        return None

    def _find_or_create_function(self, name: str) -> int | None:
        """Find an existing function node with the given name, or create one."""
        # Search existing function nodes
        for v in self.graph.vs:
            if v["label"] == NodeLabel.FUNCTION.value:
                fname = _vattr(v, "name", "")
                fullname = _vattr(v, "fullname", "")
                if fname == name or name in fullname or fullname.endswith("." + name):
                    return v.index

        # Create a placeholder function node
        vid = self.graph.vcount()
        self.graph.add_vertex(vid)
        self.graph.vs[vid]["label"] = NodeLabel.FUNCTION.value
        self.graph.vs[vid]["name"] = name
        self.graph.vs[vid]["type"] = "function"
        self.graph.vs[vid]["is_external"] = True
        self.graph.vs[vid]["lineno"] = 0
        return vid

    def _find_same_name_with_dfg(
        self, current: int, name: str
    ) -> int | None:
        """Find a same-name identifier/parameter in another scope that has DFG edges.

        Used as a cross-scope fallback in _resolve_alias when the callee
        identifier has no DFG upstream within its own scope, but a same-name
        variable definition exists in an outer scope.
        """
        # Prefer identifier with DFG incoming edge (definition with data source)
        best = None
        best_has_dfg = False
        for v in self.graph.vs:
            if v.index == current:
                continue
            if _vattr(v, "name") != name:
                continue
            if v["label"] not in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                continue
            has_dfg = any(
                self.graph.es.select(_target=v.index, label="dfg")
            )
            if has_dfg:
                # First match with DFG wins (usually the definition site)
                return v.index
            if best is None:
                best = v.index
        return best

    def _create_alias_edge(
        self,
        source_vid: int,
        resolved_name: str,
        alias_type: str,
        target_func_vid: int | None,
    ) -> None:
        """Create an alias edge from callee identifier to resolved function."""
        attrs = {
            "alias_type": alias_type,
            "resolved_name": resolved_name,
        }
        if target_func_vid is not None:
            self.graph.add_edge(
                source_vid, target_func_vid, label="alias", **attrs
            )
        else:
            # Self-loop as marker - consumers check resolved_name attribute
            self.graph.add_edge(
                source_vid, source_vid, label="alias", **attrs
            )
        self._alias_count += 1
        logger.debug(
            "[ALIAS] v%d -> '%s' (type=%s, target=%s)",
            source_vid,
            resolved_name,
            alias_type,
            target_func_vid,
        )
