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

        # Build name → [vid] index for identifier lookup (receiver type)
        name_index: dict[str, list[int]] = {}
        for v in graph.vs:
            if _vattr(v, "label") == NodeLabel.IDENTIFIER.value:
                name = _vattr(v, "name", "")
                if name:
                    name_index.setdefault(name, []).append(v.index)

        count = 0
        for v in graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in _CALL_TYPES:
                continue
            # Skip intermediate callee expressions
            if v.index in callee_targets:
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
            elif op_name:
                fullname = op_name
            else:
                fullname = callee_name

            # Determine function node name (short)
            func_name = callee_name

            # Find existing function node or create external one
            target_vid = self._find_or_create_function(
                graph, func_name, fullname, lineno
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

        # Step 2: For each receiver name, search for java_type/dtype
        for qualifier_name in receiver_names:
            candidates = name_index.get(qualifier_name, [])
            # Sort: same-file first
            sorted_candidates: list[int] = []
            for vid in candidates:
                vfile = _vattr(graph.vs[vid], "file_path", "")
                if vfile == call_file:
                    sorted_candidates.insert(0, vid)
                else:
                    sorted_candidates.append(vid)

            for vid in sorted_candidates:
                dtype = _vattr(graph.vs[vid], "java_type", "") or \
                        _vattr(graph.vs[vid], "dtype", "")
                if dtype:
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
                                lineno: int = 0) -> int | None:
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

        # Try name match (reuse existing external function node)
        for v in graph.vs.select(label="function"):
            if _vattr(v, "name") == func_name:
                # Prefer non-external
                if not _vattr(v, "is_external", False):
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
