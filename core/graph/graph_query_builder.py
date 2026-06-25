"""AST Graph Query Builder — high-level analysis queries on the AST graph.

Wraps GraphAnalyzer to provide convenient query methods for:
- Project overview (file/class/function/operator statistics)
- Single file inspection (structure, functions, imports)
- Function detail (definition, params, callers, callees)
- Taint trace from a specific line (line number → sink → controllability)
- Generic node search by label/name/type

All methods are read-only — they never modify the graph.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import igraph as ig

from core.graph.graph_analyzer import GraphAnalyzer, AnalysisResult
from core.graph.node_edge_schema import NodeLabel, EdgeLabel
from utils.igraph_compat import _vattr

__all__ = ["GraphQueryBuilder"]
logger = logging.getLogger(__name__)


def _extract_source_name(analysis: AnalysisResult) -> Optional[str]:
    """Walk the analysis chain and pull out the controllable source name.

    When ``parameters_back`` reaches a superglobal/taint source, the chain
    contains a step with ``code == 1`` and the source's ``name``.  Returns
    that name, or ``None`` if no source step was found.
    """
    for step in analysis.chain:
        if step.get("code") == 1:
            return step.get("name")
    return None


class GraphQueryBuilder:
    """High-level query interface for an AST graph.

    Usage::

        builder = GraphQueryBuilder(graph, language="php")
        print(builder.overview())
        print(builder.get_file("src/app.php"))
        print(builder.trace("src/app.php", 42))
    """

    def __init__(self, graph: ig.Graph, language: str = "php") -> None:
        self.graph = graph
        self.language = language
        self._analyzer = GraphAnalyzer(graph, language)

    # --- overview() ---
    def overview(self) -> dict[str, Any]:
        """Return project-level statistics.

        Returns dict with:
            - node_count: total vertex count
            - edge_count: total edge count
            - files: list of {path, language, node_count}
            - label_summary: {label_name: count} for all node labels
            - function_count: number of function nodes
            - class_count: number of class nodes
            - sink_count: number of sink operators found
        """
        label_counts: dict[str, int] = {}
        files: list[dict] = []

        for v in self.graph.vs:
            label = _vattr(v, "label", "")
            label_counts[label] = label_counts.get(label, 0) + 1

        # Collect file nodes
        for v in self.graph.vs:
            if _vattr(v, "label") == NodeLabel.FILE.value:
                path = _vattr(v, "name", "")
                lang = _vattr(v, "language", "")
                # Count child nodes
                children = sum(1 for e in self.graph.es.select(_source=v.index, label="own"))
                files.append({"path": path, "language": lang, "node_count": children})

        # Count sinks
        sinks = self._analyzer.find_sinks()

        return {
            "node_count": self.graph.vcount(),
            "edge_count": self.graph.ecount(),
            "files": sorted(files, key=lambda f: f["path"]),
            "label_summary": dict(sorted(label_counts.items(), key=lambda x: -x[1])),
            "function_count": label_counts.get(NodeLabel.FUNCTION.value, 0),
            "class_count": label_counts.get(NodeLabel.CLASS.value, 0),
            "sink_count": len(sinks),
        }

    # --- get_file() ---
    def get_file(self, file_path: str) -> dict[str, Any]:
        """Return detailed info for a single file.

        Returns dict with:
            - path: file path
            - language: language
            - classes: [{name, lineno}]
            - functions: [{name, fullname, lineno, params, return_type}]
            - imports: [{name, module, alias, lineno}]
            - operators: [{name, type, lineno}] (limited to first 20)
            - branch_count: number of branch nodes
        """
        # Find file node
        file_vid = None
        for v in self.graph.vs:
            if _vattr(v, "label") == NodeLabel.FILE.value and _vattr(v, "name") == file_path:
                file_vid = v.index
                break

        if file_vid is None:
            return {"error": f"File not found: {file_path}"}

        file_v = self.graph.vs[file_vid]
        classes = []
        functions = []
        imports = []
        operators = []
        branch_count = 0

        # Traverse own edges to find children
        for e in self.graph.es.select(_source=file_vid, label="own"):
            child_vid = e.target
            cv = self.graph.vs[child_vid]
            child_label = _vattr(cv, "label")

            if child_label == NodeLabel.CLASS.value:
                classes.append({
                    "vid": child_vid,
                    "name": _vattr(cv, "name", ""),
                    "lineno": _vattr(cv, "lineno", 0),
                })
            elif child_label == NodeLabel.FUNCTION.value:
                # Get params via own children
                params = []
                for pe in self.graph.es.select(_source=child_vid, label="own"):
                    pv = self.graph.vs[pe.target]
                    if _vattr(pv, "label") == NodeLabel.PARAMETER.value:
                        params.append(_vattr(pv, "name", ""))

                functions.append({
                    "vid": child_vid,
                    "name": _vattr(cv, "name", ""),
                    "fullname": _vattr(cv, "fullname", ""),
                    "lineno": _vattr(cv, "lineno", 0),
                    "params": params,
                    "return_type": _vattr(cv, "return_type", ""),
                })
            elif child_label == NodeLabel.IMPORT.value:
                imports.append({
                    "name": _vattr(cv, "name", ""),
                    "module": _vattr(cv, "module", ""),
                    "alias": _vattr(cv, "alias", ""),
                    "lineno": _vattr(cv, "lineno", 0),
                })

        # Collect operator/branch counts by BFS from file node via own edges
        # (file_path may be None on many nodes, so we use structural traversal)
        op_count = 0
        branch_count = 0
        queue = [file_vid]
        visited = {file_vid}
        while queue:
            next_queue = []
            for cur in queue:
                for e in self.graph.es.select(_source=cur, label="own"):
                    cid = e.target
                    if cid in visited:
                        continue
                    visited.add(cid)
                    cv = self.graph.vs[cid]
                    cl = _vattr(cv, "label")
                    if cl == NodeLabel.OPERATOR.value:
                        op_count += 1
                        if len(operators) < 20:
                            operators.append({
                                "name": _vattr(cv, "name", ""),
                                "type": _vattr(cv, "type", ""),
                                "lineno": _vattr(cv, "lineno", 0),
                            })
                    elif cl == NodeLabel.BRANCH.value:
                        branch_count += 1
                    next_queue.append(cid)
            queue = next_queue

        return {
            "path": file_path,
            "language": _vattr(file_v, "language", ""),
            "classes": sorted(classes, key=lambda c: c["lineno"]),
            "functions": sorted(functions, key=lambda f: f["lineno"]),
            "imports": sorted(imports, key=lambda i: i["lineno"]),
            "operators": operators[:20],
            "operator_count": op_count,
            "branch_count": branch_count,
        }

    # --- get_function() ---
    def get_function(self, func_name: str) -> dict[str, Any]:
        """Return detailed info for a function.

        Returns dict with:
            - name: function name
            - fullname: fully qualified name
            - lineno: definition line number
            - file_path: source file
            - params: [{name, lineno}]
            - return_nodes: [{lineno, expr}]
            - callers: [{vid, name, file_path, lineno}]
            - callees: [{vid, name, lineno}]
            - taint_type: if enriched (source/safe/passthrough/None)
        """
        func_vids = self._analyzer.find_function_def(func_name)
        if not func_vids:
            return {"error": f"Function not found: {func_name}"}

        # Take the first match
        fv = self.graph.vs[func_vids[0]]
        result = {
            "name": _vattr(fv, "name", ""),
            "fullname": _vattr(fv, "fullname", ""),
            "lineno": _vattr(fv, "lineno", 0),
            "file_path": _vattr(fv, "file_path", ""),
            "params": [],
            "return_nodes": [],
            "callers": [],
            "callees": [],
            "taint_type": _vattr(fv, "taint_type", None),
        }

        # Params (own children with label=parameter)
        for e in self.graph.es.select(_source=func_vids[0], label="own"):
            pv = self.graph.vs[e.target]
            if _vattr(pv, "label") == NodeLabel.PARAMETER.value:
                result["params"].append({
                    "name": _vattr(pv, "name", ""),
                    "lineno": _vattr(pv, "lineno", 0),
                })

        # Return nodes (own children with label=return)
        for e in self.graph.es.select(_source=func_vids[0], label="own"):
            rv = self.graph.vs[e.target]
            if _vattr(rv, "label") == NodeLabel.RETURN.value:
                result["return_nodes"].append({
                    "lineno": _vattr(rv, "lineno", 0),
                    "expr": _vattr(rv, "name", ""),
                })

        # Callers: operators that call this function (use edges pointing to this function)
        for e in self.graph.es.select(_target=func_vids[0], label="use"):
            caller_vid = e.source
            cv = self.graph.vs[caller_vid]
            callee_name = _vattr(cv, "name", "")
            # Check if this operator actually calls our function
            if callee_name == func_name or callee_name.endswith("\\" + func_name):
                result["callers"].append({
                    "vid": caller_vid,
                    "name": callee_name,
                    "file_path": _vattr(cv, "file_path", ""),
                    "lineno": _vattr(cv, "lineno", 0),
                })

        # Callees: functions this function calls
        for e in self.graph.es.select(_source=func_vids[0], label="use"):
            callee_vid = e.target
            cv = self.graph.vs[callee_vid]
            if _vattr(cv, "label") == NodeLabel.FUNCTION.value:
                result["callees"].append({
                    "vid": callee_vid,
                    "name": _vattr(cv, "name", ""),
                    "lineno": _vattr(cv, "lineno", 0),
                })

        return result

    # --- trace() ---
    def _find_file_vid(self, file_path: str) -> int | None:
        """Find file node vid by name (exact or basename match)."""
        from os.path import basename
        target_basename = basename(file_path)
        for v in self.graph.vs:
            if _vattr(v, "label") == NodeLabel.FILE.value:
                name = _vattr(v, "name", "")
                if name == file_path or basename(name) == target_basename:
                    return v.index
        return None

    def _is_descendant_of(self, child_vid: int, ancestor_vid: int) -> bool:
        """Check if child_vid is in the own-subtree of ancestor_vid."""
        visited = set()
        queue = [ancestor_vid]
        while queue:
            next_q = []
            for cur in queue:
                for e in self.graph.es.select(_source=cur, label="own"):
                    cid = e.target
                    if cid == child_vid:
                        return True
                    if cid not in visited:
                        visited.add(cid)
                        next_q.append(cid)
            queue = next_q
        return False

    def trace(self, file_path: str, line: int) -> list[dict[str, Any]]:
        """Run taint backtracking analysis on all sinks at the given line.

        Returns list of analysis results, one per sink found at that line:
            - sink: {name, lineno, type}
            - arg_index: which argument was traced
            - result: AnalysisResult details (code, source, path, etc.)
        """
        sinks = self._analyzer.find_sinks()
        results = []

        # Find file node for scoping
        file_vid = self._find_file_vid(file_path)

        for sink in sinks:
            if sink["lineno"] != line:
                continue
            # If file_path is set on sink (not None/empty/NaN), match directly
            # Otherwise fall through to structural containment check
            sink_fp = sink.get("file_path") or None
            if sink_fp and sink_fp != file_path and sink_fp != "None":
                continue
            if file_vid is not None and not self._is_descendant_of(sink["vid"], file_vid):
                continue

            for i, arg_vid in enumerate(sink.get("arg_vids", [])):
                analysis = self._analyzer.parameters_back(arg_vid)
                results.append({
                    "sink": {
                        "name": sink["name"],
                        "lineno": sink["lineno"],
                        "type": sink["type"],
                        "vid": sink["vid"],
                    },
                    "arg_index": i,
                    "result": {
                        "code": analysis.code,
                        "reason": analysis.reason,
                        "chain": analysis.chain,
                        "path": analysis.path,
                        "expr_lineno": analysis.expr_lineno,
                        "deps": analysis.deps,
                        "description": str(analysis),
                    },
                })

        return results

    # --- search() ---
    def search(
        self,
        label: str | None = None,
        name: str | None = None,
        node_type: str | None = None,
        file_path: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Generic node search with optional filters.

        Args:
            label: Node label filter (file/class/function/operator/etc)
            name: Name substring match (case-insensitive)
            node_type: Node type filter (for operator: call/assign/binary_op/etc)
            file_path: Restrict to nodes in this file
            limit: Max results (default 50)

        Returns list of {vid, label, name, type, file_path, lineno}
        """
        name_lower = name.lower() if name else None
        results = []

        for v in self.graph.vs:
            if label and _vattr(v, "label") != label:
                continue
            if name_lower:
                vname = _vattr(v, "name", "")
                if name_lower not in vname.lower():
                    continue
            if node_type and _vattr(v, "type") != node_type:
                continue
            if file_path and _vattr(v, "file_path") != file_path:
                continue

            results.append({
                "vid": v.index,
                "label": _vattr(v, "label", ""),
                "name": _vattr(v, "name", ""),
                "type": _vattr(v, "type", ""),
                "file_path": _vattr(v, "file_path", ""),
                "lineno": int(_vattr(v, "lineno", 0) or 0),
            })

            if len(results) >= limit:
                break

        return results

    # --- get_subgraph() ---
    def get_subgraph(
        self,
        center_vid: int,
        depth: int = 2,
        edge_labels: list[str] | None = None,
        max_nodes: int = 500,
    ) -> dict[str, Any]:
        """Extract a subgraph centered on a given node via BFS.

        Args:
            center_vid: Center node vertex ID.
            depth: BFS depth (default 2).
            edge_labels: Optional edge label filter (only follow these edges).
                When None, all edges are traversed for BFS and included.
            max_nodes: Safety cap on node count (default 500).

        Returns dict with:
            - center_vid: center node ID
            - nodes: [{id, label, name, type, file_path, lineno, taint_type}]
            - edges: [{source, target, label, type}]
            - total_nodes / total_edges
        """
        edge_label_set = set(edge_labels) if edge_labels else None

        # BFS
        visited: set[int] = {center_vid}
        queue = [center_vid]
        for _ in range(depth):
            if len(visited) > max_nodes:
                break
            next_queue: list[int] = []
            for vid in queue:
                for nb in self.graph.neighbors(vid, mode="all"):
                    if nb in visited:
                        continue
                    # If edge_labels filter set, check at least one edge vid↔nb has matching label
                    if edge_label_set:
                        has_match = False
                        for e in self.graph.es.select(_source=vid, _target=nb):
                            if _vattr(e, "label") in edge_label_set:
                                has_match = True
                                break
                        if not has_match:
                            for e in self.graph.es.select(_source=nb, _target=vid):
                                if _vattr(e, "label") in edge_label_set:
                                    has_match = True
                                    break
                        if not has_match:
                            continue
                    visited.add(nb)
                    next_queue.append(nb)
            queue = next_queue

        return self._serialize_subgraph(visited, edge_label_set, center_vid)

    # --- get_file_subgraph() ---
    def get_file_subgraph(
        self,
        file_path: str,
        include_cross_edges: bool = True,
        max_nodes: int = 1000,
    ) -> dict[str, Any]:
        """Extract the subgraph for a specific file.

        Collects all nodes under the file node via ``own`` edges,
        plus optionally all edges between those nodes (including cg/dfg/use).

        Args:
            file_path: File path to look up.
            include_cross_edges: If True, include non-own edges between
                file-owned nodes (cg, dfg, use, etc.).
            max_nodes: Safety cap.

        Returns same format as get_subgraph().
        """
        file_vid = self._find_file_vid(file_path)
        if file_vid is None:
            return {"error": f"File not found: {file_path}"}

        # Collect all descendants via own edges
        visited: set[int] = {file_vid}
        queue = [file_vid]
        while queue:
            if len(visited) > max_nodes:
                break
            next_queue: list[int] = []
            for vid in queue:
                for e in self.graph.es.select(_source=vid, label="own"):
                    if e.target not in visited:
                        visited.add(e.target)
                        next_queue.append(e.target)
            queue = next_queue

        edge_label_set = None if include_cross_edges else {"own"}
        return self._serialize_subgraph(visited, edge_label_set)

    # --- internal: _serialize_subgraph() ---
    def _serialize_subgraph(
        self,
        vids: set[int],
        edge_label_set: set[str] | None = None,
        center_vid: int | None = None,
    ) -> dict[str, Any]:
        """Serialize a set of vertex IDs into the subgraph JSON format."""
        # Serialize nodes
        nodes = []
        for vid in sorted(vids):
            v = self.graph.vs[vid]
            nodes.append({
                "id": vid,
                "label": _vattr(v, "label", ""),
                "name": _vattr(v, "name", ""),
                "type": _vattr(v, "type", ""),
                "file_path": _vattr(v, "file_path", ""),
                "lineno": int(_vattr(v, "lineno", 0) or 0),
                "taint_type": _vattr(v, "taint_type", None),
            })

        # Collect edges between visited nodes efficiently
        edge_set: set[int] = set()
        for vid in vids:
            for eid in self.graph.incident(vid, mode="all"):
                e = self.graph.es[eid]
                if e.source in vids and e.target in vids:
                    if edge_label_set and _vattr(e, "label") not in edge_label_set:
                        continue
                    edge_set.add(eid)

        edges = []
        for eid in sorted(edge_set):
            e = self.graph.es[eid]
            edges.append({
                "source": e.source,
                "target": e.target,
                "label": _vattr(e, "label", ""),
                "type": _vattr(e, "type", ""),
            })

        result = {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
        }
        if center_vid is not None:
            result["center_vid"] = center_vid
        return result

    # --- get_chain_subgraph() ---
    def get_chain_subgraph(self, vids: list[int]) -> dict[str, Any]:
        """Extract subgraph for a list of VIDs (e.g., taint chain nodes).

        Simply collects the given VIDs + all edges between them.
        Unlike get_subgraph() which does BFS expansion, this is exact.

        Args:
            vids: List of vertex IDs from the chain.

        Returns:
            Same format as get_subgraph(): {nodes, edges, total_nodes, total_edges}
        """
        valid_vids = {v for v in vids if v is not None and 0 <= v < self.graph.vcount()}
        if not valid_vids:
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}
        return self._serialize_subgraph(valid_vids)
