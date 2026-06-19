"""AST Graph Builder — assembles UnifiedNode/UnifiedEdge into an igraph Graph.

Language-independent.  Receives normalized node/edge lists from a Normalizer
and builds a complete, queryable AST graph.
"""

from __future__ import annotations

from typing import Any

__all__ = ["AstGraphBuilder"]


# ---------------------------------------------------------------------------
# AstGraphBuilder
# ---------------------------------------------------------------------------

class AstGraphBuilder:
    """Builds an igraph Graph from UnifiedNode / UnifiedEdge lists.

    Usage::

        builder = AstGraphBuilder()
        builder.add_file(file_node, nodes, edges)
        graph = builder.build()

    The builder accumulates nodes and edges across files, then produces
    a single igraph Graph with all attributes stored as vertex/edge attributes.
    """

    def __init__(self) -> None:
        self._nodes: list[dict[str, Any]] = []
        self._edges: list[dict[str, Any]] = []
        self._node_offset = 0

    # -- public API -----------------------------------------------------------

    def add_file(
        self,
        file_node: dict[str, Any],
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> None:
        """Add a single file's worth of nodes and edges.

        Edge source/target values from the Normalizer are **local** (0-based
        per file).  This method applies a global offset so that edges from
        later files correctly reference their own nodes.
        """
        offset = self._node_offset

        # File node becomes the first node for this file
        self._nodes.append(file_node)
        # Offset for child nodes: file_node is at `offset`, so child
        # source/target values (0-based relative to file_node) need +offset
        self._nodes.extend(nodes)

        # Remap edge source/target to global indices
        for edge in edges:
            edge["source"] = edge.get("source", 0) + offset
            edge["target"] = edge.get("target", 0) + offset
        self._edges.extend(edges)

        # Update offset for next file
        self._node_offset = len(self._nodes)

    def build(self) -> Any:
        """Build the final igraph Graph from accumulated nodes and edges.

        Returns:
            An igraph Graph object.  Vertex attributes include ``label``,
            ``name``, ``lineno``, ``end_lineno``, ``language``, plus all keys
            from ``attrs`` flattened.  Edge attributes include ``label`` plus
            all keys from ``attrs`` flattened.

        Raises:
            ImportError: If igraph is not installed.
        """
        try:
            import igraph as ig
        except ImportError:
            raise ImportError(
                "igraph is required for graph building. "
                "Install it with: pip install python-igraph"
            )

        if not self._nodes:
            return ig.Graph(directed=True)

        # Collect all attribute keys across all nodes
        node_attr_keys = set()
        for n in self._nodes:
            node_attr_keys.update(k for k in n.keys() if k != "attrs")
            node_attr_keys.update(n.get("attrs", {}).keys())
        node_attr_keys.discard("attrs")

        # Build vertex attribute lists
        n_count = len(self._nodes)
        v_attrs: dict[str, list] = {k: [] for k in node_attr_keys}

        for n in self._nodes:
            attrs = dict(n.get("attrs", {}))
            for k in node_attr_keys:
                if k == "label":
                    v_attrs["label"].append(n.get("label", ""))
                elif k == "name":
                    v_attrs["name"].append(n.get("name", ""))
                elif k == "lineno":
                    v_attrs["lineno"].append(n.get("lineno", 0))
                elif k == "end_lineno":
                    v_attrs["end_lineno"].append(n.get("end_lineno", 0))
                elif k == "language":
                    v_attrs["language"].append(n.get("language", ""))
                else:
                    v_attrs[k].append(attrs.get(k))

        # Create graph
        g = ig.Graph(
            n=n_count,
            directed=True,
            vertex_attrs=v_attrs if v_attrs else None,
        )

        # Collect all edge attribute keys
        edge_attr_keys = set()
        for e in self._edges:
            edge_attr_keys.update(k for k in e.keys() if k != "attrs")
            edge_attr_keys.update(e.get("attrs", {}).keys())
        edge_attr_keys.discard("attrs")

        if self._edges:
            e_list: list[tuple[int, int]] = []
            e_attrs: dict[str, list] = {k: [] for k in edge_attr_keys}

            for e in self._edges:
                src = e.get("source", 0)
                tgt = e.get("target", 0)
                if src >= n_count or tgt >= n_count:
                    continue
                e_list.append((src, tgt))

                e_extra = dict(e.get("attrs", {}))
                for k in edge_attr_keys:
                    if k == "label":
                        e_attrs["label"].append(e.get("label", ""))
                    else:
                        e_attrs[k].append(e_extra.get(k))

            g.add_edges(e_list, attributes=e_attrs if e_attrs else None)

        return g

    @property
    def node_count(self) -> int:
        """Number of accumulated nodes (including file nodes)."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Number of accumulated edges."""
        return len(self._edges)

    def clear(self) -> None:
        """Reset the builder, discarding all accumulated nodes and edges."""
        self._nodes.clear()
        self._edges.clear()
        self._node_offset = 0
