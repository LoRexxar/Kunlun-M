"""Derived edge builders — registry + coordinator.

Each builder follows BaseEdgeBuilder.build(graph, language, **kwargs) -> int.
Builders run sequentially after AST mapping to derive additional edges.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.dfg import DataFlowBuilder
from core.graph.edge_builders.cg import CallGraphBuilder
from core.graph.edge_builders.alias import AliasBuilder

__all__ = ["run_all", "DataFlowBuilder", "CallGraphBuilder", "AliasBuilder"]

# Builder execution order
_BUILDERS = [
    ("dfg", DataFlowBuilder),
    ("cg", CallGraphBuilder),
    ("alias", AliasBuilder),
]


def run_all(graph: "ig.Graph", language: str, **kwargs) -> dict[str, int]:
    """Run all registered edge builders sequentially.

    Args:
        graph: igraph Graph with AST edges already present.
        language: Source language identifier.
        **kwargs: Passed to each builder's build() method.

    Returns:
        Dict mapping builder name to number of edges added.
    """
    results = {}
    for name, builder_cls in _BUILDERS:
        builder = builder_cls()
        count = builder.build(graph, language, **kwargs)
        results[name] = count
    return results
