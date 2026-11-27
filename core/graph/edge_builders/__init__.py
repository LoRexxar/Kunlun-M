"""Derived edge builders — registry + coordinator.

Each builder follows BaseEdgeBuilder.build(graph, language, **kwargs) -> int.
Builders run sequentially after AST mapping to derive additional edges.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.dfg import DataFlowBuilder
from core.graph.edge_builders.use import UseEdgeBuilder
from core.graph.edge_builders.cg import CallGraphBuilder
from core.graph.edge_builders.alias import AliasBuilder

__all__ = [
    "run_all", "DataFlowBuilder", "UseEdgeBuilder",
    "CallGraphBuilder", "AliasBuilder",
]

# Builder execution order
# dfg_phase1  → use → dfg_phase2 → cg → alias → dfg_phase3
# DFG split into two phases: phase 1 builds basic DFG edges; use edges built
# after phase 1 so receiver type resolution can leverage them; phase 2 runs
# analyses that depend on use edges (param passing, return propagation,
# fluent API returns). CG needs use edges to derive function→function call
# graph; alias runs last.  Phase 3 (Fix 157k, CVE-2026-124444) re-runs the
# arg→param binding AFTER alias edges exist: the alias builder resolves
# bodyless use targets to real functions, and only then can indirect calls
# (DataSet:133 → DataAdapter::Select) bind their arguments — the analyzer
# side already follows alias edges; phase 3 closes the builder-side gap.
_BUILDERS = [
    ("dfg_phase1", DataFlowBuilder),
    ("use", UseEdgeBuilder),
    ("dfg_phase2", DataFlowBuilder),
    ("cg", CallGraphBuilder),
    ("alias", AliasBuilder),
    ("dfg_phase3", DataFlowBuilder),
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
        if name == "dfg_phase1":
            count = builder.build(graph, language, phase=1, **kwargs)
        elif name == "dfg_phase2":
            count = builder.build(graph, language, phase=2, **kwargs)
        elif name == "dfg_phase3":
            count = builder.build(graph, language, phase=3, **kwargs)
        else:
            count = builder.build(graph, language, **kwargs)
        results[name] = count
    return results
