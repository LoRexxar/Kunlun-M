"""Backward-compatible re-export.

DataFlowAnalyzer has been moved to core.graph.edge_builders.dfg.DataFlowBuilder.
This module keeps the old import path working.
"""

from core.graph.edge_builders.dfg import DataFlowBuilder as DataFlowAnalyzer
from core.graph.edge_builders.dfg import DataFlowBuilder as _DFA  # noqa: F811
from core.graph.edge_builders.cg import CallGraphBuilder
from core.graph.edge_builders import run_all as run_all_edge_builders

__all__ = [
    "DataFlowAnalyzer",
    "DataFlowBuilder",
    "CallGraphBuilder",
    "run_all_edge_builders",
]
