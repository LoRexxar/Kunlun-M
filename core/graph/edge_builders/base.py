"""Base interface for derived edge builders.

Each builder follows the same contract:
    build(graph, language, **kwargs) -> int

Derived edges are computed after AST mapping (ast/own/use/crg/member/frg)
and enrich the graph with additional relationship edges (dfg, cg, etc.).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig


class BaseEdgeBuilder(ABC):
    """Abstract base for derived edge builders."""

    @abstractmethod
    def build(self, graph: "ig.Graph", language: str, **kwargs) -> int:
        """Build derived edges on the graph.

        Args:
            graph: igraph Graph with AST edges already present.
            language: Source language identifier ("php", "python", ...).
            **kwargs: Builder-specific options.

        Returns:
            Number of edges added.
        """
