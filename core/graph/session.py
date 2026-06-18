"""AST Graph Session — manages graph lifecycle for secondary analysis.

Loads a persisted igraph graph (.graphmlz) and provides a GraphQueryBuilder
for running queries without re-scanning.  Optionally loads SQLite index for
fast lookups.

Usage::

    from core.graph.session import AstGraphSession

    with AstGraphSession("/path/to/.kunlun_graph") as session:
        print(session.query.overview())
        print(session.query.get_file("src/app.php"))
        result = session.query.trace("src/app.php", 42)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

__all__ = ["AstGraphSession"]
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import igraph as ig


class AstGraphSession:
    """Context manager for an AST graph analysis session.

    Loads the graph on entry, provides query access, and cleans up on exit.
    The graph is read-only — no mutations are committed to disk.
    """

    def __init__(
        self,
        graph_dir: str,
        db_path: str | None = None,
        language: str = "php",
    ) -> None:
        """
        Args:
            graph_dir: Directory containing ast_graph.graphmlz.
            db_path: Optional SQLite DB path for node index queries.
            language: Primary source language.
        """
        self.graph_dir = graph_dir
        self.db_path = db_path
        self.language = language
        self._graph: ig.Graph | None = None
        self._query = None

    def __enter__(self) -> "AstGraphSession":
        self.load()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def load(self) -> None:
        """Load graph from .graphmlz file."""
        from core.graph.graph_io import AstGraphIO
        from core.graph.graph_query_builder import GraphQueryBuilder

        io = AstGraphIO(self.graph_dir)
        self._graph = io.load()

        if self._graph is None:
            raise FileNotFoundError(
                f"No valid graph found in {self.graph_dir}. "
                f"Run a scan first to build the graph."
            )

        logger.info(
            "Graph loaded: %d nodes, %d edges from %s",
            self._graph.vcount(),
            self._graph.ecount(),
            io.graph_path,
        )
        self._query = GraphQueryBuilder(self._graph, self.language)

    def close(self) -> None:
        """Release graph reference."""
        self._graph = None
        self._query = None

    @property
    def query(self):
        """Access the GraphQueryBuilder for this session."""
        if self._query is None:
            raise RuntimeError(
                "Session not loaded. Call load() or use as context manager."
            )
        return self._query

    @property
    def graph(self) -> "ig.Graph":
        """Direct access to the underlying igraph Graph (advanced use)."""
        if self._graph is None:
            raise RuntimeError("Session not loaded.")
        return self._graph

    @property
    def is_loaded(self) -> bool:
        return self._graph is not None
