"""Graph Traversal — Joern CPGQL-style fluent graph query for console."""

from __future__ import annotations

from collections import deque
from typing import Any
import warnings

import igraph as ig

from core.graph.node_edge_schema import NodeLabel, EdgeLabel
from utils.igraph_compat import _vattr

__all__ = ["GraphTraversal"]

# 9 edge types for dynamic property generation
_EDGE_TYPES = [e.value for e in EdgeLabel]
_NODE_LABELS = [n.value for n in NodeLabel]


class GraphTraversal:
    """Joern CPGQL-style graph traversal.

    Usage:
        g = GraphTraversal(graph)

        # Node type filter + name filter
        g.function                          # all function nodes
        g.function.main                     # function nodes named "main"

        # Edge traversal (18 properties)
        g.function.main.ownout              # nodes owned by function "main"
        g.function.main.dfgin               # nodes flowing into function "main"

        # Wildcard traversal
        g.function.main.outall              # all nodes reachable via outgoing edge
        g.function.main.inall               # all nodes reachable via incoming edge

        # Variable binding
        a = g.function.main
        a.ownout                            # same as g.function.main.ownout

        # Output (terminal operators — auto-evaluated as property access)
        g.function.l()                      # formatted list (needs parens)
        g.function.count                    # node count (auto-call, no parens needed)
        g.function.ids                      # vid list (auto-call, no parens needed)
        g.function.nodes                    # node attribute dicts (auto-call)

        # Also available as methods (when chained with parens):
        g.function.n()                      # same as .count
        g.function.vids()                    # same as .ids
        g.function._nodes()                  # same as .nodes

        # Analysis
        g.find_dfg(source_vid, sink_vid)        # find data flow path
        g.shortest_path(source_vid, target_vid) # shortest path
    """

    def __init__(self, graph: ig.Graph, language: str = ""):
        self.graph = graph
        self.language = language
        self._vids: list[int] | None = None  # None = 未筛选（所有节点），[] = 空结果

    # ------------------------------------------------------------------
    # 内部辅助
    # ------------------------------------------------------------------

    def _with_vids(self, vids: list[int]) -> "GraphTraversal":
        """根据给定 vid 列表返回新的 Traversal 实例（共享 graph/language）。"""
        t = GraphTraversal.__new__(GraphTraversal)
        t.graph = self.graph
        t.language = self.language
        t._vids = vids
        return t

    def _filter_by_label(self, label: str) -> "GraphTraversal":
        """按节点 label 过滤（如 g.function 返回所有 function 节点）。"""
        vids = [v.index for v in self.graph.vs if _vattr(v, "label") == label]
        return self._with_vids(vids)

    def _filter_by_name(self, name: str) -> "GraphTraversal":
        """按节点 name 过滤（如 g.function.main 返回 name=='main' 的 function 节点）。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        vids = [vid for vid in base if _vattr(self.graph.vs[vid], "name") == name]
        return self._with_vids(vids)

    def _traverse_out(self, edge_type: str) -> "GraphTraversal":
        """沿指定边类型出方向遍历：source 在当前集合中，收集 target。"""
        if not self._vids:
            return self._with_vids([])
        source_set = set(self._vids)
        vids = []
        for e in self.graph.es:
            if _vattr(e, "label") == edge_type and e.source in source_set:
                vids.append(e.target)
        return self._with_vids(vids)

    def _traverse_in(self, edge_type: str) -> "GraphTraversal":
        """沿指定边类型入方向遍历：target 在当前集合中，收集 source。"""
        if not self._vids:
            return self._with_vids([])
        target_set = set(self._vids)
        vids = []
        for e in self.graph.es:
            if _vattr(e, "label") == edge_type and e.target in target_set:
                vids.append(e.source)
        return self._with_vids(vids)

    def _traverse_all_out(self) -> "GraphTraversal":
        """沿所有出边遍历（不限边类型）。"""
        if not self._vids:
            return self._with_vids([])
        source_set = set(self._vids)
        vids = []
        for e in self.graph.es:
            if e.source in source_set:
                vids.append(e.target)
        return self._with_vids(vids)

    def _traverse_all_in(self) -> "GraphTraversal":
        """沿所有入边遍历（不限边类型）。"""
        if not self._vids:
            return self._with_vids([])
        target_set = set(self._vids)
        vids = []
        for e in self.graph.es:
            if e.target in target_set:
                vids.append(e.source)
        return self._with_vids(vids)

    # ------------------------------------------------------------------
    # 动态属性路由
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> "GraphTraversal":
        # 注意：__getattr__ 仅在常规属性查找失败时触发，
        # 因此 self.graph / self.language / self._vids 等真实属性不会进入这里。

        # 0. 特殊终端操作符：自动调用对应方法返回结果
        # （这些不能定义为真实方法，否则 __getattribute__ 会优先返回方法对象）
        if name == "count":
            return self.n()
        if name == "ids":
            return self.vids()
        if name == "nodes":
            return self._nodes()

        # 1. 节点类型匹配（如 g.function）
        if name in _NODE_LABELS:
            return self._filter_by_label(name)

        # 2. 边遍历：{edge_type}{direction}（如 ownout, dfgin, cgout, usein）
        for edge_type in _EDGE_TYPES:
            if name == f"{edge_type}out":
                return self._traverse_out(edge_type)
            if name == f"{edge_type}in":
                return self._traverse_in(edge_type)

        # 3. 特殊：outall / inall
        if name == "outall":
            return self._traverse_all_out()
        if name == "inall":
            return self._traverse_all_in()

        # 4. 链式命名：当 _vids 非空（已通过 label 过滤），按 name 过滤
        # 例：g.function.main  →  先 .function (label) 再 .main (name)
        return self._filter_by_name(name)

    # ------------------------------------------------------------------
    # 输出方法
    # ------------------------------------------------------------------

    def l(self) -> None:
        """格式化打印当前节点集合。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        for vid in base:
            v = self.graph.vs[vid]
            label = _vattr(v, "label", "?")
            name = _vattr(v, "name", "<anon>")
            lineno = _vattr(v, "lineno", 0)
            file_path = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            print(f"[{label}] {name}  vid={vid}  L{lineno}")
            if file_path:
                print(f"  file: {file_path}")
            # 显示额外属性（排除基础属性）
            extra = {
                k: val for k, val in dict(v.attributes()).items()
                if k not in ("label", "name", "lineno", "end_lineno",
                             "file_path", "path", "language") and val
            }
            for k, val in extra.items():
                print(f"  {k}: {val}")

    def pprint(self) -> None:
        """Alias for l()."""
        self.l()

    def n(self) -> int:
        """返回当前节点集合的大小。在 REPL 中推荐用 .n() 代替 .count()，
        因为 .count 会被 Python __getattribute__ 拦截为方法对象。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        return len(base)

    # count() 在 __getattr__ 中特殊处理——当链式末尾访问 .count 时自动调用 n()
    # 不能定义为真实方法，否则 Python __getattribute__ 会优先返回方法对象

    def vids(self) -> list[int]:
        """返回当前节点集合的 vid 列表。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        return base

    def _nodes(self) -> list[dict]:
        """返回当前节点集合的属性字典列表（含 _vid）。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        result = []
        for vid in base:
            v = self.graph.vs[vid]
            attrs = dict(v.attributes())
            attrs["_vid"] = vid
            result.append(attrs)
        return result

    def code(self) -> None:
        """显示当前节点集合的源码上下文（如果可用）。"""
        base = self._vids if self._vids is not None else [v.index for v in self.graph.vs]
        for vid in base:
            v = self.graph.vs[vid]
            label = _vattr(v, "label", "?")
            name = _vattr(v, "name", "<anon>")
            lineno = _vattr(v, "lineno", 0)
            file_path = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            print(f"[{label}] {name}  vid={vid}  L{lineno}  {file_path}")

    # ------------------------------------------------------------------
    # 分析函数
    # ------------------------------------------------------------------

    def find_dfg(self, source_vid: int, sink_vid: int, max_depth: int = 50) -> list[int]:
        """BFS 从 source 沿 dfg 边到达 sink，返回路径 vid 列表；找不到返回空列表。

        Args:
            source_vid: 起点节点 vid。
            sink_vid: 终点节点 vid。
            max_depth: 最大路径深度，避免无限展开。

        Returns:
            vid 路径列表（含起点和终点）；不可达时返回 ``[]``。
        """
        if source_vid == sink_vid:
            return [source_vid]
        visited = {source_vid}
        queue = deque([(source_vid, [source_vid])])
        while queue:
            cur, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            for e in self.graph.es:
                if _vattr(e, "label") != "dfg" or e.source != cur:
                    continue
                nxt = e.target
                if nxt in visited:
                    continue
                if nxt == sink_vid:
                    return path + [nxt]
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))
        return []

    def shortest_path(self, source_vid: int, target_vid: int) -> list[int]:
        """任意边类型下的最短路径（视为无向图）。

        Args:
            source_vid: 起点 vid。
            target_vid: 终点 vid。

        Returns:
            vid 路径列表；不可达或异常时返回 ``[]``。
        """
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                paths = self.graph.get_shortest_paths(source_vid, target_vid, mode="all")
                return paths[0] if paths and paths[0] else []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # 表示
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        n = self.graph.vcount() if self._vids is None else len(self._vids)
        return f"<GraphTraversal {n} node(s)>"
