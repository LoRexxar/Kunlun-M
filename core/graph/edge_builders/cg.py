"""Call graph edge builder — 推导 function→function 的 cg 边。

从已有边推导：
  function → own → operator(call) → use → function(callee)
生成：
  function(caller) → cg → function(callee)
"""

from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.base import BaseEdgeBuilder
from core.graph.node_edge_schema import EdgeLabel, NodeLabel, OperatorType
from utils.igraph_compat import _vattr

__all__ = ["CallGraphBuilder"]

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
}

class CallGraphBuilder(BaseEdgeBuilder):
    """推导 function→function 的调用图边。"""

    def build(self, graph: "ig.Graph", language: str = "php", **kwargs) -> int:
        count = 0

        # ── 1. 预构建边索引 ──────────────────────────────────────
        # own_src_idx[(src)] → [tgt]  : function 下 own 出边（找 call operator）
        # use_src_idx[(src)] → [tgt]  : operator 下 use 出边（找 callee function）
        own_src_idx: dict[int, list[int]] = {}
        use_src_idx: dict[int, list[int]] = {}
        for e in graph.es:
            lbl = _vattr(e, "label", "")
            s = e.source
            if lbl == "own":
                own_src_idx.setdefault(s, []).append(e.target)
            elif lbl == "use":
                use_src_idx.setdefault(s, []).append(e.target)

        # ── 2. 预构建函数节点集合 ────────────────────────────────
        func_vids: set[int] = set()
        for v in graph.vs:
            if _vattr(v, "label") == NodeLabel.FUNCTION.value:
                func_vids.add(v.index)

        # ── 3. 遍历函数 → call operator → use callee，批量收集 ──
        # Fix 34b: previously only operators OWNED directly by the function
        # node were visited.  Calls nested inside if/else/loop/branch blocks
        # (own chain: function → branch → … → operator) were invisible to
        # the callgraph (CVE-2026-108970: Session::register calls
        # addNewUser inside an if block -- no cg edge, function judged
        # dead, sink skipped).  Walk each function's full own subtree.
        children_of: dict[int, list[int]] = {}
        for src, tgts in own_src_idx.items():
            children_of[src] = tgts

        def _iter_own_subtree(root_vid: int):
            """Yield all vids in the own subtree rooted at root_vid (incl.)."""
            stack = [root_vid]
            seen = set()
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                yield cur
                for ch in children_of.get(cur, ()):
                    if ch not in seen:
                        stack.append(ch)

        cg_edges: dict[tuple[int, int], dict] = {}  # (caller, callee) → attrs

        for func_vid in func_vids:
            # Fix 34b: full own subtree, not just direct own children
            for op_vid in _iter_own_subtree(func_vid):
                ov = graph.vs[op_vid]
                if _vattr(ov, "label") != NodeLabel.OPERATOR.value:
                    continue
                if _vattr(ov, "type") not in _CALL_TYPES:
                    continue
                # call operator 下的 use 出边
                use_tgts = use_src_idx.get(op_vid, [])
                for callee_vid in use_tgts:
                    if callee_vid not in func_vids or callee_vid == func_vid:
                        continue
                    key = (func_vid, callee_vid)
                    if key not in cg_edges:
                        cg_edges[key] = {}

        # ── 4. 回填 use 边属性（call_type, lineno）──────────────
        # 从 use 边获取属性（可能有多个 call_type，取第一个）
        use_attrs: dict[int, list[dict]] = {}
        for e in graph.es:
            if _vattr(e, "label", "") == "use":
                s = e.source
                use_attrs.setdefault(s, []).append({
                    "target": e.target,
                    "call_type": _vattr(e, "call_type", "direct"),
                    "lineno": _vattr(e, "lineno", 0),
                })

        for (caller, callee), attrs in cg_edges.items():
            # 找 caller 下 call operator 的 use 边指向 callee 的属性
            # (Fix 34b: subtree walk mirrors the collection phase above)
            own_tgts = list(_iter_own_subtree(caller))
            for op_vid in own_tgts:
                ov = graph.vs[op_vid]
                if _vattr(ov, "label") != NodeLabel.OPERATOR.value:
                    continue
                if _vattr(ov, "type") not in _CALL_TYPES:
                    continue
                for ua in use_attrs.get(op_vid, []):
                    if ua["target"] == callee:
                        attrs["call_type"] = ua["call_type"]
                        attrs["lineno"] = ua["lineno"]
                        break
                if attrs:
                    break

        # ── 5. 批量写入 ─────────────────────────────────────────
        if cg_edges:
            edges = [(s, t) for s, t in cg_edges.keys()]
            # attributes 需要 dict[str, list]，长度与 edges 一致
            attr_dict: dict[str, list] = {}
            # Fix 34: label='cg' was never set -- all callgraph edges got
            # label=None, so every label="cg" query in the scanner (dead
            # code check, interprocedural taint) matched nothing and all
            # sinks inside called functions were treated as dead code
            # (CVE-2026-108970: addNewUser mysqli_query missed).
            attr_dict["label"] = ["cg"] * len(edges)
            for key in ("call_type", "lineno"):
                vals = []
                for (s, t), a in cg_edges.items():
                    vals.append(a.get(key, "direct" if key == "call_type" else 0))
                attr_dict[key] = vals
            graph.add_edges(edges, attributes=attr_dict)
            count = len(cg_edges)

        return count
