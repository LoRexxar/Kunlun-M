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
        # 遍历所有 function 节点
        for fv in graph.vs:
            if _vattr(fv, "label") != NodeLabel.FUNCTION.value:
                continue
            func_vid = fv.index
            # 找 function 下的 call operator
            for oe in graph.es.select(_source=func_vid, label="own"):
                ov = graph.vs[oe.target]
                if _vattr(ov, "label") != NodeLabel.OPERATOR.value:
                    continue
                if _vattr(ov, "type") not in _CALL_TYPES:
                    continue
                op_vid = oe.target
                # 找 call operator 的 use → function(callee)
                for ue in graph.es.select(_source=op_vid, label="use"):
                    callee_vid = ue.target
                    callee_v = graph.vs[callee_vid]
                    if _vattr(callee_v, "label") != NodeLabel.FUNCTION.value:
                        continue
                    # 避免重复边
                    if func_vid == callee_vid:
                        continue
                    # 检查是否已存在同方向 cg 边
                    exists = False
                    for ce in graph.es.select(_source=func_vid, _target=callee_vid, label="cg"):
                        exists = True
                        break
                    if not exists:
                        call_type = _vattr(ue, "call_type", "direct")
                        lineno = _vattr(ue, "lineno", 0)
                        graph.add_edge(func_vid, callee_vid,
                                       label="cg",
                                       call_type=call_type,
                                       lineno=lineno)
                        count += 1
        return count
