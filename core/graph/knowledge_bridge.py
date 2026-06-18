"""Knowledge bridge — 图构建阶段的 taint enrichment。

在 DFG 边生成之后、图分析之前，遍历所有 function 节点，
查询知识库（TraceCache / SourceRegistry / 函数摘要），
将污染传播行为标注为节点属性：

    - function 节点: taint_type = "source" | "safe" | "passthrough"
    - function 节点: taint_passthrough = [0, 2, ...]  （passthrough 时，常驻属性）
    - parameter 节点 (function 的 own 子节点, passthrough 时):
      taint_type = "passthrough_arg"

taint_passthrough 是 function 上的常驻属性，与 parameter 上的 passthrough_arg
是同一份数据的两个视图：
    - 反向分析（call → function）：直接读 function.taint_passthrough
    - 正向分析（function body 内）：读 parameter.taint_type="passthrough_arg"

分析器遇到 call operator 时：
    call → use 边 → function(读 taint_type)
      → source/safe: 直接判定
      → passthrough: 读 taint_passthrough → 映射 call 的 ast[role=arg] → 追踪实参

核心原则：
- 属性标在函数定义上，不标在调用点上
- 不遍历 AST，只读图的属性和边
- 知识库是只读查询对象，由外部传入
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.graph.node_edge_schema import NodeLabel
from utils.igraph_compat import _vattr

if TYPE_CHECKING:
    import igraph as ig

__all__ = ["enrich_taint"]

logger = logging.getLogger(__name__)


def enrich_taint(
    graph: ig.Graph,
    language: str,
    trace_cache=None,
    source_registry=None,
    summary_lookup=None,
) -> int:
    """遍历图中所有 function 节点，查询知识库并标注 taint 属性。

    Args:
        graph: 已构建的 igraph AST 图
        language: 语言标识 ("php", "python", ...)
        trace_cache: TraceCache 实例（可选），提供 lookup_builtin(name) 方法
        source_registry: SourceRegistry 实例（可选）
        summary_lookup: 可调用对象 summary_lookup(name) → FunctionSummary | None

    Returns:
        标注的 function 节点数量
    """
    count = 0
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.FUNCTION.value:
            continue

        func_vid = v.index
        func_name = _vattr(v, "name", "")
        fullname = _vattr(v, "fullname", "")
        if not func_name:
            continue

        # 1. TraceCache builtin（内置函数没有图中的 body，直接查知识库）
        if trace_cache is not None:
            if _enrich_from_builtin(graph, func_vid, func_name, trace_cache):
                count += 1
                continue

        # 2. SourceRegistry（框架 source producer 方法/函数）
        if source_registry is not None:
            if _enrich_from_source_registry(graph, func_vid, func_name, source_registry):
                count += 1
                continue

        # 3. 函数摘要（用户自定义函数的返回值数据流）
        if summary_lookup is not None:
            if _enrich_from_summary(graph, func_vid, func_name, summary_lookup):
                count += 1
                continue

    logger.debug("enrich_taint: annotated %d function nodes", count)
    return count


# ---------------------------------------------------------------------------
# Internal: enrichment helpers — 标注在 function + parameter 节点上
# ---------------------------------------------------------------------------

def _enrich_from_builtin(graph: ig.Graph, func_vid: int, func_name: str, trace_cache) -> bool:
    """从 TraceCache 内置知识库标注。"""
    knowledge = trace_cache.lookup_builtin(func_name)
    if not knowledge:
        return False

    safe = knowledge.get("safe", False)
    passthrough: list[int] = knowledge.get("passthrough", [])

    if safe and not passthrough:
        graph.vs[func_vid]["taint_type"] = "safe"
        return True

    if passthrough:
        graph.vs[func_vid]["taint_type"] = "passthrough"
        graph.vs[func_vid]["taint_passthrough"] = passthrough
        _mark_passthrough_params(graph, func_vid, passthrough)
        return True

    # 有记录但 safe=False 且无 passthrough
    graph.vs[func_vid]["taint_type"] = "safe"
    return True


def _enrich_from_source_registry(
    graph: ig.Graph, func_vid: int, func_name: str, source_registry,
) -> bool:
    """从 SourceRegistry 标注框架 source producer。"""
    simple_name = _get_simple_name(func_name)

    # source producer 函数
    info = source_registry.is_source_producer(simple_name)
    if info:
        graph.vs[func_vid]["taint_type"] = "source"
        return True

    return False


def _enrich_from_summary(
    graph: ig.Graph, func_vid: int, func_name: str, summary_lookup,
) -> bool:
    """从函数摘要标注。

    函数摘要记录了返回值的数据流来源（param/global/call/literal）。
    - param 来源 → function 标为 passthrough，对应 parameter 标为 passthrough_arg
    - global/call 来源且为 source → function 标为 source
    - literal 来源 → function 标为 safe
    """
    summary = summary_lookup(func_name)
    if not summary or not summary.return_flow:
        return False

    passthrough_indices: set[int] = set()

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                passthrough_indices.add(param_idx)
        elif rf.origin_type == "global":
            if _is_source_var(rf.origin):
                graph.vs[func_vid]["taint_type"] = "source"
                return True
        elif rf.origin_type == "call":
            simple = _get_simple_name(rf.origin)
            if simple and _is_source_var(simple):
                graph.vs[func_vid]["taint_type"] = "source"
                return True

    if passthrough_indices:
        graph.vs[func_vid]["taint_type"] = "passthrough"
        graph.vs[func_vid]["taint_passthrough"] = sorted(passthrough_indices)
        _mark_passthrough_params(graph, func_vid, sorted(passthrough_indices))
        return True

    # 有摘要但无可透传来源
    graph.vs[func_vid]["taint_type"] = "safe"
    return True


# ---------------------------------------------------------------------------
# Internal: parameter 标记
# ---------------------------------------------------------------------------

def _mark_passthrough_params(graph: ig.Graph, func_vid: int, passthrough_indices: list[int]):
    """标记 function 下对应的 parameter 节点为 passthrough_arg。

    遍历 function → own → parameter，匹配 index。
    """
    idx_set = set(passthrough_indices)
    for e in graph.es.select(_source=func_vid, label="own"):
        target = graph.vs[e.target]
        if _vattr(target, "label") != NodeLabel.PARAMETER.value:
            continue
        pidx = _vattr(target, "index")
        if pidx is not None and int(pidx) in idx_set:
            graph.vs[e.target]["taint_type"] = "passthrough_arg"


# ---------------------------------------------------------------------------
# Internal: utilities
# ---------------------------------------------------------------------------

def _get_simple_name(name: str) -> str:
    """提取短名：'trim' / 'MyClass::method' → 'method'。"""
    if "::" in name:
        return name.split("::")[-1]
    if "\\" in name:
        return name.rsplit("\\", 1)[-1]
    return name


def _is_source_var(name: str) -> bool:
    """判断是否是 source variable。"""
    if not name:
        return False
    return name.lstrip("\\") in {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
        "$_FILES", "$_SESSION", "$_ENV",
    }
