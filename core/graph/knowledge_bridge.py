"""Knowledge bridge — 图构建阶段的 taint enrichment。

在 DFG 边生成之后、图分析之前，遍历所有 call operator 节点，
查询知识库（TraceCache / SourceRegistry / 函数摘要），
将污染传播行为直接标注为节点属性：

    - operator 节点: taint_type = "source" | "safe" | "passthrough"
    - arg 节点 (passthrough): taint_type = "passthrough_arg"

标注完成后，GraphAnalyzer 只需读取节点属性即可判定可控性，
无需运行时查询知识库，图完全自包含。

核心原则：
- 不遍历 AST，只读图的属性和边
- 知识库是只读查询对象，由外部传入
- 标注结果随图持久化（GraphML / JSON）
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.graph.node_edge_schema import NodeLabel, OperatorType
from utils.igraph_compat import _vattr

if TYPE_CHECKING:
    import igraph as ig

__all__ = ["enrich_taint"]

logger = logging.getLogger(__name__)

_CALL_TYPES = {
    OperatorType.CALL.value,
    OperatorType.STATIC_CALL.value,
    OperatorType.METHOD_CALL.value,
}


def enrich_taint(
    graph: ig.Graph,
    language: str,
    trace_cache=None,
    source_registry=None,
    summary_lookup=None,
) -> int:
    """遍历图中所有 call operator，查询知识库并标注 taint 属性。

    Args:
        graph: 已构建的 igraph AST 图
        language: 语言标识 ("php", "python", ...)
        trace_cache: TraceCache 实例（可选）
        source_registry: SourceRegistry 实例（可选）
        summary_lookup: 可调用对象 summary_lookup(name) → FunctionSummary | None

    Returns:
        标注的节点数量
    """
    count = 0
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.OPERATOR.value:
            continue
        if _vattr(v, "type") not in _CALL_TYPES:
            continue

        op_vid = v.index
        callee = _vattr(v, "name", "")
        if not callee:
            continue

        # 1. TraceCache builtin
        if trace_cache is not None:
            if _enrich_from_builtin(graph, op_vid, callee, trace_cache):
                count += 1
                continue

        # 2. SourceRegistry
        if source_registry is not None:
            if _enrich_from_source_registry(graph, op_vid, callee, source_registry):
                count += 1
                continue

        # 3. 函数摘要
        if summary_lookup is not None:
            if _enrich_from_summary(graph, op_vid, callee, summary_lookup):
                count += 1
                continue

    logger.debug("enrich_taint: annotated %d call operators", count)
    return count


# ---------------------------------------------------------------------------
# Internal: enrichment helpers
# ---------------------------------------------------------------------------

def _enrich_from_builtin(graph: ig.Graph, op_vid: int, func_name: str, trace_cache) -> bool:
    """从 TraceCache 内置知识库标注。"""
    knowledge = trace_cache.lookup_builtin(func_name)
    if not knowledge:
        return False

    safe = knowledge.get("safe", False)
    passthrough: list[int] = knowledge.get("passthrough", [])

    if safe and not passthrough:
        graph.vs[op_vid]["taint_type"] = "safe"
        return True

    if passthrough:
        graph.vs[op_vid]["taint_type"] = "passthrough"
        _mark_passthrough_args(graph, op_vid, passthrough)
        return True

    # 有记录但 safe=False 且无 passthrough
    graph.vs[op_vid]["taint_type"] = "safe"
    return True


def _enrich_from_source_registry(
    graph: ig.Graph, op_vid: int, func_name: str, source_registry,
) -> bool:
    """从 SourceRegistry 标注框架方法 source。"""
    raw_type = _vattr(graph.vs[op_vid], "raw_type", "")

    # 框架方法调用: $request->input()
    if raw_type in ("MethodCall", "NullsafeMethodCall"):
        obj_name = _get_method_object_name(graph, op_vid)
        simple_name = _get_simple_name(func_name)
        if obj_name and simple_name:
            obj_clean = obj_name.lstrip("$")
            if source_registry.is_framework_request_method(obj_clean, simple_name):
                graph.vs[op_vid]["taint_type"] = "source"
                return True

    # source producer 函数
    simple_name = _get_simple_name(func_name)
    info = source_registry.is_source_producer(simple_name)
    if info:
        graph.vs[op_vid]["taint_type"] = "source"
        return True

    return False


def _enrich_from_summary(
    graph: ig.Graph, op_vid: int, func_name: str, summary_lookup,
) -> bool:
    """从函数摘要标注。"""
    summary = summary_lookup(func_name)
    if not summary or not summary.return_flow:
        return False

    arg_names = _get_arg_names(graph, op_vid)
    passthrough_indices: set[int] = set()

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                if param_idx < len(arg_names) and arg_names[param_idx]:
                    passthrough_indices.add(param_idx)
        elif rf.origin_type == "global":
            if _is_source_var(rf.origin, source_registry=None):
                graph.vs[op_vid]["taint_type"] = "source"
                return True
        elif rf.origin_type == "call":
            simple = _get_simple_name(rf.origin)
            if simple and _is_source_var(simple, source_registry=None):
                graph.vs[op_vid]["taint_type"] = "source"
                return True

    if passthrough_indices:
        graph.vs[op_vid]["taint_type"] = "passthrough"
        _mark_passthrough_args(graph, op_vid, sorted(passthrough_indices))
        return True

    # 有摘要但无可透传来源
    graph.vs[op_vid]["taint_type"] = "safe"
    return True


# ---------------------------------------------------------------------------
# Internal: graph traversal helpers
# ---------------------------------------------------------------------------

def _mark_passthrough_args(graph: ig.Graph, op_vid: int, passthrough_indices: list[int]):
    """标记 passthrough 对应的 arg 节点。"""
    idx_set = set(passthrough_indices)
    arg_counter = 0
    for e in graph.es.select(_source=op_vid, label="ast"):
        if _vattr(e, "role") != "arg":
            continue
        idx = _vattr(e, "index")
        actual_idx = int(idx) if idx is not None else arg_counter
        if actual_idx in idx_set:
            graph.vs[e.target]["taint_type"] = "passthrough_arg"
        arg_counter += 1


def _get_arg_names(graph: ig.Graph, op_vid: int) -> list[str]:
    """获取 call operator 的实参名列表。"""
    names: list[str] = []
    arg_edges: list[tuple[int, int]] = []
    for e in graph.es.select(_source=op_vid, label="ast"):
        if _vattr(e, "role") == "arg":
            idx = _vattr(e, "index")
            idx_val = int(idx) if idx is not None else len(arg_edges)
            arg_edges.append((idx_val, e.target))
    arg_edges.sort(key=lambda x: x[0])
    for _, target_vid in arg_edges:
        tlabel = _vattr(graph.vs[target_vid], "label", "")
        if tlabel == NodeLabel.IDENTIFIER.value:
            names.append(_vattr(graph.vs[target_vid], "name", ""))
        else:
            names.append("")
    return names


def _get_method_object_name(graph: ig.Graph, op_vid: int) -> str | None:
    """从图中获取 MethodCall 的对象名。"""
    raw_type = _vattr(graph.vs[op_vid], "raw_type", "")
    if raw_type not in ("MethodCall", "NullsafeMethodCall"):
        return None
    for me in graph.es.select(_label="member"):
        obj_vid = me.source
        callee_vid = me.target
        callee_name = _vattr(graph.vs[callee_vid], "name", "")
        op_name = _vattr(graph.vs[op_vid], "name", "")
        if callee_name == op_name:
            obj_name = _vattr(graph.vs[obj_vid], "name", "")
            if obj_name.startswith("$"):
                return obj_name
    return None


def _get_simple_name(name: str) -> str:
    """提取短名。"""
    if "::" in name:
        return name.split("::")[-1]
    if "\\" in name:
        return name.rsplit("\\", 1)[-1]
    return name


def _is_source_var(name: str, source_registry=None) -> bool:
    """判断是否是 source variable。"""
    if not name:
        return False
    return name.lstrip("\\") in {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
        "$_FILES", "$_SESSION", "$_ENV",
    }
