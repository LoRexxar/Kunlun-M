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
        vlabel = _vattr(v, "label", "")
        vtype = _vattr(v, "type", "")
        is_function_def = vlabel == NodeLabel.FUNCTION.value
        is_call_node = (vlabel == NodeLabel.OPERATOR.value
                        and vtype in ("call", "method_call"))

        if not (is_function_def or is_call_node):
            continue

        func_vid = v.index
        func_name = _vattr(v, "name", "")
        fullname = _vattr(v, "fullname", "")
        if not func_name:
            continue

        # 对于 call/method_call 节点，提取短名和完整名
        # e.g. "fmt.Sprintf" → lookup_name="Sprintf", full_lookup="fmt.Sprintf"
        # TraceCache knowledge 中 key 是完整名（如 "fmt.Sprintf"），需同时尝试
        lookup_name = func_name
        full_lookup = func_name
        if is_call_node:
            dot_pos = func_name.rfind(".")
            lookup_name = func_name[dot_pos + 1:] if dot_pos >= 0 else func_name

        # 1. SourceRegistry（框架 source producer + builtin source member）
        #    source 标注优先级最高 — 如果函数本身就是 source（接收外部数据），
        #    则直接标记为 source，不再查 builtin 知识库（避免 sink 函数被 builtin
        #    的 passthrough 语义错误覆盖）。
        #    传完整 func_name（如 "document.cookie"），内部用短名查 source producer，
        #    用完整 chain 查 source member。
        if source_registry is not None:
            if _enrich_from_source_registry(graph, func_vid, func_name, source_registry):
                count += 1
                continue

        # 2. TraceCache builtin（内置函数的返回值可控性知识库）
        #    仅在 source_registry 未匹配时使用。先短名查，再完整名查。
        if trace_cache is not None:
            if _enrich_from_builtin(graph, func_vid, lookup_name, full_lookup, trace_cache):
                count += 1
                continue

        # 3. 函数摘要（用户自定义函数的返回值数据流）
        if summary_lookup is not None:
            if _enrich_from_summary(graph, func_vid, lookup_name, summary_lookup):
                count += 1
                continue

    logger.debug("enrich_taint: annotated %d function nodes", count)
    return count


# ---------------------------------------------------------------------------
# Internal: enrichment helpers — 标注在 function + parameter 节点上
# ---------------------------------------------------------------------------

# receiver passthrough 的字符串标记 ("this"/"self")
_RECEIVER_PT_NAMES: frozenset[str] = frozenset({"this", "self"})


def _enrich_from_builtin(graph: ig.Graph, func_vid: int, short_name: str, full_name: str, trace_cache) -> bool:
    """从 TraceCache 内置知识库标注。先短名查，再完整名查。"""
    knowledge = trace_cache.lookup_builtin(short_name)
    if not knowledge and full_name != short_name:
        knowledge = trace_cache.lookup_builtin(full_name)
    if not knowledge:
        return False

    safe = knowledge.get("safe", False)
    passthrough: list = knowledge.get("passthrough", [])

    # 分离 receiver passthrough ("this"/"self") 和位置参数 passthrough (int 索引)
    receiver_pt = any(isinstance(x, str) and x in _RECEIVER_PT_NAMES for x in passthrough)
    param_indices = [i for i in passthrough if isinstance(i, int)]

    if safe and not passthrough:
        graph.vs[func_vid]["taint_type"] = "safe"
        return True

    if passthrough:
        graph.vs[func_vid]["taint_type"] = "passthrough"
        graph.vs[func_vid]["taint_passthrough"] = param_indices
        if receiver_pt:
            graph.vs[func_vid]["taint_receiver_pt"] = True
        if param_indices:
            _mark_passthrough_params(graph, func_vid, param_indices)
        return True

    # 有记录但 safe=False 且无 passthrough
    graph.vs[func_vid]["taint_type"] = "safe"
    return True


def _enrich_from_source_registry(
    graph: ig.Graph, func_vid: int, func_name: str, source_registry,
) -> bool:
    """从 SourceRegistry 标注框架 source producer 和 builtin source member。"""
    simple_name = _get_simple_name(func_name)

    # 1. source producer 函数（用户定义的返回可控数据的函数）
    info = source_registry.is_source_producer(simple_name)
    if info:
        graph.vs[func_vid]["taint_type"] = "source"
        return True

    # 2. builtin source member expression（JS/TS: document.cookie, location.hash, process.env 等）
    #    注意：这里用完整的 func_name（如 "document.cookie"），不是 short name（"cookie"）
    #    is_source_member 支持前缀匹配（如 process.env.USER_INPUT 匹配 process.env）
    if source_registry.is_source_member(func_name):
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
    # summary 一般只产出 int 索引，但为保险起见也检测 receiver 标记
    has_receiver_pt = False

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                if isinstance(param_idx, str) and param_idx in _RECEIVER_PT_NAMES:
                    has_receiver_pt = True
                elif isinstance(param_idx, int):
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

    if passthrough_indices or has_receiver_pt:
        graph.vs[func_vid]["taint_type"] = "passthrough"
        sorted_indices = sorted(passthrough_indices)
        graph.vs[func_vid]["taint_passthrough"] = sorted_indices
        if has_receiver_pt:
            graph.vs[func_vid]["taint_receiver_pt"] = True
        if sorted_indices:
            _mark_passthrough_params(graph, func_vid, sorted_indices)
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
    idx_set = set(i for i in passthrough_indices if isinstance(i, int))
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
    clean = name.lstrip("\\")
    # PHP superglobals
    if clean in {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
        "$_FILES", "$_SESSION", "$_ENV",
    }:
        return True
    # JS/TS source roots（通过 member chain 访问的根对象）
    if clean in {"location", "document", "window", "process"}:
        return True
    return False
