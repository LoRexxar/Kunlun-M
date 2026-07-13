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
) -> int:
    """遍历图中所有 function 节点，查询知识库并标注 taint 属性。

    Args:
        graph: 已构建的 igraph AST 图
        language: 语言标识 ("php", "python", ...)
        trace_cache: TraceCache 实例（可选），提供 lookup_builtin(name) 方法
        source_registry: SourceRegistry 实例（可选）

    函数摘要已迁移到 core/graph/function_summary.py（图原生摘要），
    不再通过 summary_lookup 参数传入。

    Returns:
        标注的 function 节点数量
    """
    count = 0
    for v in graph.vs:
        vlabel = _vattr(v, "label", "")
        vtype = _vattr(v, "type", "")
        is_function_def = vlabel == NodeLabel.FUNCTION.value
        is_call_node = (vlabel == NodeLabel.OPERATOR.value
                        and vtype in ("call", "method_call", "static_call"))

        if not (is_function_def or is_call_node):
            continue

        func_vid = v.index
        func_name = _vattr(v, "name", "")
        fullname = _vattr(v, "fullname", "")
        if not func_name:
            continue

        # 对于 call/method_call 节点，提取短名和完整名
        # e.g. "Markdown.hashPart" (from normalizer fullname attr) → full_lookup="Markdown.hashPart"
        lookup_name = func_name
        full_lookup = func_name
        if is_call_node:
            # 优先使用 normalizer 设置的 fullname（ClassName.methodName）
            node_fullname = _vattr(v, "fullname", "")
            if node_fullname and "." in node_fullname:
                full_lookup = node_fullname
                lookup_name = node_fullname.rsplit(".", 1)[-1]
            else:
                dot_pos = func_name.rfind(".")
                lookup_name = func_name[dot_pos + 1:] if dot_pos >= 0 else func_name
        elif fullname and "." in fullname:
            # function_def 节点：使用 fullname 做完整名查找
            full_lookup = fullname
            lookup_name = fullname.rsplit(".", 1)[-1]

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

    # 3. Source variable 标注（PHP superglobals: $_GET, $_POST, $_COOKIE 等）
    #    这些是 identifier 节点而非 function/call，需要在 function/call 循环外处理
    source_var_count = _enrich_source_variables(graph)
    count += source_var_count

    # 4. 注解标注（Java @RequestParam/@PathVariable 等标记参数为 source）
    annotated_param_count = _enrich_annotated_params(graph)
    count += annotated_param_count

    # 5. 框架 request 参数标注（PHP $request, Python flask.request 等）
    #    当检测到框架时，函数参数中名为 $request / request 的参数标注为 source
    if source_registry is not None:
        fw_param_count = _enrich_framework_request_params(graph, source_registry)
        count += fw_param_count

    logger.debug("enrich_taint: annotated %d function nodes, %d source variables, %d annotated params",
                 count - source_var_count - annotated_param_count, source_var_count, annotated_param_count)
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
    #    PHP SourceRegistry 没有 is_source_member，用 hasattr 保护
    if hasattr(source_registry, 'is_source_member') and source_registry.is_source_member(func_name):
        graph.vs[func_vid]["taint_type"] = "source"
        return True

    return False


# LEGACY: _enrich_from_summary 已迁移到 core/graph/function_summary.py（图原生摘要）


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


def _enrich_source_variables(graph: ig.Graph) -> int:
    """标注图中的 source variable 节点（PHP superglobals、JS source roots 等）。

    这些变量是用户可控的 source，但在图中以 identifier 节点表示，
    不经过 function/call 路径，需要单独标注。
    """
    from core.graph.node_edge_schema import NodeLabel

    count = 0
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.IDENTIFIER.value:
            continue
        if _vattr(v, "taint_type"):  # 已标注，跳过
            continue
        name = _vattr(v, "name", "")
        if _is_source_var(name):
            graph.vs[v.index]["taint_type"] = "source"
            count += 1
    return count


def _enrich_annotated_params(graph: ig.Graph) -> int:
    """标注图中带有 source 注解的 parameter 节点。

    遍历 parameter → own → annotation 节点，检查注解是否为已知的 source 注解（如
    Java 的 @RequestParam, @PathVariable），如果是则将 parameter 标注为 taint_type=source。
    """
    from core.graph.node_edge_schema import NodeLabel

    # 各语言的 source 注解名集合
    SOURCE_ANNOTATIONS: dict[str, set[str]] = {
        'java': {
            'RequestParam', 'PathVariable', 'RequestBody', 'ModelAttribute',
            'RequestHeader', 'CookieValue', 'MatrixVariable', 'PathParam',
        },
        'kotlin': {
            'RequestParam', 'PathVariable', 'RequestBody', 'ModelAttribute',
            'RequestHeader', 'CookieValue', 'MatrixVariable', 'PathParam',
        },
    }
    # 合并为全局集合（目前只有 Java/Kotlin 使用注解检测）
    _all_annotations = set()
    for anns in SOURCE_ANNOTATIONS.values():
        _all_annotations.update(anns)

    count = 0
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.PARAMETER.value:
            continue
        if _vattr(v, "taint_type"):
            continue
        # 遍历 parameter → own → annotation 子节点
        for e in graph.es.select(_source=v.index, label="own"):
            target = graph.vs[e.target]
            if _vattr(target, "label") != NodeLabel.ANNOTATION.value:
                continue
            ann_name = _vattr(target, "name", "")
            ann_scope = _vattr(target, "scope", "")
            # 只处理参数级注解
            if ann_scope != "param-annotation":
                continue
            if ann_name in _all_annotations:
                graph.vs[v.index]["taint_type"] = "source"
                graph.vs[v.index]["taint_origin"] = f"@{ann_name}"
                count += 1
                break
    return count


def _enrich_framework_request_params(graph: ig.Graph, source_registry) -> int:
    """标注图中匹配框架 request 对象名称的 parameter 节点为 source。

    当 source_registry 中有框架的 request_object_names 配置时（如 Symfony 的
    {'request', '$request'}），函数参数名匹配该集合的 parameter 节点被标记为
    taint_type=source。适用于 PHP/Symfony、PHP/Laravel 等通过 DI 注入 request 的框架。
    """
    from core.graph.node_edge_schema import NodeLabel

    # 从 source_registry 收集所有框架的 request 对象名称
    request_names: set[str] = set()
    if hasattr(source_registry, 'framework_request_objects'):
        request_names.update(source_registry.framework_request_objects)

    if not request_names:
        return 0

    count = 0
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.PARAMETER.value:
            continue
        if _vattr(v, "taint_type"):
            continue
        name = _vattr(v, "name", "")
        if not name:
            continue
        # PHP 参数名含 $ 前缀（如 $request），也检查不含 $ 的版本
        clean = name.lstrip("$")
        if name in request_names or clean in request_names:
            graph.vs[v.index]["taint_type"] = "source"
            graph.vs[v.index]["taint_origin"] = "framework_request_param"
            count += 1
    return count

def _get_simple_name(name: str) -> str:
    """提取短名：'trim' / 'MyClass::method' → 'method'。"""
    if "::" in name:
        return name.split("::")[-1]
    if "\\" in name:
        return name.rsplit("\\", 1)[-1]
    return name


def _is_source_var(name: str) -> bool:
    """判断是否是 source variable。

    注意：$_SESSION 不在此列表中——session 数据是服务端持久化的状态，
    非用户直接可控输入。$_SERVER 仍保留，因为 graph_analyzer 的 member chain
    检查会按 key 过滤（_SERVER_UNCONTROLLED_KEYS），整体保留 source 标注
    可让 DFG/AST 的污点预传播覆盖 HTTP_* 等可控字段。
    """
    if not name:
        return False
    clean = name.lstrip("\\")
    # PHP superglobals ($_SESSION excluded — server-side session data)
    if clean in {
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
        "$_FILES", "$_ENV",
    }:
        return True
    # JS/TS source roots（通过 member chain 访问的根对象）
    if clean in {"location", "document", "window", "process"}:
        return True
    return False
