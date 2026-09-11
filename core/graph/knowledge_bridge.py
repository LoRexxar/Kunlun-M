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

        # Skip nodes belonging to other languages.
        # In multi-language graphs, each enrich_taint(language=X) call
        # must only annotate nodes for that language to prevent cross-language
        # taint pollution (e.g. PHP TraceCache marking Python's "get" as safe).
        node_lang = _vattr(v, "language", "")
        if node_lang and node_lang != language:
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
            if _enrich_from_source_registry(graph, func_vid, full_lookup, source_registry):
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

    # 3b. Mark superglobal use-site nodes as taint_type=safe when they were
    #     reassigned by a safe function (e.g. $_GET['x'] = strtr(...)).
    #     This directly annotates the graph so the analyzer doesn't need to
    #     re-derive overwritten status at each source check site.
    _record_sanitized_superglobal_members(graph)

    # 4. 注解标注（Java @RequestParam/@PathVariable 等标记参数为 source）
    annotated_param_count = _enrich_annotated_params(graph)
    count += annotated_param_count

    # 5. 框架 request 参数标注（PHP $request, Python flask.request 等）
    #    当检测到框架时，函数参数中名为 $request / request 的参数标注为 source
    if source_registry is not None:
        fw_param_count = _enrich_framework_request_params(graph, source_registry)
        count += fw_param_count

    # 6. 框架 safe 方法标注
    #    某些框架方法返回值经过安全转换（hash/枚举/常量），不应传播污点。
    #    例如 Symfony Request::getCacheKey() 返回 URL 的 MD5 hash。
    if source_registry is not None and hasattr(source_registry, 'framework') and source_registry.framework:
        config = getattr(source_registry, '_fw_config', None) or {}
        safe_methods = config.get('safe_return_methods', set())
        if safe_methods:
            safe_method_count = _enrich_framework_safe_methods(graph, safe_methods)
            count += safe_method_count

    # 6b. 内置 sanitizer call 节点标注
    #     _REPAIR_FUNCTIONS (htmlspecialchars, intval, shlex.quote, etc.)
    #     are built-in sanitizers. Mark their call nodes as taint_type=safe
    #     so that function_summary._trace_return_value can detect them.
    from core.graph.graph_analyzer import _REPAIR_FUNCTIONS
    repair_count = _enrich_repair_calls(graph, _REPAIR_FUNCTIONS)
    count += repair_count

    # 7. 传播 safe taint: 将 sanitizer call 的 safe 标记传播到赋值 LHS 变量
    safe_prop_count = _propagate_safe_taint(graph)
    count += safe_prop_count

    logger.debug("enrich_taint: annotated %d function nodes, %d source variables, %d annotated params",
                 count - source_var_count - annotated_param_count, source_var_count, annotated_param_count)
    return count


# ---------------------------------------------------------------------------
# Internal: enrichment helpers — 标注在 function + parameter 节点上
# ---------------------------------------------------------------------------

# receiver passthrough 的字符串标记 ("this"/"self")
_RECEIVER_PT_NAMES: frozenset[str] = frozenset({"this", "self"})

# 正则替换/匹配函数 — pattern 为固定常量且不含 dot wildcard 时标为 safe
_REGEX_SANITIZE_FUNCS: frozenset[str] = frozenset({
    "preg_replace", "preg_replace_callback", "preg_filter",
    "mb_ereg_replace", "ereg_replace", "eregi_replace",
})

# PHP 正则的括号类分隔符映射（开 → 闭）
_REGEX_BRACKET_DELIMS: dict[str, str] = {
    "(": ")", "[": "]", "{": "}", "<": ">",
}


def _extract_php_regex_pattern(name: str) -> str:
    """从 PHP 字符串常量名中提取正则内容。

    PHP 的 preg_* 函数使用 `/pattern/flags` 格式（也支持 `#`、`~`、`()`
    等其他分隔符）。name 由 normalizer 用 Python repr 写入，通常带外层
    引号（如 `'/foo/'`），先去引号再取分隔符内的内容。返回空串表示无法提取。
    """
    if not name:
        return ""
    s = name.strip()
    # 去掉外层 Python repr 引号
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        s = s[1:-1]
    if not s:
        return ""
    delimiter = s[0]
    # 括号类分隔符：从右找闭合字符
    if delimiter in _REGEX_BRACKET_DELIMS:
        close = _REGEX_BRACKET_DELIMS[delimiter]
        end = s.rfind(close)
        if end <= 0:
            return ""
        return s[1:end]
    # 普通分隔符（/、#、~、!、@ 等）：从右找下一个分隔符
    end = s.rfind(delimiter)
    if end <= 0:
        return ""
    return s[1:end]


def _regex_has_dot_wildcard(regex: str) -> bool:
    """检查正则字符串中是否有未转义的 `.`（dot wildcard）。

    - `\\.` 是转义的 `.`，不算 wildcard
    - `[...]` 字符类内的 `.` 不算 wildcard
    """
    in_char_class = False
    i = 0
    n = len(regex)
    while i < n:
        ch = regex[i]
        if ch == "\\":
            # 转义序列：跳过下一字符
            i += 2
            continue
        if ch == "[":
            in_char_class = True
        elif ch == "]":
            in_char_class = False
        elif ch == "." and not in_char_class:
            return True
        i += 1
    return False


def _is_regex_sanitize_safe(graph, func_vid: int) -> bool:
    """检查正则替换函数的 arg[0]（pattern）是否为常量字符串且不含 dot wildcard。

    遍历 func_vid 出发的 ast 边 + role=arg，按 arg_index 找到 arg[0]，
    判断其 label 是否为 constant，并检查其正则内容是否含未转义的 `.`。
    找不到 arg[0] 或不是常量时返回 False。
    """
    for e in graph.es.select(_source=func_vid, label="ast"):
        if _vattr(e, "role", "") != "arg":
            continue
        arg_idx = _vattr(e, "arg_index", -1)
        try:
            if int(arg_idx) != 0:
                continue
        except (TypeError, ValueError):
            continue
        target = graph.vs[e.target]
        if _vattr(target, "label", "") != NodeLabel.CONST.value:
            return False
        name = _vattr(target, "name", "")
        pattern = _extract_php_regex_pattern(name)
        if not pattern:
            return False
        return not _regex_has_dot_wildcard(pattern)
    return False


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

    if safe:
        graph.vs[func_vid]["taint_type"] = "safe"
        return True

    # 正则替换函数：pattern 为固定常量且不含 dot wildcard → safe
    if short_name in _REGEX_SANITIZE_FUNCS or full_name in _REGEX_SANITIZE_FUNCS:
        if _is_regex_sanitize_safe(graph, func_vid):
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
    #    传完整 func_name（如 tree.getParameter）而不是 simple_name，
    #    这样 Java is_source_producer 可以检查调用者前缀。
    info = source_registry.is_source_producer(func_name)
    if info:
        graph.vs[func_vid]["taint_type"] = "source"
        # Encode origin in existing attribute to avoid igraph dynamic attr issues.
        # Format: "source" for framework/builtin, "source:user" for user_defined.
        if info.type == "user_defined":
            graph.vs[func_vid]["taint_type"] = "source:user"
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
# Internal: sanitizer → LHS 传播
# ---------------------------------------------------------------------------

def _propagate_safe_taint(graph: ig.Graph) -> int:
    """将 sanitizer call 的 safe 标记传播到赋值 LHS 变量。

    当 ``$y = esc_attr($x)`` 时，``esc_attr`` call 节点已通过 ``_enrich_from_builtin``
    标记为 ``taint_type="safe"``，但 ``$y`` (LHS 标识符) 未被标记。
    ``parameters_back`` BFS 反向追踪时只看当前节点的 ``taint_type``，
    不会展开 RHS 子树，因此会把 ``$y`` 当作普通变量继续向上回溯到 source，
    产生误报。

    算法：
    1. 找出所有 assign operator 节点（label=operator, type=assign|aug_assign）
    2. 对每个 assign，取 LHS 标识符（ast[role=lhs]）和 RHS 子树根（ast[role=rhs]）
    3. 在 RHS AST 子树中 BFS 查找带 ``taint_type="safe"`` 的 call 节点
    4. 若找到，则将 LHS 标识符节点标记为 ``taint_type="safe"``
    5. 返回标记的节点数量
    """
    from core.graph.node_edge_schema import OperatorType, EdgeLabel

    count = 0
    assign_types = {OperatorType.ASSIGN.value, OperatorType.AUG_ASSIGN.value}

    for v in graph.vs:
        if _vattr(v, "label", "") != NodeLabel.OPERATOR.value:
            continue
        if _vattr(v, "type", "") not in assign_types:
            continue

        assign_vid = v.index

        # 取 LHS / RHS 节点（通过 ast 边的 role 区分）
        lhs_vids: list[int] = []
        rhs_vids: list[int] = []
        for e in graph.es.select(_source=assign_vid, label=EdgeLabel.AST.value):
            role = _vattr(e, "role", "")
            if role == "lhs":
                lhs_vids.append(e.target)
            elif role == "rhs":
                rhs_vids.append(e.target)

        if not lhs_vids or not rhs_vids:
            continue

        lhs_vid = lhs_vids[0]
        rhs_vid = rhs_vids[0]

        # 仅当 LHS 是标识符时才标记
        if _vattr(graph.vs[lhs_vid], "label", "") != NodeLabel.IDENTIFIER.value:
            continue

        # 已有 taint 标记（source/safe 等）则跳过，避免覆盖更高优先级的标注
        if _vattr(graph.vs[lhs_vid], "taint_type", ""):
            continue

        # 检查 RHS AST 子树中是否含 safe call 节点
        if _rhs_has_safe_call(graph, rhs_vid):
            graph.vs[lhs_vid]["taint_type"] = "safe"
            count += 1

    if count:
        logger.debug("_propagate_safe_taint: marked %d LHS variables as safe", count)
    return count


def _rhs_has_safe_call(graph: ig.Graph, root_vid: int) -> bool:
    """检查以 ``root_vid`` 为根的 AST 子树是否包含 ``taint_type="safe"`` 的 call 节点。

    仅遍历 AST 边，不跟随 DFG 边 — 我们只关心赋值右侧的即时语法结构，
    不展开数据流。
    """
    from core.graph.node_edge_schema import EdgeLabel

    queue = [root_vid]
    visited = {root_vid}

    while queue:
        vid = queue.pop(0)
        v = graph.vs[vid]

        # 命中 safe operator（包括 call/method_call/static_call）即返回
        if _vattr(v, "label", "") == NodeLabel.OPERATOR.value:
            if _vattr(v, "taint_type", "") == "safe":
                return True

        # BFS 进入 AST 子节点
        for e in graph.es.select(_source=vid, label=EdgeLabel.AST.value):
            child = e.target
            if child not in visited:
                visited.add(child)
                queue.append(child)

    return False


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


# PHP superglobals that can be subscript-assigned (e.g. $_GET['x'] = ...).
# $_SERVER is excluded: its keys are server-config values and reassigning
# one doesn't neutralize user-controlled HTTP_* fields in the same array.
_SUPERGLOBAL_SUBSCRIPT_PARENTS: frozenset[str] = frozenset({
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
})


def _find_enclosing_function(graph: ig.Graph, vid: int) -> int | None:
    """Walk ``own`` edges upward from *vid* to find an ancestor function node.

    Falls back to ``ast`` edges if no ``own`` parent exists (identifiers inside
    operator subtrees are often linked via ``ast`` rather than ``own``).
    Returns the function vertex id, or ``None`` if not found within 15 hops.
    """
    from core.graph.node_edge_schema import NodeLabel

    visited: set[int] = set()
    current = vid
    for _ in range(15):
        if current is None or current in visited:
            break
        visited.add(current)
        # Prefer 'own' edge, then 'ast' edge
        parent_vid: int | None = None
        for e in graph.es.select(_target=current, label="own"):
            parent_vid = e.source
            break
        if parent_vid is None:
            for e in graph.es.select(_target=current, label="ast"):
                # Skip condition/callee edges — they don't represent enclosure
                role = _vattr(e, "role", "")
                if role in ("condition", "callee"):
                    continue
                parent_vid = e.source
                break
        if parent_vid is None:
            break
        if _vattr(graph.vs[parent_vid], "label", "") == NodeLabel.FUNCTION.value:
            return parent_vid
        current = parent_vid
    return None


def _record_sanitized_superglobal_members(graph: ig.Graph) -> None:
    """Detect ``$_GET['key'] = expr`` assignments and mark use-site nodes safe.

    When a superglobal subscript is reassigned with a sanitized value inside a
    function, subsequent reads of the same subscript in that function reflect
    the sanitized value, not the original user input.  Instead of recording the
    assignment for the analyzer to re-check at every source site (the old
    approach), this function **directly rewrites** ``taint_type`` from
    ``source`` to ``safe`` on the relevant superglobal and member nodes that
    appear *after* the assignment in the same file + function scope.

    The analyzer then simply checks ``taint_type == "safe"`` before treating a
    superglobal node as a source — no overwritten bookkeeping required.
    """
    from core.graph.node_edge_schema import NodeLabel, EdgeLabel, OperatorType

    assign_types = {OperatorType.ASSIGN.value, OperatorType.AUG_ASSIGN.value}
    marked = 0

    for v in graph.vs:
        if _vattr(v, "label", "") != NodeLabel.OPERATOR.value:
            continue
        if _vattr(v, "type", "") not in assign_types:
            continue

        assign_vid = v.index

        # Find LHS child via ast[role=lhs]
        lhs_vid: int | None = None
        for e in graph.es.select(_source=assign_vid, label=EdgeLabel.AST.value):
            if _vattr(e, "role", "") == "lhs":
                lhs_vid = e.target
                break
        if lhs_vid is None:
            continue

        # LHS must be a property/identifier (subscript member)
        lhs_label = _vattr(graph.vs[lhs_vid], "label", "")
        if lhs_label != NodeLabel.IDENTIFIER.value:
            continue

        # Check if LHS has a MEMBER edge from a superglobal parent
        superglobal_name = ""
        for me in graph.es.select(_target=lhs_vid, label="member"):
            parent_name = _vattr(graph.vs[me.source], "name", "")
            if parent_name in _SUPERGLOBAL_SUBSCRIPT_PARENTS:
                superglobal_name = parent_name
                break
        if not superglobal_name:
            continue

        member_key = _vattr(graph.vs[lhs_vid], "name", "")
        if not member_key:
            continue

        # Skip variable-key assignments (e.g. $_POST[$key] = normalize(...)).
        # These don't sanitize a SPECIFIC member, and marking them would
        # incorrectly suppress all downstream superglobal uses.
        # Literal string keys contain quotes; variable keys start with $.
        stripped_key = member_key.strip("'\"")
        if stripped_key.startswith("$"):
            continue

        # --- RHS safe-callee check (recursive) ---
        # Only mark use sites if the RHS contains a safe/sanitizer
        # function call somewhere in its AST subtree. This catches both
        # direct sanitizers (e.g. $_GET['x'] = strtr(...)) and nested
        # sanitizers (e.g. $_GET['x'] = preg_replace(..., strtr(...))).
        # If the RHS contains NO safe callee at all, the reassignment
        # does NOT neutralize the taint and the nodes stay source.
        rhs_vid: int | None = None
        for e in graph.es.select(_source=assign_vid, label=EdgeLabel.AST.value):
            if _vattr(e, "role", "") == "rhs":
                rhs_vid = e.target
                break
        if rhs_vid is None:
            continue  # no RHS — skip

        # Recursively scan RHS AST subtree for safe callees
        def _rhs_has_safe_callee(vid: int, depth: int = 0,
                                  visited: set | None = None) -> bool:
            if visited is None:
                visited = set()
            if vid in visited or depth > 12:
                return False
            visited.add(vid)
            node = graph.vs[vid]
            callee = _vattr(node, "callee", "") or _vattr(node, "name", "")
            if callee:
                # Check builtin_knowledge safe=True
                try:
                    from core.core_engine.php.builtin_knowledge import KNOWLEDGE as _PHP_BK
                    entry = _PHP_BK.get(callee)
                    if isinstance(entry, dict) and entry.get("safe"):
                        return True
                except Exception:
                    pass
                # Check taint_type=safe from enrich_taint
                for ue in graph.es.select(_source=vid, label="use"):
                    fv = graph.vs[ue.target]
                    if _vattr(fv, "label", "") == NodeLabel.FUNCTION.value:
                        if _vattr(fv, "taint_type", "") == "safe":
                            return True
                        break
            # Recurse into AST children
            for e in graph.es.select(_source=vid, label=EdgeLabel.AST.value):
                if _rhs_has_safe_callee(e.target, depth + 1, visited):
                    return True
            return False

        if not _rhs_has_safe_callee(rhs_vid):
            continue  # No safe callee in RHS — leave nodes as source

        file_path = _vattr(graph.vs[assign_vid], "file_path", "")
        lineno = _vattr(graph.vs[assign_vid], "lineno", 0) or 0
        func_vid = _find_enclosing_function(graph, assign_vid)

        # --- Mark downstream superglobal + member nodes as safe ---
        # Find all superglobal nodes of the same name in the SAME FILE and
        # SAME FUNCTION with lineno GREATER than the assignment lineno, and
        # set their taint_type from "source" to "safe".
        for cand in graph.vs:
            if _vattr(cand, "name", "") != superglobal_name:
                continue
            if _vattr(cand, "label", "") != NodeLabel.IDENTIFIER.value:
                continue
            if _vattr(cand, "file_path", "") != file_path:
                continue
            cand_lineno = _vattr(cand, "lineno", 0) or 0
            if cand_lineno <= lineno:
                continue
            # Same function scope (if determinable on both sides)
            cand_func = _find_enclosing_function(graph, cand.index)
            if func_vid is not None and cand_func is not None and cand_func != func_vid:
                continue
            if _vattr(cand, "taint_type", "") == "source":
                graph.vs[cand.index]["taint_type"] = "safe"
                marked += 1

        # Also mark corresponding member/property nodes (e.g. 'package') that
        # have a member edge FROM one of these sanitized superglobal nodes and
        # appear after the assignment line.
        for cand in graph.vs:
            if _vattr(cand, "label", "") != NodeLabel.IDENTIFIER.value:
                continue
            if _vattr(cand, "name", "").strip("'\"") != member_key.strip("'\""):
                continue
            if _vattr(cand, "file_path", "") != file_path:
                continue
            cand_lineno = _vattr(cand, "lineno", 0) or 0
            if cand_lineno <= lineno:
                continue
            # Must have a member edge from a node named superglobal_name
            has_sg_parent = False
            for me in graph.es.select(_target=cand.index, label="member"):
                if _vattr(graph.vs[me.source], "name", "") == superglobal_name:
                    has_sg_parent = True
                    break
            if not has_sg_parent:
                continue
            # Same function scope (if determinable on both sides)
            cand_func = _find_enclosing_function(graph, cand.index)
            if func_vid is not None and cand_func is not None and cand_func != func_vid:
                continue
            if _vattr(cand, "taint_type", "") == "source":
                graph.vs[cand.index]["taint_type"] = "safe"
                marked += 1

    if marked:
        logger.debug(
            "_record_sanitized_superglobal_members: marked %d nodes taint_type=safe",
            marked,
        )


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


def _enrich_framework_safe_methods(graph: ig.Graph, safe_methods: set[str]) -> int:
    """标注框架 safe 方法的 call 节点为 taint_type=safe。

    这些方法的返回值经过安全转换（hash/枚举/常量），不应传播污点。
    """
    count = 0
    for v in graph.vs:
        vlabel = _vattr(v, "label", "")
        vtype = _vattr(v, "type", "")
        if vlabel != NodeLabel.OPERATOR.value or vtype not in ("method_call", "static_call"):
            continue
        if _vattr(v, "taint_type"):
            continue
        name = _vattr(v, "name", "")
        if name in safe_methods:
            graph.vs[v.index]["taint_type"] = "safe"
            count += 1
    return count


def _enrich_repair_calls(graph: ig.Graph, repair_funcs: frozenset[str]) -> int:
    """标注内置 sanitizer 的 call 节点为 taint_type=safe。

    _REPAIR_FUNCTIONS 中的函数（htmlspecialchars, intval, shlex.quote 等）
    是内置 sanitizer。标记它们的 call 节点为 safe，使 function_summary
    能正确识别包含 sanitizer 的 return path 为 safe。
    """
    from core.graph.node_edge_schema import NodeLabel as _NL
    from core.graph.graph_analyzer import _CALL_TYPES
    count = 0
    for v in graph.vs:
        vlabel = _vattr(v, "label", "")
        vtype = _vattr(v, "type", "")
        if vlabel != _NL.OPERATOR.value:
            continue
        if vtype not in _CALL_TYPES:
            continue
        if _vattr(v, "taint_type"):
            continue
        callee = _vattr(v, "callee", "")
        name = _vattr(v, "name", "")
        # Match by callee name (short name like "htmlspecialchars")
        # or full name (like "html.escape", "shlex.quote")
        short = callee or (name.split(".")[-1] if "." in name else name)
        if short in repair_funcs or name in repair_funcs:
            graph.vs[v.index]["taint_type"] = "safe"
            count += 1
    return count

def _enrich_framework_request_params(graph: ig.Graph, source_registry) -> int:
    """标注图中匹配框架 request 对象名称的 parameter 节点为 source。

    当 source_registry 中有框架的 request_object_names 配置时（如 Symfony 的
    {'request', '$request'}），函数参数名匹配该集合的 parameter 节点被标记为
    taint_type=source。适用于 PHP/Symfony、PHP/Laravel 等通过 DI 注入 request 的框架。

    要求参数同时满足以下至少一个条件，避免参数名碰巧叫 request 的误标：
    - 参数名在 request_object_names 中
    - 参数的 type_hint 包含 'Request'（如 Request, RequestInterface）
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
        name_match = name in request_names or clean in request_names
        if not name_match:
            continue
        # Verify the parameter is actually an HTTP Request object:
        # check type_hint for 'Request' substring (e.g. Request,
        # RequestInterface, ServerRequestInterface, HttpFoundation\Request).
        type_hint = _vattr(v, "type_hint", "")
        if "Request" not in type_hint:
            continue
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
    # "process" removed: only process.env is a source (via SourceRegistry)
    if clean in {"location", "document", "window"}:
        return True
    return False
