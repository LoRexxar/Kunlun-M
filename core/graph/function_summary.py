"""Graph-based function summary — 图引擎上的函数摘要生成器。

替代旧引擎的 14 语言 summary_generator.py，直接在已构建的 AST 图上工作。
从 function 的 return 节点沿 DFG 反向 BFS 到 parameter，
生成摘要并直接标注为图节点属性。

摘要结果写入 function 节点：
    func_summary_type: "passthrough" | "source" | "safe" | "literal" | "unknown"
    func_summary_pt: [0, 2, ...]  — 返回值依赖的形参索引

同步到 taint 属性（供 graph_analyzer Rule 4c 消费）：
    taint_type = func_summary_type
    taint_passthrough = func_summary_pt

算法：
    1. 遍历所有 function 节点
    2. 找 return → ast[value] → 返回值表达式
    3. 从返回值沿 DFG 反向 BFS（约束在 own 子树内）
    4. 碰到 parameter → 记录 own 边 index
    5. 碰到 taint_type=source/safe/passthrough → 标记
    6. 碰到 call → use → function → 递归查目标摘要
    7. 汇总 return flows → 确定 summary_type
    8. 两遍迭代处理解决递归调用依赖
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import igraph as ig

__all__ = ["build_function_summaries"]

logger = logging.getLogger(__name__)

# BFS 递归深度上限
_MAX_TRACE_DEPTH = 15

# 迭代轮数上限（解决 A→B→A 递归调用）
_MAX_ITERATIONS = 5

# call operator 类型集合
_CALL_TYPES = frozenset({"call", "method_call", "static_call"})


def _collect_ast_descendants(graph: ig.Graph, start_vid: int, result: set[int],
                               return_vids: list[int] | None = None):
    """递归收集 start_vid 通过 ast/own 边可达的所有后代节点（BFS）。

    同时追踪 ast 边和 own 边（own 边仅在 branch/control 节点下展开）。
    因为 PHP 等语言的 if/else body 通过 branch → own → return 连接，
    而非 ast 边。限制 own 边展开避免跨越到其他 function 节点。

    Args:
        return_vids: 如果提供，在展开过程中收集到的 return 节点也会追加到此列表。
    """
    from collections import deque
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    # 允许展开 own 子节点的节点类型（branch/control 结构）
    _OWN_EXPAND_LABELS = {NodeLabel.BRANCH.value, "control"}

    queue = deque([start_vid])
    result.add(start_vid)
    if return_vids is not None and _vattr(graph.vs[start_vid], "label", "") == NodeLabel.RETURN.value:
        return_vids.append(start_vid)
    while queue:
        vid = queue.popleft()
        src_label = _vattr(graph.vs[vid], "label", "")
        for e in graph.es.select(_source=vid):
            el = _vattr(e, "label")
            if el == "ast":
                if e.target not in result:
                    result.add(e.target)
                    queue.append(e.target)
            elif el == "own" and src_label in _OWN_EXPAND_LABELS:
                # branch/control 节点的 own 子节点也展开
                if e.target not in result:
                    result.add(e.target)
                    queue.append(e.target)
                    if return_vids is not None and _vattr(graph.vs[e.target], "label", "") == NodeLabel.RETURN.value:
                        return_vids.append(e.target)


def build_function_summaries(
    graph: ig.Graph,
    languages: list[str] | None = None,
) -> dict[str, int]:
    """在图上构建函数摘要，标注 function 节点属性。

    Args:
        graph: 已构建 DFG 边的 igraph AST 图
        languages: 语言过滤列表（可选），None 表示全部

    Returns:
        统计信息 dict: {"annotated": N, "passthrough": N, "source": N, "safe": N, "literal": N, "unknown": N}
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    lang_set: set[str] | None = set(languages) if languages else None

    stats = {"annotated": 0, "passthrough": 0, "source": 0, "safe": 0, "literal": 0, "unknown": 0}

    # ── 收集所有 function 节点及其结构 ──
    func_data: dict[int, dict] = {}  # func_vid → {own_vids, param_idx, return_vids, lang}
    for v in graph.vs:
        if _vattr(v, "label") != NodeLabel.FUNCTION.value:
            continue
        if lang_set is not None and _vattr(v, "language", "") not in lang_set:
            continue
        vid = v.index
        own_vids: set[int] = set()
        param_idx: dict[int, int] = {}  # param_vid → param index
        return_vids: list[int] = []
        for e in graph.es.select(_source=vid, label="own"):
            child_vid = e.target
            child_label = _vattr(graph.vs[child_vid], "label", "")
            if child_label == NodeLabel.PARAMETER.value:
                idx = _vattr(e, "index")
                if idx is not None and idx != "":
                    param_idx[child_vid] = int(idx)
                # parameter 不展开 ast 子树（无意义）
                own_vids.add(child_vid)
            elif child_label == NodeLabel.RETURN.value:
                return_vids.append(child_vid)
                own_vids.add(child_vid)
            else:
                # 其他 own 子节点：递归展开 ast 子树（同时收集嵌套 return）
                _collect_ast_descendants(graph, child_vid, own_vids, return_vids)
        func_data[vid] = {
            "own_vids": own_vids,
            "param_idx": param_idx,
            "return_vids": return_vids,
        }

    if not func_data:
        return stats

    # ── 迭代处理（解决递归调用依赖） ──
    processed: set[int] = set()

    for iteration in range(_MAX_ITERATIONS):
        new_this_round = 0
        for vid, fd in func_data.items():
            if vid in processed:
                continue
            if not fd["return_vids"]:
                # 无 return 的函数（void/无显式返回）— 不需要摘要
                processed.add(vid)
                continue

            return_flows = _collect_return_flows(
                graph, fd["return_vids"], fd["own_vids"], fd["param_idx"]
            )
            if not return_flows:
                processed.add(vid)
                continue

            # 汇总
            summary_type, dep_params = _aggregate_flows(return_flows)

            # 如果有未解析的 call（目标函数尚未有摘要），且不是最后一轮，延迟处理
            has_unresolved = any(
                f.get("origin_type") == "unknown" and f.get("has_unresolved_call")
                for f in return_flows
            )
            if has_unresolved and summary_type == "unknown" and iteration < _MAX_ITERATIONS - 1:
                continue

            # ── 写入摘要属性 ──
            graph.vs[vid]["func_summary_type"] = summary_type
            if dep_params:
                graph.vs[vid]["func_summary_pt"] = sorted(dep_params)

            # 同步到 taint 属性（仅当 enrich_taint 未标注时）
            existing_taint = _vattr(graph.vs[vid], "taint_type", "")
            if not existing_taint and summary_type in ("passthrough", "source", "safe"):
                graph.vs[vid]["taint_type"] = summary_type
                if summary_type == "passthrough" and dep_params:
                    sorted_deps = sorted(dep_params)
                    graph.vs[vid]["taint_passthrough"] = sorted_deps
                    _mark_passthrough_params(graph, vid, sorted_deps)

            processed.add(vid)
            new_this_round += 1
            stats[summary_type] = stats.get(summary_type, 0) + 1

        stats["annotated"] += new_this_round
        if new_this_round == 0:
            break  # 无进展，停止迭代

    # 将剩余未处理的标记为 processed（避免后续重复计算）
    for vid in func_data:
        if vid not in processed:
            processed.add(vid)

    logger.debug(
        "build_function_summaries: processed %d/%d functions, stats=%s",
        len(processed), len(func_data), stats,
    )
    return stats


# ---------------------------------------------------------------------------
# Internal: return flow 收集与聚合
# ---------------------------------------------------------------------------


def _collect_return_flows(
    graph: ig.Graph,
    return_vids: list[int],
    own_vids: set[int],
    param_idx: dict[int, int],
) -> list[dict]:
    """从所有 return 节点收集 return flows。"""
    from utils.igraph_compat import _vattr

    flows = []
    for ret_vid in return_vids:
        for ae in graph.es.select(_source=ret_vid, label="ast"):
            if _vattr(ae, "role") == "value":
                flow = _trace_return_value(graph, ae.target, own_vids, param_idx, visited=set())
                if flow:
                    flows.append(flow)
    return flows


def _aggregate_flows(flows: list[dict]) -> tuple[str, set[int]]:
    """汇总 return flows，返回 (summary_type, dep_params_set)。

    规则：
    - 有任何 source → "source"
    - 有 dep_params → "passthrough"
    - 全部 literal/safe → "safe"
    - 否则 → "unknown"
    """
    has_source = False
    all_dep_params: set[int] = set()
    all_safe_or_literal = True

    for flow in flows:
        ot = flow.get("origin_type", "")
        if ot == "source":
            has_source = True
            all_safe_or_literal = False
        elif ot == "param":
            all_dep_params.update(flow.get("dep_params", []))
            all_safe_or_literal = False
        elif ot == "literal":
            pass  # safe_or_literal stays True
        elif ot == "safe":
            pass  # safe_or_literal stays True
        else:  # unknown
            all_safe_or_literal = False

    if has_source:
        return "source", all_dep_params
    if all_dep_params:
        return "passthrough", all_dep_params
    if flows and all_safe_or_literal:
        return "safe", all_dep_params
    return "unknown", all_dep_params


# ---------------------------------------------------------------------------
# Internal: DFG 反向追踪
# ---------------------------------------------------------------------------


def _trace_return_value(
    graph: ig.Graph,
    start_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    depth: int = 0,
) -> dict:
    """从返回值表达式 vid 沿 DFG 反向追踪到参数/字面量/source。

    Returns dict: {origin, origin_type, dep_params, has_unresolved_call}
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    if start_vid in visited or depth > _MAX_TRACE_DEPTH:
        return {"origin": "", "origin_type": "unknown", "dep_params": [], "has_unresolved_call": True}
    visited = visited | {start_vid}

    v = graph.vs[start_vid]
    vlabel = _vattr(v, "label", "")
    vtype = _vattr(v, "type", "")
    vname = _vattr(v, "name", "")

    # ── 1. 直接命中 parameter ──
    if start_vid in param_idx:
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": [param_idx[start_vid]],
            "has_unresolved_call": False,
        }

    # ── 2. 字面量 ──
    if vlabel == NodeLabel.CONST.value:
        return {"origin": vname, "origin_type": "literal", "dep_params": [], "has_unresolved_call": False}

    # ── 2.5. 节点自身已有 taint_type 注解（由 enrich_taint 或 _enrich_source_variables 标注） ──
    #     适用于 identifier/function/statement 等非 operator 节点。
    #     例如: return \$_GET (identifier 被标注为 source)
    #     operator 节点在 step 3 中单独处理（因为 call 还需要追踪 use→function）。
    self_taint = _vattr(v, "taint_type", "")
    if self_taint == "source":
        return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
    if self_taint == "safe":
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
    if self_taint == "passthrough":
        pt = _vattr(v, "taint_passthrough", [])
        if pt:
            return _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, depth)

    # ── 2.6. $this / self（链式调用返回自身实例） ──
    #     PHP/Java 中 `return $this` / `return self` 是链式调用模式，
    #     返回的是当前对象实例，不是外部输入，视为 safe。
    if vlabel == NodeLabel.IDENTIFIER.value:
        iname = _vattr(v, "name", "")
        if isinstance(iname, str) and iname in ("$this", "self"):
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        # phply 格式: Variable('$this')
        if isinstance(iname, str) and ("$this" in iname or iname.strip("'\"") == "$this"):
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 2.7. 静态属性/常量（identifier type='static'） ──
    #     self::$instance（name 含 Variable，可能从外部赋值）不安全；
    #     ORM::LIMIT_STYLE_TOP_N（name 不含 Variable，静态常量）safe。
    if vlabel == NodeLabel.IDENTIFIER.value and vtype == "static" and "Variable(" not in vname:
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 3. Operator（call, method_call, static_call 等） ──
    if vlabel == NodeLabel.OPERATOR.value:
        # 3a. 已有 taint_type 注解（builtin 函数，由 enrich_taint 标注）
        taint = _vattr(v, "taint_type", "")
        if taint == "source":
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if taint == "safe":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        if taint == "passthrough":
            pt = _vattr(v, "taint_passthrough", [])
            return _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, depth)

        # 3b. call operator → 尝试 use → function（用户自定义函数的摘要）
        if vtype in _CALL_TYPES:
            result = _trace_call_to_function(graph, start_vid, own_vids, param_idx, visited, depth)
            if result:
                return result

        # 3c. 内置安全构造函数——不传播外部污点
        #     array() 是 PHP 数组字面量构造，返回值仅由参数决定，
        #     但其参数（如果有的话）已经通过 arg DFG 被单独追踪。
        #     call 本身视为 safe 容器。
        callee = _vattr(v, "callee", "")
        if callee == "array":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 3.5. Branch/Ternary 追踪 ──
    #    return $x ? $a : $b — 追踪 iftrue 和 iffalse 两个分支，
    #    聚合结果（condition 不影响污点传播）。
    if vlabel == NodeLabel.BRANCH.value:
        branch_flows = []
        for be in graph.es.select(_source=start_vid, label="ast"):
            role = _vattr(be, "role", "")
            if role in ("iftrue", "iffalse"):
                sub = _trace_return_value(graph, be.target, own_vids, param_idx, visited, depth + 1)
                branch_flows.append(sub)
        if branch_flows:
            # 用 _aggregate_flows 聚合所有分支
            agg_type, agg_params = _aggregate_flows(branch_flows)
            if agg_type in ("source", "param"):
                return {"origin": vname, "origin_type": agg_type,
                        "dep_params": list(agg_params), "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}
            if agg_type == "safe":
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if agg_params:
                return {"origin": vname, "origin_type": "param",
                        "dep_params": list(agg_params), "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}
            # 所有分支都 unknown
            return {"origin": vname, "origin_type": "unknown", "dep_params": [],
                    "has_unresolved_call": any(f.get("has_unresolved_call") for f in branch_flows)}

    # ── 4. 通用 DFG 反向追踪 ──
    all_dep_params: list[int] = []
    has_source = False
    has_safe = False
    any_unresolved = False
    dfg_has_safe_source = False  # DFG 链中是否存在 safe/literal 源

    for de in graph.es.select(_target=start_vid, label="dfg"):
        src_vid = de.source

        # 4a. 检查 DFG 源节点自身是否是 source/safe（如 $_COOKIE、$_GET 等
        #     不在函数 own 子树内的全局变量，由 enrich_taint 标注）
        src_taint = _vattr(graph.vs[src_vid], "taint_type", "")
        if src_taint == "source":
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if src_taint == "safe":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

        # 4b. 约束在函数 own 子树内，递归追踪
        if src_vid not in own_vids:
            continue
        sub = _trace_return_value(graph, src_vid, own_vids, param_idx, visited, depth + 1)
        if sub["origin_type"] == "source":
            return sub  # source 立即返回
        if sub["origin_type"] == "safe":
            return sub  # safe 立即返回（阻断）
        if sub["origin_type"] == "literal":
            dfg_has_safe_source = True
            continue  # 字面量不传播污点，忽略此 DFG 源
        all_dep_params.extend(sub.get("dep_params", []))
        if sub.get("has_unresolved_call"):
            any_unresolved = True

    # ── 5. Member 边检查（$obj[$key] / obj.prop 等成员访问） ──
    #    identifier 通过 member 边连接到容器对象，如果容器是 source，
    #    则 member access 的结果也是 source。
    #    e.g. $_COOKIE['theme'] → member ← $_COOKIE (source)
    if vlabel == NodeLabel.IDENTIFIER.value:
        for me in graph.es.select(_target=start_vid, label="member"):
            container_vid = me.source
            container = graph.vs[container_vid]
            container_taint = _vattr(container, "taint_type", "")
            # $this / self：链式调用或属性访问，返回对象实例，非外部输入
            container_name = _vattr(container, "name", "")
            if isinstance(container_name, str) and container_name in ("$this", "self"):
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if container_taint == "source":
                return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
            # 容器可能是 passthrough 函数的返回值——递归追踪
            if container_vid in own_vids:
                sub = _trace_return_value(graph, container_vid, own_vids, param_idx, visited, depth + 1)
                if sub["origin_type"] in ("source", "param"):
                    return sub

    # ── 6. AST 赋值 fallback（DFG 缺失时，通过 assignment AST 追踪） ──
    #    当 identifier 无 DFG 且 member 追踪无果时，在 own subtree 内搜索
    #    同名 identifier 作为 assignment LHS 的节点，追踪 RHS 表达式。
    #    这弥补了 PHP normalizer 不生成 assignment DFG 边的缺陷。
    #    e.g. $markup = $this->elements($Elements); return $markup;
    if vlabel == NodeLabel.IDENTIFIER.value and depth < 3:
        ret_name = _vattr(v, "name", "")
        if ret_name:
            assign_found = _trace_assign_fallback(
                graph, ret_name, start_vid, own_vids, param_idx, visited, depth
            )
            if assign_found and assign_found["origin_type"] != "unknown":
                return assign_found
            if assign_found and assign_found.get("dep_params"):
                return assign_found

    if all_dep_params:
        unique = list(dict.fromkeys(all_dep_params))
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": unique,
            "has_unresolved_call": any_unresolved,
        }

    # 4c. DFG 链全部追溯到 safe/literal 但无 dep_params → safe
    #     e.g. return $compiled; // $compiled = $a . $b . ' ' （DFG 链到 string literal）
    if dfg_has_safe_source and not any_unresolved:
        return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": any_unresolved}


def _trace_assign_fallback(
    graph: ig.Graph,
    target_name: str,
    origin_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    depth: int,
) -> dict | None:
    """在 own subtree 内搜索 assignment LHS 同名 identifier，追踪 RHS 表达式。

    用于弥补 PHP/JS 等语言 normalizer 不生成 assignment DFG 边的缺陷。
    e.g. $x = call($param); return $x; → 追踪 call 的返回值。

    Returns: _trace_return_value 的结果 dict，或 None（未找到匹配赋值）。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    new_visited = visited | {origin_vid}
    for n in own_vids:
        if _vattr(graph.vs[n], "label") != NodeLabel.OPERATOR.value:
            continue
        if _vattr(graph.vs[n], "type") not in ("assign", "aug_assign"):
            continue
        for le in graph.es.select(_source=n, label="ast", role="left"):
            lhs = graph.vs[le.target]
            if _vattr(lhs, "label") == NodeLabel.IDENTIFIER.value and _vattr(lhs, "name", "") == target_name:
                # 找到匹配的赋值，追踪 RHS
                for re in graph.es.select(_source=n, label="ast", role="right"):
                    rhs_vid = re.target
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, depth + 1)
                    return sub
                return None  # RHS 不存在
        # PHP normalizer 用 "lhs"/"rhs"，兼容
        for le in graph.es.select(_source=n, label="ast", role="lhs"):
            lhs = graph.vs[le.target]
            if _vattr(lhs, "label") == NodeLabel.IDENTIFIER.value and _vattr(lhs, "name", "") == target_name:
                for re in graph.es.select(_source=n, label="ast", role="rhs"):
                    rhs_vid = re.target
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, depth + 1)
                    return sub
                return None
    return None  # 未找到同名赋值


def _trace_call_to_function(
    graph: ig.Graph,
    call_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    depth: int,
) -> dict | None:
    """追踪 call → use → function，读取目标函数的摘要。"""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    for ue in graph.es.select(_source=call_vid, label="use"):
        target = graph.vs[ue.target]
        if _vattr(target, "label") != NodeLabel.FUNCTION.value:
            continue

        target_summary = _vattr(target, "func_summary_type", "")
        target_pt = _vattr(target, "func_summary_pt", [])

        if target_summary == "passthrough" and target_pt:
            return _trace_passthrough_call(graph, call_vid, target_pt, own_vids, param_idx, visited, depth)
        if target_summary == "source":
            vname = _vattr(graph.vs[call_vid], "name", "")
            return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
        if target_summary == "safe":
            vname = _vattr(graph.vs[call_vid], "name", "")
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        if target_summary in ("literal",):
            vname = _vattr(graph.vs[call_vid], "name", "")
            return {"origin": vname, "origin_type": "literal", "dep_params": [], "has_unresolved_call": False}

        # 目标无 func_summary_type → fallback 检查 enrich_taint 标注的 taint_type
        # （内置 source/safe 函数由 source_registry 通过 enrich_taint 标注）
        target_taint = _vattr(target, "taint_type", "")
        if target_taint in ("source", "safe"):
            vname = _vattr(graph.vs[call_vid], "name", "")
            return {"origin": vname, "origin_type": target_taint, "dep_params": [], "has_unresolved_call": False}

        # 目标完全未知 → 返回 None，让调用方继续 DFG 追踪
        return {"origin": "", "origin_type": "unknown", "dep_params": [], "has_unresolved_call": True}

    return None  # 无 use 边，让调用方继续


def _trace_passthrough_call(
    graph: ig.Graph,
    call_vid: int,
    pt_indices: list,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    depth: int,
) -> dict:
    """追踪 passthrough call 的参数——将 passthrough 索引映射到 call 的 ast[arg] 实参，递归追踪。"""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    all_dep_params: list[int] = []
    any_unresolved = False
    arg_counter = 0

    for ae in graph.es.select(_source=call_vid, label="ast"):
        if _vattr(ae, "role") != "arg":
            continue
        # NOTE: normalizer 用 "arg_index" 存参数索引，兼容 "index"（旧格式）
        idx = _vattr(ae, "arg_index") or _vattr(ae, "index")
        actual_idx = int(idx) if idx is not None and idx != "" else arg_counter
        if actual_idx in pt_indices:
            arg_vid = ae.target
            # 实参为字面量 const（如 str_repeat('<br>', $n)）→ 直接标 safe
            if _vattr(graph.vs[arg_vid], "label") == NodeLabel.CONST.value:
                vname = _vattr(graph.vs[call_vid], "name", "")
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            sub = _trace_return_value(graph, arg_vid, own_vids, param_idx, visited, depth + 1)
            if sub["origin_type"] == "source":
                return sub
            if sub["origin_type"] == "safe":
                return sub
            all_dep_params.extend(sub.get("dep_params", []))
            if sub.get("has_unresolved_call"):
                any_unresolved = True
        arg_counter += 1

    vname = _vattr(graph.vs[call_vid], "name", "")
    unique = list(dict.fromkeys(all_dep_params))
    if unique:
        return {
            "origin": vname,
            "origin_type": "param",
            "dep_params": unique,
            "has_unresolved_call": any_unresolved,
        }
    return {"origin": vname, "origin_type": "unknown", "dep_params": [], "has_unresolved_call": any_unresolved}


# ---------------------------------------------------------------------------
# Internal: parameter 标记
# ---------------------------------------------------------------------------


def _mark_passthrough_params(graph: ig.Graph, func_vid: int, passthrough_indices: list[int]):
    """标记 function 下对应的 parameter 节点为 passthrough_arg。

    遍历 function → own → parameter，匹配 own 边的 index 属性。
    注意：index 在 own 边上，不在 parameter 节点上。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    idx_set = set(i for i in passthrough_indices if isinstance(i, int))
    for e in graph.es.select(_source=func_vid, label="own"):
        target_label = _vattr(graph.vs[e.target], "label")
        if target_label != NodeLabel.PARAMETER.value:
            continue
        # index 在 own 边上（不在 parameter 节点上）
        pidx = _vattr(e, "index")
        if pidx is not None and int(pidx) in idx_set:
            graph.vs[e.target]["taint_type"] = "passthrough_arg"
