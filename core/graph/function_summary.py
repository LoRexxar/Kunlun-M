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

logger = logging.getLogger("KunlunLog")

# BFS 递归深度上限
_MAX_TRACE_DEPTH = 15

# 迭代轮数上限（解决 A→B→A 递归调用）
_MAX_ITERATIONS = 5

# call operator 类型集合
_CALL_TYPES = frozenset({"call", "method_call", "static_call"})


def _build_edge_index(graph: "ig.Graph"):
    """一次性遍历所有边，构建 O(1) 索引替代 es.select。

    Returns:
        out: dict[str, dict[int, list[int]]]  — label → {src_vid: [tgt_vid, ...]}
        inn: dict[str, dict[int, list[int]]]  — label → {tgt_vid: [src_vid, ...]}
        ast_children: dict[int, list[tuple[int, str, str]]]  — src_vid → [(tgt_vid, role, arg_index), ...]
        own_children: dict[int, list[tuple[int, str]]]  — src_vid → [(tgt_vid, index), ...]
    """
    from utils.igraph_compat import _vattr
    out: dict[str, dict[int, list[int]]] = {}
    inn: dict[str, dict[int, list[int]]] = {}
    ast_children: dict[int, list[tuple[int, str, str]]] = {}
    own_children: dict[int, list[tuple[int, str]]] = {}
    for e in graph.es:
        el = _vattr(e, "label") or ""
        s, t = e.source, e.target
        out.setdefault(el, {}).setdefault(s, []).append(t)
        inn.setdefault(el, {}).setdefault(t, []).append(s)
        if el == "ast":
            role = _vattr(e, "role") or ""
            arg_idx = _vattr(e, "arg_index") or _vattr(e, "index") or ""
            ast_children.setdefault(s, []).append((t, role, arg_idx))
        if el == "own":
            idx = _vattr(e, "index") or ""
            own_children.setdefault(s, []).append((t, idx))
    return {
        "out": out,
        "in": inn,
        "ast_ch": ast_children,
        "own_ch": own_children,
    }


def _collect_ast_descendants(graph: ig.Graph, start_vid: int, result: set[int],
                               return_vids: list[int] | None = None, eidx: dict | None = None):
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
        for tgt_vid in eidx["out"].get("ast", {}).get(vid, []):
            if tgt_vid not in result:
                result.add(tgt_vid)
                queue.append(tgt_vid)
        if src_label in _OWN_EXPAND_LABELS:
            # branch/control 节点的 own 子节点也展开
            for tgt_vid in eidx["out"].get("own", {}).get(vid, []):
                if tgt_vid not in result:
                    result.add(tgt_vid)
                    queue.append(tgt_vid)
                    if return_vids is not None and _vattr(graph.vs[tgt_vid], "label", "") == NodeLabel.RETURN.value:
                        return_vids.append(tgt_vid)


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

    # 一次性构建 O(1) 边索引，替代所有 es.select 调用
    eidx = _build_edge_index(graph)

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
        for child_vid, edge_idx in eidx["own_ch"].get(vid, []):
            child_label = _vattr(graph.vs[child_vid], "label", "")
            if child_label == NodeLabel.PARAMETER.value:
                if edge_idx is not None and edge_idx != "":
                    param_idx[child_vid] = int(edge_idx)
                # parameter 不展开 ast 子树（无意义）
                own_vids.add(child_vid)
            elif child_label == NodeLabel.RETURN.value:
                return_vids.append(child_vid)
                own_vids.add(child_vid)
            else:
                # 其他 own 子节点：递归展开 ast 子树（同时收集嵌套 return）
                _collect_ast_descendants(graph, child_vid, own_vids, return_vids, eidx=eidx)
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
                graph, fd["return_vids"], fd["own_vids"], fd["param_idx"], eidx
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
                # Use "source:user" for source to distinguish from framework/builtin
                # sources, allowing inline return analysis in graph_analyzer.
                sync_type = "source:user" if summary_type == "source" else summary_type
                graph.vs[vid]["taint_type"] = sync_type
                if summary_type == "passthrough" and dep_params:
                    sorted_deps = sorted(dep_params)
                    graph.vs[vid]["taint_passthrough"] = sorted_deps
                    _mark_passthrough_params(graph, vid, sorted_deps, eidx)

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
    eidx: dict,
) -> list[dict]:
    """从所有 return 节点收集 return flows。"""
    from utils.igraph_compat import _vattr

    flows = []
    for ret_vid in return_vids:
        for tgt, role, _ in eidx["ast_ch"].get(ret_vid, []):
            if role == "value":
                flow = _trace_return_value(graph, tgt, own_vids, param_idx, set(), eidx)
                if flow:
                    flows.append(flow)
    return flows


def _aggregate_flows(flows: list[dict]) -> tuple[str, set[int]]:
    """汇总 return flows，返回 (summary_type, dep_params_set)。

    规则：
    - 有任何 source → "source"
    - 有 dep_params，且没有 safe flow → "passthrough"
    - 有 dep_params + safe flow 混合 → "safe"（函数内部做了 sanitization，
      param return 通常是特殊条件的 fallback，如 is_array 分支）
    - 全部 literal/safe → "safe"
    - 否则 → "unknown"
    """
    has_source = False
    has_safe = False
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
            has_safe = True
            pass  # safe_or_literal stays True
        else:  # unknown
            all_safe_or_literal = False

    if has_source:
        return "source", all_dep_params
    if all_dep_params:
        # Mixed safe + param: function has sanitization logic.
        # The param return is typically a conditional fallback
        # (e.g. if(is_array) return $text). Prefer "safe" so the
        # sanitizer in the primary return path is respected.
        if has_safe:
            return "safe", set()
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
    eidx: dict,
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
        # 检查 parameter 是否已被 enrich_taint 标注为 source（如 @RequestParam）
        self_taint = _vattr(v, "taint_type", "")
        if self_taint == "source":
            return {
                "origin": vname,
                "origin_type": "source",
                "dep_params": [],
                "has_unresolved_call": False,
            }
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
            return _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, eidx, depth)

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
    #     self::$_config[$key]（name 含 Variable('$key')，$key 是参数）→ passthrough。
    if vlabel == NodeLabel.IDENTIFIER.value and vtype == "static":
        if "Variable(" not in vname:
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
        # 提取 name 中的所有 Variable('$xxx') 名，尝试与参数关联
        import re as _re
        var_names = _re.findall(r"Variable\('\$(\w+)'\)", vname)
        if var_names:
            matched_params = []
            for vn in var_names:
                for pvid, pidx in param_idx.items():
                    pname = _vattr(graph.vs[pvid], "name", "")
                    # 参数名可能是 $xxx 或 Variable('$xxx')
                    if pname.endswith("$" + vn) or ("Variable('$" + vn + "'") in pname:
                        matched_params.append(pidx)
                        break
            if matched_params:
                unique = list(dict.fromkeys(matched_params))
                return {"origin": vname, "origin_type": "param",
                        "dep_params": unique, "has_unresolved_call": False}

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
            return _trace_passthrough_call(graph, start_vid, pt, own_vids, param_idx, visited, eidx, depth)

        # 3b. call operator → 尝试 use → function（用户自定义函数的摘要）
        if vtype in _CALL_TYPES:
            result = _trace_call_to_function(graph, start_vid, own_vids, param_idx, visited, eidx, depth)
            if result and result.get("origin_type") != "unknown":
                return result
            # 3f. 目标函数无摘要（unknown）→ fallback 追踪 ast 实参
            #     如果实参中包含 source parameter 的引用，call 返回值也继承该 origin。
            #     这是保守估计：对于无摘要的外部/框架函数，假设返回值包含实参的污点。
            if result and result.get("has_unresolved_call"):
                for arg_vid, role, arg_idx in eidx["ast_ch"].get(start_vid, []):
                    if not role.startswith("arg"):
                        continue
                    # 跳过 callee（ast child role 不是 arg 的部分）
                    arg_sub = _trace_return_value(graph, arg_vid, own_vids, param_idx, visited, eidx, depth + 1)
                    if arg_sub and arg_sub.get("origin_type") in ("source", "param"):
                        return {"origin": vname, "origin_type": arg_sub["origin_type"],
                                "dep_params": arg_sub.get("dep_params", []),
                                "has_unresolved_call": arg_sub.get("has_unresolved_call", False)}
                    # 如果实参中有 source 但 return type 是 unknown，优先报告 unknown
                    if arg_sub and arg_sub.get("origin_type") == "unknown":
                        # 继续检查其他实参
                        pass

        # 3c. 内置安全构造函数——不传播外部污点
        #     array() 是 PHP 数组字面量构造，返回值仅由参数决定，
        #     但其参数（如果有的话）已经通过 arg DFG 被单独追踪。
        #     call 本身视为 safe 容器。
        callee = _vattr(v, "callee", "")
        if callee == "array":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

        # 3d. type_cast → 追踪内部表达式（passthrough）
        #     (int)$x, (string)$x, (bool)$x — 类型转换不消除污点，
        #     结果取决于内部表达式。递归追踪 ast 子节点。
        if vtype == "type_cast":
            for inner in [t for t, r, _ in eidx["ast_ch"].get(start_vid, [])]:
                sub = _trace_return_value(graph, inner, own_vids, param_idx, visited, eidx, depth + 1)
                if sub["origin_type"] in ("source", "param", "safe"):
                    return sub
                # 内部是 unknown/literal → type_cast 也是 unknown
                return sub
            # 无子节点 → safe（如 return (int) 42 — 但正常不会被解析为 type_cast）
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

        # 3e. new → 安全构造（无外部输入）
        #     new ClassName() 创建新实例，不传播外部污点。
        #     TODO: 有参数时（new Foo($param)）应追踪构造函数。
        if vtype == "new":
            return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

    # ── 3.5. Branch/Ternary 追踪 ──
    #    return $x ? $a : $b — 追踪 iftrue 和 iffalse 两个分支，
    #    聚合结果（condition 不影响污点传播）。
    if vlabel == NodeLabel.BRANCH.value:
        branch_flows = []
        for tgt, role, _ in eidx["ast_ch"].get(start_vid, []):
            if role in ("iftrue", "iffalse"):
                sub = _trace_return_value(graph, tgt, own_vids, param_idx, visited, eidx, depth + 1)
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

    for src_vid in eidx["in"].get("dfg", {}).get(start_vid, []):
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
        sub = _trace_return_value(graph, src_vid, own_vids, param_idx, visited, eidx, depth + 1)
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
    #    e.g. $array[array_rand($array)] → member ← $array (parameter)
    if vlabel == NodeLabel.IDENTIFIER.value:
        for container_vid in eidx["in"].get("member", {}).get(start_vid, []):
            container = graph.vs[container_vid]
            container_taint = _vattr(container, "taint_type", "")
            # $this / self：链式调用或属性访问，返回对象实例，非外部输入
            container_name = _vattr(container, "name", "")
            if isinstance(container_name, str) and container_name in ("$this", "self"):
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            if container_taint == "source":
                return {"origin": vname, "origin_type": "source", "dep_params": [], "has_unresolved_call": False}
            # 容器直接是函数参数 → 返回值与该参数关联
            #   注意：normalizer 对同一变量名可能创建多个 vid，
            #   所以需要按 name 匹配而非 vid。
            container_name_raw = _vattr(container, "name", "")
            if isinstance(container_name_raw, str) and container_name_raw.startswith("$"):
                for pvid, pidx in param_idx.items():
                    pname = _vattr(graph.vs[pvid], "name", "")
                    if pname == container_name_raw:
                        return {"origin": vname, "origin_type": "param",
                                "dep_params": [pidx], "has_unresolved_call": False}
                        break
            # 容器可能是 passthrough 函数的返回值——递归追踪
            if container_vid in own_vids:
                sub = _trace_return_value(graph, container_vid, own_vids, param_idx, visited, eidx, depth + 1)
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
                graph, ret_name, start_vid, own_vids, param_idx, visited, eidx, depth
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
    eidx: dict,
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
        # 检查 LHS —— 直接 identifier 或 ArrayOffset（映射为 identifier/property）
        for lhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "left"]:
            lhs = graph.vs[lhs_vid]
            lhs_label = _vattr(lhs, "label", "")
            lhs_name = _vattr(lhs, "name", "")

            matched_lhs = False
            if lhs_label == NodeLabel.IDENTIFIER.value and lhs_name == target_name:
                matched_lhs = True
            elif lhs_label == NodeLabel.IDENTIFIER.value and _vattr(lhs, "type") == "property":
                # ArrayOffset 返回 identifier/property
                # 检查 member 边是否来自目标变量
                # $arr[$key] = $val → member($arr → $key)，LHS 是 $key (property)
                # 搜索 member 边的 source（container = $arr）
                for container_vid in eidx["in"].get("member", {}).get(lhs_vid, []):
                    container = graph.vs[container_vid]
                    if (_vattr(container, "label") == NodeLabel.IDENTIFIER.value and
                            _vattr(container, "name", "") == target_name):
                        matched_lhs = True
                        break

            if matched_lhs:
                # 找到匹配的赋值，追踪 RHS
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "right"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                # PHP normalizer 用 "lhs"/"rhs"，兼容
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "rhs"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                return None  # RHS 不存在
        # PHP normalizer 兼容：lhs role
        for lhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "lhs"]:
            lhs = graph.vs[lhs_vid]
            lhs_label = _vattr(lhs, "label", "")
            lhs_name = _vattr(lhs, "name", "")

            matched_lhs = False
            if lhs_label == NodeLabel.IDENTIFIER.value and lhs_name == target_name:
                matched_lhs = True
            elif lhs_label == NodeLabel.IDENTIFIER.value and _vattr(lhs, "type") == "property":
                for container_vid in eidx["in"].get("member", {}).get(lhs_vid, []):
                    container = graph.vs[container_vid]
                    if (_vattr(container, "label") == NodeLabel.IDENTIFIER.value and
                            _vattr(container, "name", "") == target_name):
                        matched_lhs = True
                        break

            if matched_lhs:
                for rhs_vid in [t for t, r, _ in eidx["ast_ch"].get(n, []) if r == "rhs"]:
                    if depth + 1 >= 3:
                        return None
                    sub = _trace_return_value(graph, rhs_vid, own_vids, param_idx, new_visited, eidx, depth + 1)
                    return sub
                return None
    return None  # 未找到同名赋值


def _trace_call_to_function(
    graph: ig.Graph,
    call_vid: int,
    own_vids: set[int],
    param_idx: dict[int, int],
    visited: set[int],
    eidx: dict,
    depth: int,
) -> dict | None:
    """追踪 call → use → function，读取目标函数的摘要。"""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    for target_vid in eidx["out"].get("use", {}).get(call_vid, []):
        target = graph.vs[target_vid]
        if _vattr(target, "label") != NodeLabel.FUNCTION.value:
            continue

        target_summary = _vattr(target, "func_summary_type", "")
        target_pt = _vattr(target, "func_summary_pt", [])

        if target_summary == "passthrough" and target_pt:
            return _trace_passthrough_call(graph, call_vid, target_pt, own_vids, param_idx, visited, eidx, depth)
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

        # fallback: 检查 GraphAnalyzer._REPAIR_FUNCTIONS 白名单
        # 内置修复函数（如 html.escape, shlex.quote 等）未被 enrich_taint 标注，
        # 但在 _REPAIR_FUNCTIONS 中。匹配短名（去除模块前缀）。
        target_name = _vattr(target, "name", "")
        if target_name:
            from core.graph.graph_analyzer import _REPAIR_FUNCTIONS
            short_name = target_name.rsplit(".", 1)[-1] if "." in target_name else target_name
            if short_name in _REPAIR_FUNCTIONS or target_name in _REPAIR_FUNCTIONS:
                vname = _vattr(graph.vs[call_vid], "name", "")
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}

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
    eidx: dict,
    depth: int,
) -> dict:
    """追踪 passthrough call 的参数——将 passthrough 索引映射到 call 的 ast[arg] 实参，递归追踪。"""
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    all_dep_params: list[int] = []
    any_unresolved = False
    arg_counter = 0

    for tgt, role, arg_idx in eidx["ast_ch"].get(call_vid, []):
        if role != "arg":
            continue
        actual_idx = int(arg_idx) if arg_idx else arg_counter
        if actual_idx in pt_indices:
            arg_vid = tgt
            # 实参为字面量 const（如 str_repeat('<br>', $n)）→ 直接标 safe
            if _vattr(graph.vs[arg_vid], "label") == NodeLabel.CONST.value:
                vname = _vattr(graph.vs[call_vid], "name", "")
                return {"origin": vname, "origin_type": "safe", "dep_params": [], "has_unresolved_call": False}
            sub = _trace_return_value(graph, arg_vid, own_vids, param_idx, visited, eidx, depth + 1)
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


def _mark_passthrough_params(graph: ig.Graph, func_vid: int, passthrough_indices: list[int], eidx: dict):
    """标记 function 下对应的 parameter 节点为 passthrough_arg。

    遍历 function → own → parameter，匹配 own 边的 index 属性。
    注意：index 在 own 边上，不在 parameter 节点上。
    """
    from core.graph.node_edge_schema import NodeLabel
    from utils.igraph_compat import _vattr

    idx_set = set(i for i in passthrough_indices if isinstance(i, int))
    for child_vid, edge_idx in eidx["own_ch"].get(func_vid, []):
        target_label = _vattr(graph.vs[child_vid], "label")
        if target_label != NodeLabel.PARAMETER.value:
            continue
        # index 在 own 边上（不在 parameter 节点上）
        pidx = edge_idx
        if pidx is not None and int(pidx) in idx_set:
            graph.vs[child_vid]["taint_type"] = "passthrough_arg"
