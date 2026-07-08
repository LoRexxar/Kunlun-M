"""数据流边构建器 — 在已构建的 AST 图上生成 dfg 边。

纯结构化分析器，不执行任何漏洞判定或可控性检查。
基于 igraph Graph 中已有的 ast/own/use 边，推导出 5 类数据流（dfg）边：

1. 赋值传播（forward_slice）
2. 参数传递（forward_slice）
3. 返回值传播（forward_slice）
4. 同名变量链接（same）
5. 内置知识 + 函数摘要传递（forward_slice）
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    import igraph as ig

from core.graph.edge_builders.base import BaseEdgeBuilder
from core.graph.node_edge_schema import (
    AstRole, CgCallType, CrgType, DfgType, EdgeLabel, NodeLabel, OperatorType,
)
from utils.igraph_compat import _vattr

__all__ = ["DataFlowBuilder"]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DataFlowBuilder
# ---------------------------------------------------------------------------

class DataFlowBuilder(BaseEdgeBuilder):
    """在已构建的 AST 图上生成 dfg 边。

    接收一个已完成 ast/own/use 边构建的 igraph Graph，
    通过结构化分析推导数据流关系，批量添加 dfg 边。

    用法::

        builder = DataFlowBuilder()
        builder.build(graph, language="php")
    """

    def __init__(self) -> None:
        self.graph: "ig.Graph | None" = None
        self._dfg_edges: list[tuple[int, int, str]] = []  # (src, tgt, dfg_type)
        # 函数名→vid列表索引（build() 中预构建，用于 _resolve_function O(1) 查找）
        self._func_name_index: dict[str, list[int]] = {}
        self._func_fullname_index: dict[str, list[int]] = {}

    # -- 公共接口 ------------------------------------------------------------

    def build(self, graph: "ig.Graph", language: str = "php", phase: int = 1, **kwargs) -> int:
        """主入口：生成所有 dfg 边并添加到图中。

        执行顺序：
            1. 赋值传播
            2. 参数传递
            3. 返回值传播
            4. 同名变量链接
            5. 内置知识 + 函数摘要传递
            6. 批量写入 dfg 边

        Args:
            graph: 已包含 ast/own/use 等边的 igraph 有向图。
            language: 目标语言标识，目前仅 ``php`` 支持内置知识。

        Returns:
            新增的 dfg 边数量。
        """
        self.graph = graph
        self._dfg_edges = []

        if self.graph.vcount() == 0:
            return 0

        # 预构建函数名索引：name → [vid1, vid2, ...]
        # 避免在 _resolve_function 中对每个函数调用做 O(V) 全图遍历
        self._func_name_index = {}
        self._func_fullname_index = {}
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.FUNCTION.value:
                continue
            # fullname 索引（精确匹配）
            fullname = _vattr(v, "fullname", "")
            if fullname:
                self._func_fullname_index.setdefault(fullname, []).append(v.index)
            # 短名索引（仅用于无 fullname 的局部函数）
            fname = _vattr(v, "name", "")
            if fname and not fullname:
                self._func_name_index.setdefault(fname, []).append(v.index)

        # 依次执行各分析步骤（分两阶段）
        # Phase 1: 不依赖 use 边的分析步骤
        # Phase 2: 依赖 use 边的分析步骤（参数传递、返回值传播、fluent API）
        if phase == 1:
            self._analyze_operator_flows()
            self._analyze_method_receiver_flows()
            self._analyze_member_access_flows()
            self._analyze_assignments()
            self._analyze_parameter_scope_flows()
            # NOTE: builtin_and_summary (step 5) must run BEFORE same_variables
            # (step 4) so that param_flow DFG edges (e.g. snprintf output params)
            # are already accumulated in _dfg_edges when same_variables checks
            # for DFG incoming edges on output param identifiers.
            self._analyze_builtin_and_summary(language)
            self._analyze_same_variables()
            try:
                self._analyze_cross_file_variables(language)
            except Exception:
                logger.exception(
                    "[DataFlowBuilder] _analyze_cross_file_variables failed, "
                    "skipping cross-file DFG links"
                )
        elif phase == 2:
            self._analyze_parameter_passing()
            self._analyze_return_values()
            self._analyze_fluent_api_returns()

        # 批量写入
        self._apply_dfg_edges()

        return len(self._dfg_edges)

    # -- 分析步骤 0：表达式操作符数据流 -----------------------------------------

    def _analyze_operator_flows(self) -> None:
        """#0: 表达式操作符 — 操作数 → 操作符的 dfg 边。

        对 binary_op / unary_op / type_cast / cast 等运算操作符，
        所有操作数（ast 子节点）都向操作符本身流出数据。
        这样 parameters_back 遇到拼接表达式时能沿 dfg 回溯到操作数。

        例: mysql_query("SELECT " . $id)
            图上: $id → dfg → binary_op(.)  → dfg → mysql_query 的 arg
            分析: arg=binop → dfg→ $id → dfg→ $_GET → source ✅
        """
        expr_types = {
            OperatorType.BINARY_OP.value,
            OperatorType.UNARY_OP.value,
            OperatorType.TYPE_CAST.value,
        }

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in expr_types:
                continue

            vid = v.index
            # 获取所有 ast 子节点（操作数）
            for e in self.graph.es.select(_source=vid, label=EdgeLabel.AST.value):
                child_vid = e.target
                child_label = _vattr(self.graph.vs[child_vid], "label", "")
                # 操作数可以是 identifier、const、operator、literal 等
                if child_label in (
                    NodeLabel.IDENTIFIER.value,
                    NodeLabel.CONST.value,
                    NodeLabel.OPERATOR.value,
                ):
                    self._add_dfg_edge(child_vid, vid, DfgType.FORWARD_SLICE.value)

        # call operator: args → call DFG (so parameters_back can trace through sinks)
        # 不像 binary_op 把所有子节点连入，call 只连接 ast[arg] 子节点中
        # 的 identifier/const/operator，让 parameters_back 能从 sink 调用
        # 的 arg 反向追踪到数据来源。
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
            OperatorType.NEW.value,
        }
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue
            vid = v.index
            for e in self.graph.es.select(_source=vid, label=EdgeLabel.AST.value):
                if _vattr(e, "role") != AstRole.ARG.value:
                    continue
                child_vid = e.target
                child_label = _vattr(self.graph.vs[child_vid], "label", "")
                if child_label in (
                    NodeLabel.IDENTIFIER.value,
                    NodeLabel.CONST.value,
                    NodeLabel.OPERATOR.value,
                ):
                    self._add_dfg_edge(child_vid, vid, DfgType.FORWARD_SLICE.value)

    # -- 分析步骤 0b：method_call receiver 数据流 ------------------------------

    def _analyze_method_receiver_flows(self) -> None:
        """#0b: method_call receiver — receiver 标识符 → method_call operator 的 dfg 边。

        对于 method_call/static_call 类型的 operator，从其 name 中提取
        receiver object 名称（取第一个 '.' 前的部分），在同一函数作用域内
        查找同名的 parameter/identifier 节点，创建 DFG 边。

        例: Go:  r.URL.Query().Get("file")
            图上: parameter(r) → dfg → method_call(r.URL.Query) → dfg → identifier(filename)
            分析: filename ← dfg ← method_call ← dfg ← parameter(r) → entry_param ✅

        例: PHP: $pdo->query($sql)
            图上: parameter($pdo) → dfg → method_call($pdo.query) → dfg → ...
        """
        call_types = {OperatorType.METHOD_CALL.value, OperatorType.STATIC_CALL.value}

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue

            vid = v.index

            # 1. 优先沿 callee member 边链回溯 receiver（JS/Go member expression chain）
            #    call --[ast/callee]--> callee_member <--[member]-- chain <--[member]-- identifier
            receiver_vid = None
            for eid in self.graph.incident(vid, mode="out"):
                e = self.graph.es[eid]
                if _vattr(e, "label") != EdgeLabel.AST.value:
                    continue
                if _vattr(e, "role", "") != "callee":
                    continue
                callee_vid = e.target
                current = callee_vid
                visited_chain = {current}
                while True:
                    member_found = False
                    for eid2 in self.graph.incident(current, mode="in"):
                        e2 = self.graph.es[eid2]
                        if _vattr(e2, "label") == EdgeLabel.MEMBER.value:
                            member_source = e2.source
                            if member_source not in visited_chain:
                                visited_chain.add(member_source)
                                src_label = _vattr(
                                    self.graph.vs[member_source], "label", ""
                                )
                                if src_label == NodeLabel.IDENTIFIER.value:
                                    receiver_vid = member_source
                                elif src_label == NodeLabel.OPERATOR.value:
                                    current = member_source
                                    member_found = True
                                break
                    if receiver_vid is not None or not member_found:
                        break
                if receiver_vid is not None:
                    break

            if receiver_vid is not None:
                self._add_dfg_edge(receiver_vid, vid, DfgType.FORWARD_SLICE.value)
                continue

            # 2. 回退到 name-based 搜索（PHP/Go 等无 member chain 的情况）
            name = _vattr(v, "name", "") or ""
            dot_pos = name.find(".")
            if dot_pos <= 0:
                continue
            receiver_name = name[:dot_pos]

            # 通过 own 边向上找到 parent function/file
            parent_vid = None
            for eid in self.graph.incident(vid, mode="in"):
                e = self.graph.es[eid]
                if _vattr(e, "label") in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                    parent_vid = e.source
                    break

            if parent_vid is None:
                continue

            # 沿作用域链（own/ast 父链）向上查找同名 parameter/identifier。
            # 处理方法调用在 if/for/try body 内的场景：parent 是 branch 而非
            # function，receiver（如 Optional）parameter 在上层 method 节点中。
            scope_chain = [parent_vid]
            visited_scopes = {parent_vid}
            current_scope = parent_vid
            while True:
                found_parent = False
                for eid in self.graph.incident(current_scope, mode="in"):
                    e = self.graph.es[eid]
                    if _vattr(e, "label") not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                        continue
                    ancestor_vid = e.source
                    if ancestor_vid in visited_scopes:
                        continue
                    ancestor_label = _vattr(
                        self.graph.vs[ancestor_vid], "label", ""
                    )
                    visited_scopes.add(ancestor_vid)
                    scope_chain.append(ancestor_vid)
                    current_scope = ancestor_vid
                    found_parent = True
                    if ancestor_label in (
                        NodeLabel.FUNCTION.value,
                        NodeLabel.FILE.value,
                    ):
                        break
                if not found_parent:
                    break

            for scope_vid in scope_chain:
                for eid in self.graph.incident(scope_vid, mode="out"):
                    e = self.graph.es[eid]
                    if _vattr(e, "label") not in (
                        EdgeLabel.OWN.value, EdgeLabel.AST.value
                    ):
                        continue
                    child = self.graph.vs[e.target]
                    child_name = _vattr(child, "name", "") or ""
                    child_label = _vattr(child, "label", "")
                    if child_name == receiver_name and child_label in (
                        NodeLabel.PARAMETER.value,
                        NodeLabel.IDENTIFIER.value,
                    ):
                        receiver_vid = e.target
                        break
                    # 搜索 assign/var 子节点的 lhs identifier
                    # （如 var template = new Template(...) → template 在
                    # assign 的 lhs 中而非 function 的直接子节点）
                    if child_label == NodeLabel.OPERATOR.value and _vattr(
                        child, "type", ""
                    ) == OperatorType.ASSIGN.value:
                        lhs_nodes = self._get_ast_children(
                            e.target, role=AstRole.LHS.value
                        )
                        for lhs_vid in lhs_nodes:
                            lhs_v = self.graph.vs[lhs_vid]
                            if _vattr(lhs_v, "name", "") == receiver_name:
                                receiver_vid = lhs_vid
                                break
                        if receiver_vid is not None:
                            break
                if receiver_vid is not None:
                    break

            if receiver_vid is None:
                continue

            self._add_dfg_edge(receiver_vid, vid, DfgType.FORWARD_SLICE.value)

    def _analyze_member_access_flows(self) -> None:
        """#0c: member access chain — 创建 identifier(receiver) → identifier(property) 的 DFG 边。

        对于 member 边 (receiver --member--> property)，当 property 是 identifier 且
        receiver 也是 identifier 时，创建 DFG 边使 parameters_back 能沿 member chain 追溯。

        例: request.args → identifier(request) --dfg--> identifier(args)
        例: request.data → identifier(request) --dfg--> identifier(data)
        """
        for e in self.graph.es.select(label=EdgeLabel.MEMBER.value):
            src_vid = e.source
            tgt_vid = e.target
            src_label = _vattr(self.graph.vs[src_vid], "label", "")
            tgt_label = _vattr(self.graph.vs[tgt_vid], "label", "")
            if (src_label == NodeLabel.IDENTIFIER.value
                    and tgt_label == NodeLabel.IDENTIFIER.value):
                self._add_dfg_edge(
                    src_vid, tgt_vid, DfgType.FORWARD_SLICE.value
                )

    # -- 分析步骤 1：赋值传播 -------------------------------------------------

    def _analyze_assignments(self) -> None:
        """#1: 赋值传播 — 为每个 assign/aug_assign 创建 dfg 边。

        规则：
        - 找到 operator(type=assign) 的 RHS 子节点（ast[role=rhs]）
        - 找到 operator(type=assign) 的 LHS 子节点（ast[role=lhs]）
        - 若 RHS 是 identifier/operator → 创建 dfg(RHS → LHS)
        - aug_assign 同理

        变体：部分语言（JS）的 VariableDeclaration 用 rhs+value 结构
        （rhs→declarator(identifier) → value→init），此时 rhs 子节点本身
        就是 lhs（declarator identifier），value 是实际数据来源。
        """
        assign_types = {OperatorType.ASSIGN.value, OperatorType.AUG_ASSIGN.value}

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in assign_types:
                continue

            vid = v.index

            # 获取 LHS 和 RHS 子节点
            lhs_nodes = self._get_ast_children(vid, role=AstRole.LHS.value)
            rhs_nodes = self._get_ast_children(vid, role=AstRole.RHS.value)

            # 变体：rhs 子节点是 identifier 且有 value 子边（JS VariableDeclaration）
            # 此时 rhs 就是 lhs（被声明的变量），value 是赋值来源
            if not lhs_nodes and rhs_nodes:
                rhs_vid = rhs_nodes[0]
                rhs_label = _vattr(self.graph.vs[rhs_vid], "label", "")
                if rhs_label == NodeLabel.IDENTIFIER.value:
                    value_nodes = self._get_ast_children(rhs_vid, role="value")
                    if value_nodes:
                        lhs_nodes = [rhs_vid]
                        rhs_nodes = value_nodes

            # 变体：穿透 type_cast / subscript_expression
            # type_cast: TS as-expression, C cast 等 — identity
            # subscript: arr[key] — 取 object operand 作为真正的 rhs
            if rhs_nodes:
                real_rhs = rhs_nodes
                changed = True
                while changed:
                    changed = False
                    for rvid in list(real_rhs):
                        rlabel = _vattr(self.graph.vs[rvid], "label", "")
                        rtype = _vattr(self.graph.vs[rvid], "type", "")
                        raw_type = _vattr(self.graph.vs[rvid], "raw_type", "")
                        if rlabel == NodeLabel.OPERATOR.value and rtype == OperatorType.TYPE_CAST.value:
                            operand_nodes = self._get_ast_children(rvid, role=AstRole.OPERAND.value)
                            if operand_nodes:
                                real_rhs = operand_nodes
                                changed = True
                                break
                        elif (rlabel == NodeLabel.OPERATOR.value
                              and raw_type in ("subscript_expression",
                                                "element_access_expression")):
                            # subscript: 取第一个 operand (the object) 作为 DFG source
                            operand_nodes = self._get_ast_children(rvid, role=AstRole.OPERAND.value)
                            if operand_nodes:
                                real_rhs = operand_nodes
                                changed = True
                                break
                rhs_nodes = real_rhs

            if not lhs_nodes or not rhs_nodes:
                continue

            lhs_vid = lhs_nodes[0]
            rhs_vid = rhs_nodes[0]

            # LHS 应为 identifier 或 const
            lhs_label = _vattr(self.graph.vs[lhs_vid], "label", "")
            if lhs_label not in (NodeLabel.IDENTIFIER.value, NodeLabel.CONST.value):
                continue

            # RHS 可以是 identifier、const 或 operator（如函数调用）
            rhs_label = _vattr(self.graph.vs[rhs_vid], "label", "")
            if rhs_label in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.CONST.value,
                NodeLabel.OPERATOR.value,
            ):
                self._add_dfg_edge(rhs_vid, lhs_vid, DfgType.FORWARD_SLICE.value)

            # TernaryOp (branch type): 两个分支的值分别 dfg 到 LHS
            if rhs_label == NodeLabel.BRANCH.value:
                rhs_type = _vattr(self.graph.vs[rhs_vid], "type", "").lower()
                if rhs_type == "ternary":
                    # iftrue 和 iffalse 分支的值节点 dfg 到 LHS
                    for branch_child in self.graph.es.select(
                        _source=rhs_vid, label=EdgeLabel.AST.value
                    ):
                        child_vid = branch_child.target
                        child_label = _vattr(self.graph.vs[child_vid], "label", "")
                        # iftrue/iffalse 的值节点（identifier/const/operator）
                        if child_label in (
                            NodeLabel.IDENTIFIER.value,
                            NodeLabel.CONST.value,
                            NodeLabel.OPERATOR.value,
                        ):
                            self._add_dfg_edge(
                                child_vid, lhs_vid, DfgType.FORWARD_SLICE.value
                            )

    # -- 分析步骤 2：参数传递 -------------------------------------------------

    def _analyze_parameter_passing(self) -> None:
        """#2: 参数传递 — 将调用参数与函数定义参数关联。

        规则：
        - 找到 operator(type=call/static_call/method_call) 的 use 目标（函数节点）
        - 若 use 目标是占位节点（无 own 子节点），尝试通过同名解析到真正的函数定义
        - 调用者的 ast[arg, arg_index=N] 对应函数定义的 own[index=N] 参数
        - 创建 dfg(arg_identifier → parameter)
        - 若无 use 目标（外部函数），则跳过
        """
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue

            vid = v.index

            # 通过 use 边找到函数节点
            func_vid = self._get_cg_target(vid)
            if func_vid is None:
                continue

            # 尝试解析到真正的函数定义（占位节点无 own 子节点）
            resolved_vid = self._resolve_function(func_vid)

            # 获取该调用的所有 arg 子节点
            arg_children = self._get_ast_children_by_arg_index(vid)

            # 获取函数定义的参数（按 own index）
            param_map = self._get_own_children_by_index(resolved_vid)

            # 匹配 arg_index → parameter own index
            for arg_idx, arg_vid in arg_children.items():
                param_vid = param_map.get(arg_idx)
                if param_vid is not None:
                    self._add_dfg_edge(arg_vid, param_vid, DfgType.FORWARD_SLICE.value)

    # -- 分析步骤 3：返回值传播 -----------------------------------------------

    def _analyze_return_values(self) -> None:
        """#3: 返回值传播 — 将 return 值连接到调用者的赋值目标。

        规则：
        - 遍历所有 call/static_call/method_call operator
        - 通过 use 边找到函数节点，再解析到真正的函数定义
        - 找到函数定义体内的 return 节点的 ast[value] 子节点
        - 若调用 operator 被赋值（其作为某个 assign 的 RHS），则创建 dfg(return_value → LHS)
        """
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue

            caller_vid = v.index

            # 通过 use 边找到函数节点，并解析到真正的定义
            func_vid = self._get_cg_target(caller_vid)
            if func_vid is None:
                continue

            resolved_vid = self._resolve_function(func_vid)
            if resolved_vid == func_vid:
                # 仍然是占位节点，无法解析到定义
                continue

            # 找到真正的函数定义中的 return 节点
            return_vids = self._get_own_children_by_label(resolved_vid, NodeLabel.RETURN.value)

            for ret_vid in return_vids:
                value_children = self._get_ast_children(ret_vid, role=AstRole.VALUE.value)
                if not value_children:
                    continue
                return_value_vid = value_children[0]

                # 检查调用者 operator 是否作为某个 assign 的 RHS
                assign_lhs = self._find_assign_lhs_for_callee(caller_vid)
                if assign_lhs is not None:
                    self._add_dfg_edge(
                        return_value_vid, assign_lhs, DfgType.FORWARD_SLICE.value
                    )

    # -- 分析步骤 3b：Fluent API / Builder 模式 DFG 回传 -------------------------

    def _analyze_fluent_api_returns(self) -> None:
        """#3b: Fluent API — method_call 返回值回传到 receiver 对象。

        对于 mutable builder 模式（如 StringBuilder.append、StringBuilder.insert），
        method_call 会修改 receiver 对象并返回 this。数据流应从 call 回传到 receiver，
        使得后续对同一 receiver 的调用能追踪到之前传入的数据。

        规则：
        - 遍历所有 method_call/static_call operator
        - 如果已有 DFG 入边来自某个 receiver identifier/variable
        - 且该 receiver 在同一作用域内多次作为相同或不同方法的 receiver
        - 则创建 dfg(call → receiver) 边，表示 call 的返回值回到 receiver

        例: cart.append("..." + field1 + "...")
            图上: field1 → dfg → cart.append → dfg → cart
            效果: cart.toString() → dfg → output() 时，可回溯到 field1
        """
        call_types = {
            OperatorType.METHOD_CALL.value,
            OperatorType.STATIC_CALL.value,
        }

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue

            vid = v.index

            # 找到流入此 call 的 DFG receiver 来源
            receiver_vid = None
            for eid in self.graph.incident(vid, mode="in"):
                e = self.graph.es[eid]
                if _vattr(e, "label") != EdgeLabel.DFG.value:
                    continue
                src = self.graph.vs[e.source]
                src_label = _vattr(src, "label", "")
                if src_label in (
                    NodeLabel.IDENTIFIER.value,
                    NodeLabel.PARAMETER.value,
                ):
                    # 确认此来源确实是 receiver（同名检查）
                    src_name = _vattr(src, "name", "")
                    op_name = _vattr(v, "name", "")
                    # receiver name 是 op_name 的第一段（如 "cart" in "cart.append"）
                    dot_pos = op_name.find(".")
                    if dot_pos > 0:
                        receiver_name = op_name[:dot_pos]
                        if src_name == receiver_name:
                            receiver_vid = src.index
                            break

            if receiver_vid is None:
                continue

            # 检查此 receiver 是否在同作用域内有其他 method_call（多次使用）
            receiver_name = _vattr(self.graph.vs[receiver_vid], "name", "")
            other_calls = 0
            for eid2 in self.graph.incident(receiver_vid, mode="out"):
                e2 = self.graph.es[eid2]
                if _vattr(e2, "label") == EdgeLabel.DFG.value:
                    tgt = self.graph.vs[e2.target]
                    if (tgt.index != vid
                            and _vattr(tgt, "label") == NodeLabel.OPERATOR.value
                            and _vattr(tgt, "type") in call_types):
                        other_calls += 1

            # 只有当 receiver 被多次使用时才回传（避免对单次调用过度传播）
            if other_calls == 0:
                continue

            # 检查是否已有此 DFG 边（避免重复）
            for eid3 in self.graph.es.select(_source=vid, _target=receiver_vid,
                                              label=EdgeLabel.DFG.value):
                continue  # 已存在，跳过当前 call 继续下一个

            # 创建 call → receiver 的 DFG 回传边
            self._add_dfg_edge(vid, receiver_vid, DfgType.FORWARD_SLICE.value)

    # -- 分析步骤 4：同名变量链接 ---------------------------------------------

    def _analyze_same_variables(self) -> None:
        """#4: 同名变量链接 — 在同一作用域内链接同名变量的「使用→定义」。

        规则：
        - 赋值 LHS 的 identifier 是 same 链的断点（它已经有 dfg(RHS→LHS)）
        - 非 LHS 的 identifier（纯使用）向前链接到同一作用域内最近的同名 LHS
        - 目的：让 echo($x) 中的 $x 能通过 same 边回溯到 $x = $source 的 RHS
        """
        # 先收集所有赋值 LHS identifier
        assign_lhs_vids: set[int] = set()
        assign_types = {OperatorType.ASSIGN.value, OperatorType.AUG_ASSIGN.value}
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in assign_types:
                continue
            lhs_nodes = self._get_ast_children(v.index, role=AstRole.LHS.value)
            for lhv in lhs_nodes:
                lhs_label = _vattr(self.graph.vs[lhv], "label", "")
                if lhs_label in (NodeLabel.IDENTIFIER.value, NodeLabel.CONST.value):
                    assign_lhs_vids.add(lhv)
            # JS VariableDeclarator: rhs 子节点是 identifier，它有 value 子边
            # 此时 rhs identifier 就是声明变量的 LHS
            if not lhs_nodes:
                rhs_nodes = self._get_ast_children(v.index, role=AstRole.RHS.value)
                for rhv in rhs_nodes:
                    if _vattr(self.graph.vs[rhv], "label") == NodeLabel.IDENTIFIER.value:
                        value_nodes = self._get_ast_children(rhv, role="value")
                        if value_nodes:
                            assign_lhs_vids.add(rhv)

        # Parameter 节点是定义端点（类似 assign LHS）
        # 函数参数没有显式的赋值，但同名 identifier/parameter 使用应回溯到它
        for v in self.graph.vs:
            if _vattr(v, "label") == NodeLabel.PARAMETER.value:
                assign_lhs_vids.add(v.index)

        # C/Go normalizer may label function parameters as "identifier" (not
        # "parameter").  An identifier that is an own-child of a function node
        # with an "ast[value]" edge (initialiser) is a definition site
        # (e.g. C: char *args[] = {...}).  Treat as LHS.
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.IDENTIFIER.value:
                continue
            has_own = False
            for oe in self.graph.es.select(_target=v.index, label="own"):
                parent_label = _vattr(
                    self.graph.vs[oe.source], "label", ""
                )
                if parent_label == NodeLabel.FUNCTION.value:
                    has_own = True
                    break
            if has_own:
                # Only treat as LHS if it has an initialiser (ast[value] edge)
                has_init = any(
                    _vattr(e, "role") == "value"
                    for e in self.graph.es.select(_source=v.index, label="ast")
                )
                if has_init:
                    assign_lhs_vids.add(v.index)

        # 收集作用域 → identifier 映射
        scope_vars: dict[tuple[int, str], dict[str, list[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for v in self.graph.vs:
            if _vattr(v, "label") not in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                continue
            vname = _vattr(v, "name", "")
            if not vname:
                continue
            scope_vid = self._get_scope_parent(v.index)
            if scope_vid is None:
                continue
            scope_label = _vattr(self.graph.vs[scope_vid], "label", "")
            scope_vars[(scope_vid, scope_label)][vname].append(v.index)

        # 对每个作用域中同名 identifier，建立使用→最近LHS 的 same 链
        for scope_key, name_groups in scope_vars.items():
            for name, vids in name_groups.items():
                if len(vids) < 2:
                    continue
                vids_sorted = sorted(
                    vids, key=lambda vid: _vattr(self.graph.vs[vid], "lineno", 0)
                )
                # 从每个非 LHS 的 identifier，向前找最近的同名 LHS
                for i, vid in enumerate(vids_sorted):
                    if vid in assign_lhs_vids:
                        continue  # LHS 不向前链接（已有 dfg(RHS→LHS)）
                    # 找前方最近的 LHS
                    found = False
                    for j in range(i - 1, -1, -1):
                        if vids_sorted[j] in assign_lhs_vids:
                            self._add_dfg_edge(
                                vids_sorted[j], vid, DfgType.SAME.value
                            )
                            found = True
                            break
                    if found:
                        continue
                    # 回退：如果没有同名 LHS，找前方最近的有 DFG 入边的
                    # identifier（如通过 param_flow 写入的 output param）。
                    # 这样 snprintf(cmd,...) 的 cmd(有DFG入边) → system(cmd) 的 cmd
                    # 注意：DFG 边可能还未写入 graph（批量写入在最后），
                    # 所以需要同时检查 self._dfg_edges 累积列表。
                    for j in range(i - 1, -1, -1):
                        if vids_sorted[j] in assign_lhs_vids:
                            break  # 已有 LHS 但被跳过（lineno 不匹配）
                        target_vid = vids_sorted[j]
                        has_dfg_in = any(
                            self.graph.es.select(
                                _target=target_vid, label="dfg"
                            )
                        )
                        if not has_dfg_in:
                            # Check accumulated but not-yet-flushed DFG edges
                            has_dfg_in = any(
                                tgt == target_vid
                                for _, tgt, _ in self._dfg_edges
                            )
                        if has_dfg_in:
                            self._add_dfg_edge(
                                target_vid, vid, DfgType.SAME.value
                            )
                            break
                    # 回退3：如果前方有同名 parameter，创建 parameter → identifier 的 DFG 边
                    # 使 parameters_back 能从 body identifier 追溯到函数参数
                    for j in range(i - 1, -1, -1):
                        if vids_sorted[j] in assign_lhs_vids:
                            break
                        if _vattr(self.graph.vs[vids_sorted[j]], "label") == NodeLabel.PARAMETER.value:
                            self._add_dfg_edge(
                                vids_sorted[j], vid, DfgType.SAME.value
                            )
                            break

    def _analyze_parameter_scope_flows(self) -> None:
        """#0d: parameter → body identifier — 对每个 function 的 parameter，
        查找同 file 内同名的 identifier（无 DFG 入边、非 assign LHS 的），
        创建 parameter → identifier 的 DFG 边。

        这解决了 Python/JS 等语言中函数参数在函数体内被直接引用时
        （如 member access 的 receiver: request.args 中的 request）
        缺少 DFG 边的问题。

        由于 Python normalizer 创建的 member access receiver identifier
        不一定挂在 function 的 own 子树中，此方法按 file 粒度匹配。
        """
        for fv in self.graph.vs.select(label=NodeLabel.FUNCTION.value):
            func_vid = fv.index
            func_path = _vattr(fv, "path", "")

            # 收集此 function 的所有 parameter
            params: dict[str, list[int]] = defaultdict(list)
            for oe in self.graph.es.select(_source=func_vid, label="own"):
                cv = self.graph.vs[oe.target]
                if _vattr(cv, "label") == NodeLabel.PARAMETER.value:
                    pname = _vattr(cv, "name", "")
                    if pname:
                        params[pname].append(cv.index)
            if not params:
                continue

            # 收集 assign LHS（这些已有 DFG 入边，不需要 param → ident 边）
            assign_lhs_vids: set[int] = set()
            for v in self.graph.vs.select(label=NodeLabel.IDENTIFIER.value):
                for e in self.graph.es.select(_source=v.index, label="ast"):
                    if _vattr(e, "role") in ("lhs", "assign_lhs"):
                        assign_lhs_vids.add(v.index)

            # 在同 file 内查找同名 identifier（无 DFG 入边且非 LHS）
            for pname, param_vids in params.items():
                for ident in self.graph.vs.select(
                    label=NodeLabel.IDENTIFIER.value,
                    name=pname,
                ):
                    ident_vid = ident.index
                    # 跳过 parameter 自身
                    if ident_vid in param_vids:
                        continue
                    # 跳过有 DFG 入边的（已有数据流来源）
                    has_dfg_in = any(
                        self.graph.es.select(_target=ident_vid, label="dfg")
                    )
                    if has_dfg_in:
                        continue
                    # 跳过 assign LHS
                    if ident_vid in assign_lhs_vids:
                        continue
                    # 跳过不同 file 的
                    if _vattr(ident, "path", "") != func_path:
                        continue
                    # 创建 parameter → identifier 的 DFG 边
                    for pvid in param_vids:
                        self._add_dfg_edge(
                            pvid, ident_vid, DfgType.SAME.value
                        )

    # -- 分析步骤 6：跨文件变量链接 -------------------------------------------

    def _analyze_cross_file_variables(self, language: str) -> None:
        """#6: 跨文件变量链接 — 对无 DFG 入边的 identifier，沿 import 链
        搜索被 include 文件中的同名变量，建立 cross_file DFG 边。

        支持语言语义：
        - PHP include: 被包含文件的代码在 parent 作用域执行，$变量直接流通
        - C/C++ #include: 预处理文本替换，全局变量声明跨文件可见
        - Ruby require: 模块加载，全局变量($前缀)和常量跨文件可见
        - Lua require/dofile: 模块加载，模块返回值通过赋值连接

        只处理文件级变量（不在函数体内的），函数局部变量不跨文件流通。
        """
        import os

        # 变量名过滤函数（按语言）
        def _is_global_var(name: str) -> bool:
            if language == "php":
                return name.startswith("$")
            elif language in ("c", "cpp"):
                # C/C++ 全局变量：不以特定前缀区分，但排除函数内局部变量
                # 排除明显不是变量的：数字、空、单字符运算符
                return bool(name) and name not in ("=", "+", "-", "*", "/", ")", "(", ";", ",", "{", "}", "[", "]")
            elif language == "ruby":
                return name.startswith("$") or name[0:1].isupper()  # $var or Constant
            elif language == "lua":
                # Lua 模块通过 return table 暴露接口，变量不自动跨文件可见
                # 只有显式全局变量（非 local）才有跨文件意义
                # 但 tree-sitter 中 local 难以从 identifier 层面区分
                # 暂时不做 Lua 跨文件变量链接（通过 _resolve_function 已覆盖参数传递）
                return False
            return False

        # ── Step 1: file_path → file_vid 映射 ──
        file_path_to_vid: dict[str, int] = {}
        for v in self.graph.vs:
            if _vattr(v, "label") == NodeLabel.FILE.value:
                # file 节点的路径在 location 属性中
                fp = (
                    _vattr(v, "location", "")
                    or _vattr(v, "path", "")
                    or _vattr(v, "file_path", "")
                )
                if fp:
                    file_path_to_vid[os.path.normpath(fp)] = v.index

        if not file_path_to_vid:
            return

        # ── Step 2: 按文件分组 identifier ──
        # file_vars[file_vid][var_name]["defined"] = [vid, ...]
        # file_vars[file_vid][var_name]["undefined"] = [vid, ...]
        file_vars: dict[int, dict[str, dict[str, list[int]]]] = \
            defaultdict(lambda: defaultdict(lambda: {"defined": [], "undefined": []}))

        for v in self.graph.vs:
            if _vattr(v, "label") not in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                continue
            vname = _vattr(v, "name", "")
            if not _is_global_var(vname):
                continue  # 按语言规则过滤变量名

            # 直接用 identifier 的 file_path 属性确定所属文件
            # （不依赖 _get_scope_parent，因为 identifier 可能没有 own/ast 入边）
            v_fp = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            if not v_fp:
                continue
            norm_v_fp = os.path.normpath(v_fp)
            file_vid = file_path_to_vid.get(norm_v_fp)
            if file_vid is None:
                continue

            # 检查是否有 DFG 入边（含已累积未 flush 的）
            has_dfg_in = bool(
                list(self.graph.es.select(_target=v.index, label="dfg"))
            )
            if not has_dfg_in:
                has_dfg_in = any(
                    tgt == v.index for _, tgt, _ in self._dfg_edges
                )

            cat = "defined" if has_dfg_in else "undefined"

            # C/C++: 函数内变量的 defined 降级为 local（不作为跨文件链接源）
            # 但函数内的 undefined 保留（可能是引用全局变量）
            if language in ("c", "cpp"):
                in_function = False
                for eid in self.graph.incident(v.index, mode="in"):
                    e = self.graph.es[eid]
                    elabel = _vattr(e, "label")
                    if elabel in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                        ancestor = e.source
                        visited_scope = {v.index}
                        while ancestor is not None and ancestor not in visited_scope:
                            visited_scope.add(ancestor)
                            alabel = _vattr(self.graph.vs[ancestor], "label")
                            if alabel == NodeLabel.FUNCTION.value:
                                in_function = True
                                break
                            if alabel == NodeLabel.FILE.value:
                                break
                            found_up = False
                            for eid2 in self.graph.incident(ancestor, mode="in"):
                                e2 = self.graph.es[eid2]
                                if _vattr(e2, "label") in (
                                    EdgeLabel.OWN.value, EdgeLabel.AST.value
                                ):
                                    ancestor = e2.source
                                    found_up = True
                                    break
                            if not found_up:
                                break
                        break
                if in_function and cat == "defined":
                    cat = "local"  # 函数内已定义变量，不作为跨文件链接源

            if cat in ("defined", "undefined"):
                file_vars[file_vid][vname][cat].append(v.index)

        # 保存供 _resolve_import_targets 使用（策略 2）
        self._cross_file_vars = file_vars

        # ── Step 3: 遍历 import 节点，构建 parent → targets 映射 ──
        import_types = {"include", "require", "require_once", "include_once"}
        parent_to_targets: dict[int, set[int]] = defaultdict(set)

        for v in self.graph.vs:
            if _vattr(v, "label") != "import":
                continue
            if _vattr(v, "type", "") not in import_types:
                continue

            import_vid = v.index
            import_fp = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            if not import_fp:
                continue
            norm_import_fp = os.path.normpath(import_fp)
            parent_vid = file_path_to_vid.get(norm_import_fp)
            if parent_vid is None:
                continue

            target_vids = self._resolve_import_targets(
                import_vid, import_fp, file_path_to_vid
            )
            for tv in target_vids:
                parent_to_targets[parent_vid].add(tv)

        # ── Step 4: 链接同名变量 ──
        processed: set[tuple[int, int]] = set()
        cross_count = 0
        for parent_vid, target_vids in parent_to_targets.items():
            parent_vars = file_vars.get(parent_vid, {})
            for target_vid in target_vids:
                if (parent_vid, target_vid) in processed:
                    continue
                processed.add((parent_vid, target_vid))

                target_vars = file_vars.get(target_vid, {})
                # target 文件中 defined → parent 文件中 undefined 同名变量
                for var_name, target_cats in target_vars.items():
                    target_defined = target_cats.get("defined", [])
                    parent_undefined = parent_vars.get(
                        var_name, {}
                    ).get("undefined", [])

                    for t_vid in target_defined:
                        for p_vid in parent_undefined:
                            self._add_dfg_edge(
                                t_vid, p_vid, DfgType.CROSS_FILE.value
                            )
                            cross_count += 1

        if cross_count:
            logger.info(
                "[DataFlowBuilder] Cross-file links: %d edges for %d file pairs",
                cross_count, len(processed),
            )

        # ── Step 4b: 共享 include 文件的 parent 之间变量链接 ──
        # C/C++ 语义：变量定义在 .c 文件，声明(extern)在 .h 文件。
        # 两个 .c 文件通过共同 #include 同一 .h 文件关联。
        # 需要：parent A 的 defined → parent B 的 undefined（共享同一 target）
        if language in ("c", "cpp"):
            target_to_parents: dict[int, set[int]] = defaultdict(set)
            for parent_vid, target_vids in parent_to_targets.items():
                for tv in target_vids:
                    target_to_parents[tv].add(parent_vid)

            shared_pairs: set[tuple[int, int]] = set()
            for target_vid, parents in target_to_parents.items():
                if len(parents) < 2:
                    continue
                parent_list = list(parents)
                for i in range(len(parent_list)):
                    for j in range(i + 1, len(parent_list)):
                        a, b = parent_list[i], parent_list[j]
                        pair = (min(a, b), max(a, b))
                        if pair not in shared_pairs:
                            shared_pairs.add(pair)
                            a_vars = file_vars.get(a, {})
                            b_vars = file_vars.get(b, {})
                            for var_name, a_cats in a_vars.items():
                                a_defined = a_cats.get("defined", [])
                                b_undefined = b_vars.get(
                                    var_name, {}
                                ).get("undefined", [])
                                for a_vid in a_defined:
                                    for b_vid in b_undefined:
                                        self._add_dfg_edge(
                                            a_vid, b_vid, DfgType.CROSS_FILE.value
                                        )
                                        cross_count += 1
                            # Reverse direction too
                            for var_name, b_cats in b_vars.items():
                                b_defined = b_cats.get("defined", [])
                                a_undefined = a_vars.get(
                                    var_name, {}
                                ).get("undefined", [])
                                for b_vid in b_defined:
                                    for a_vid in a_undefined:
                                        self._add_dfg_edge(
                                            b_vid, a_vid, DfgType.CROSS_FILE.value
                                        )
                                        cross_count += 1

            if cross_count:
                logger.info(
                    "[DataFlowBuilder] Shared-include cross-file links: %d additional edges for %d shared targets",
                    cross_count, len(shared_pairs),
                )

    def _resolve_import_targets(
        self, import_vid: int, parent_fp: str,
        file_path_map: dict[str, int],
    ) -> list[int]:
        """解析 import 节点的目标文件，返回 target file_vid 列表。

        Case A — 静态路径: arg 是 operator (binary_op/concat)，trace 字符串
                 叶子拼出路径，normpath 后精确匹配。
        Case B — 动态路径: arg 是 identifier（如 include($file)），
                 收集同一 parent 文件中所有 import 的已知目标作为候选。
        """
        import os

        arg_vids = self._get_ast_children(import_vid, role="arg")
        parent_dir = os.path.dirname(parent_fp)

        # Case S: source 属性直接提供路径（C/C++ #include "utils.h"）
        # C/C++ import 节点没有 ast[arg] 子节点，路径存在 source 属性中
        if not arg_vids:
            source = _vattr(self.graph.vs[import_vid], "source", "")
            if source:
                resolved = os.path.normpath(os.path.join(parent_dir, source))
                vid = file_path_map.get(resolved)
                if vid is not None:
                    return [vid]
                return self._fuzzy_match_file(source, file_path_map)
            return []

        arg_vid = arg_vids[0]
        arg_v = self.graph.vs[arg_vid]
        arg_label = _vattr(arg_v, "label", "")
        arg_type = _vattr(arg_v, "type", "")


        # Case A: 拼接路径（binary_op / concat）
        if arg_label == NodeLabel.OPERATOR.value and arg_type in (
            "binary_op", "concat",
        ):
            parts = self._trace_concat_strings(arg_vid)
            if parts:
                joined = "".join(parts)
                resolved = os.path.normpath(os.path.join(parent_dir, joined))
                vid = file_path_map.get(resolved)
                if vid is not None:
                    return [vid]
                return self._fuzzy_match_file(joined, file_path_map)

        # Case B: 动态 include（arg 是 identifier/其他）
        # 策略 1: 收集同一 parent 文件中所有 import 的已知目标
        import_types = {"include", "require", "require_once", "include_once"}
        norm_parent = os.path.normpath(parent_fp)
        candidates: set[int] = set()
        for v in self.graph.vs:
            if _vattr(v, "label") != "import":
                continue
            if _vattr(v, "type", "") not in import_types:
                continue
            v_fp = _vattr(v, "file_path", "") or _vattr(v, "path", "")
            if os.path.normpath(v_fp) != norm_parent:
                continue
            # 递归 resolve（边界：静态 import 返回结果，不再递归）
            child_arg_vids = self._get_ast_children(v.index, role="arg")
            if child_arg_vids:
                ca = self.graph.vs[child_arg_vids[0]]
                if (_vattr(ca, "label", "") == NodeLabel.OPERATOR.value
                        and _vattr(ca, "type", "") in ("binary_op", "concat")):
                    resolved = self._resolve_import_targets(
                        v.index, v_fp, file_path_map
                    )
                    for r in resolved:
                        candidates.add(r)

        # 策略 2: 动态 include 变量的同名候选
        # include($file) → $file 在 target 文件中有 DFG 入边
        # 注意：策略 1 的 fuzzy match 可能返回大量误匹配，策略 2 始终追加
        if arg_label == NodeLabel.IDENTIFIER.value:
            var_name = _vattr(arg_v, "name", "")
            if var_name.startswith("$"):
                cross_vars = getattr(self, "_cross_file_vars", {})
                parent_vid = file_path_map.get(norm_parent)
                for other_fvid, varmap in cross_vars.items():
                    if parent_vid is not None and other_fvid == parent_vid:
                        continue  # 跳过 parent 自己
                    for vn, cats in varmap.items():
                        if vn == var_name and cats.get("defined"):
                            candidates.add(other_fvid)
                            break  # 每个文件最多一个

        return list(candidates)

    def _trace_concat_strings(self, vid: int) -> list[str]:
        """递归 trace ast 子节点，提取字符串叶子，返回有序列表。

        用于解析 include 路径拼接，如:
        DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php'
        → ['dvwa/includes/dvwaPage.inc.php']  (跳过常量部分)

        const type=string 的 name 带引号，需要 strip。
        const type=constant 无法静态求值，跳过。
        """
        result: list[str] = []
        for e in self.graph.es.select(_source=vid, label="ast"):
            child_vid = e.target
            child = self.graph.vs[child_vid]
            child_label = _vattr(child, "label", "")
            child_type = _vattr(child, "type", "")
            child_name = _vattr(child, "name", "")

            if child_label == "const" and child_type == "string":
                # name 带引号，如 "'path.php'" → "path.php"
                stripped = child_name.strip("'\"")
                result.append(stripped)
            elif (child_label == NodeLabel.OPERATOR.value
                  and child_type in ("binary_op", "concat")):
                result.extend(self._trace_concat_strings(child_vid))
            # const type=constant / identifier type=variable 等无法静态求值，跳过

        return result

    def _fuzzy_match_file(
        self, partial_path: str, file_path_map: dict[str, int],
    ) -> list[int]:
        """模糊匹配文件路径 — 用 basename 或后缀匹配。

        支持 Ruby/Lua 的 require 'module' 无扩展名模式：
        partial_path='config' 能匹配 'config.rb'（去掉目标文件扩展名后比较）。
        """
        import os
        basename = os.path.basename(partial_path)
        results: list[int] = []
        for fp, vid in file_path_map.items():
            if fp.endswith(basename) or fp.endswith(partial_path):
                results.append(vid)
            else:
                # 无扩展名匹配（Ruby require 'utils' → utils.rb）
                fp_base = os.path.basename(fp)
                dot_idx = fp_base.rfind(".")
                if dot_idx > 0 and fp_base[:dot_idx] == basename:
                    results.append(vid)
        return results[:5]

    # -- 分析步骤 5：内置知识 + 函数摘要传递 ----------------------------------

    def _analyze_builtin_and_summary(self, language: str) -> None:
        """#5: 内置知识 + 函数摘要传递。

        对支持的语言：
        - 检查 builtin_knowledge 中的 passthrough / param_flow 信息
        - 检查 function summary 中的 return_flow.dep_params 信息
        - 创建对应的 dfg 边

        内置知识按语言加载；函数摘要目前仅 PHP 使用。
        """
        # 延迟导入，避免非 Django 环境下的导入错误
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        # 加载该语言的内置知识
        builtin_knowledge = self._load_builtin_knowledge(language)

        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.OPERATOR.value:
                continue
            if _vattr(v, "type") not in call_types:
                continue

            vid = v.index

            # 获取被调用函数名
            callee_name = self._get_callee_name(vid)
            if not callee_name:
                continue

            # 获取调用参数（按 arg_index）
            arg_children = self._get_ast_children_by_arg_index(vid)

            # 先检查内置知识
            if builtin_knowledge and callee_name in builtin_knowledge:
                self._apply_builtin_knowledge(vid, callee_name, arg_children, builtin_knowledge)
            elif language == "php":
                # 再检查函数摘要（仅 PHP）
                self._apply_function_summary(vid, callee_name, arg_children)

    # -- 辅助方法：边写入 -----------------------------------------------------

    def _add_dfg_edge(self, src: int, tgt: int, dfg_type: str) -> None:
        """累积一条 dfg 边（去重检查）。"""
        if src == tgt:
            return
        # 简单去重：检查是否已存在相同的 (src, tgt, dfg_type)
        key = (src, tgt, dfg_type)
        if key not in self._dfg_edges:
            self._dfg_edges.append(key)

    def _apply_dfg_edges(self) -> None:
        """将累积的 dfg 边批量写入 igraph Graph。"""
        if not self._dfg_edges:
            return

        edge_list = [(src, tgt) for src, tgt, _ in self._dfg_edges]
        edge_labels = [EdgeLabel.DFG.value] * len(edge_list)
        edge_types = [dfg_type for _, _, dfg_type in self._dfg_edges]

        self.graph.add_edges(
            edge_list,
            attributes={"label": edge_labels, "type": edge_types},
        )

    # -- 辅助方法：图遍历查询 -------------------------------------------------

    def _get_ast_children(self, vid: int, role: str | None = None) -> list[int]:
        """获取从 vid 出发的 ast 边目标顶点，可按 role 过滤。

        Args:
            vid: 源顶点索引。
            role: 可选，ast 边的 role 属性值。

        Returns:
            目标顶点索引列表。
        """
        result = []
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") != EdgeLabel.AST.value:
                continue
            if role is not None and _vattr(e, "role") != role:
                continue
            result.append(e.target)
        return result

    def _get_ast_children_by_arg_index(self, vid: int) -> dict[int, int]:
        """获取调用节点的所有 arg 子节点，返回 {arg_index: child_vid} 映射。"""
        result: dict[int, int] = {}
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") != EdgeLabel.AST.value:
                continue
            if _vattr(e, "role") != AstRole.ARG.value:
                continue
            arg_index = _vattr(e, "arg_index")
            if arg_index is not None:
                result[int(arg_index)] = e.target
        return result

    def _get_own_children(self, vid: int, index: int | None = None) -> list[int]:
        """获取从 vid 出发的 own 边目标顶点，可按 index 过滤。

        Args:
            vid: 源顶点索引。
            index: 可选，own 边的 index 属性值。

        Returns:
            目标顶点索引列表。
        """
        result = []
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            if index is not None and _vattr(e, "index") != index:
                continue
            result.append(e.target)
        return result

    def _get_own_children_by_index(self, vid: int) -> dict[int, int]:
        """获取函数定义的参数节点，返回 {own_index: child_vid} 映射。

        注意：只返回 label=parameter 的子节点，避免 body stmts 的 own index
        与 parameter index 冲突。
        """
        result: dict[int, int] = {}
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            idx = _vattr(e, "index")
            if idx is not None and idx != "":
                # 只取 parameter 子节点
                target_label = _vattr(self.graph.vs[e.target], "label", "")
                if target_label == NodeLabel.PARAMETER.value:
                    result[int(idx)] = e.target
        return result

    def _get_own_children_by_label(self, vid: int, child_label: str) -> list[int]:
        """获取从 vid 出发的 own 边中指定标签的子顶点。"""
        result = []
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            target_label = _vattr(self.graph.vs[e.target], "label", "")
            if target_label == child_label:
                result.append(e.target)
        return result

    def _has_function_body(self, vid: int) -> bool:
        """检查函数节点是否拥有 own/ast 子节点（真正定义，而非占位节点）。

        与 _get_own_children_by_index 不同，后者只返回带 index 属性的参数子节点；
        本方法检查任意 own/ast 子节点——参数、body 语句、return 节点等。
        这样可正确识别无参函数，以及 own 边缺少 index 属性的函数。
        """
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                return True
        return False

    def _get_cg_target(self, vid: int) -> Optional[int]:
        """获取从调用 operator 出发的 use/callee 边的目标函数顶点。

        Returns:
            函数顶点索引，若无相关边则返回 None。
        """
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") == EdgeLabel.USE.value:
                return e.target
        # JS 等语言用 ast[role=callee] 而非 use 边
        for e in self.graph.es.select(_source=vid, label=EdgeLabel.AST.value):
            if _vattr(e, "role") == "callee":
                return e.target
        return None

    def _get_cg_callers(self, func_vid: int) -> list[int]:
        """获取所有通过 use/callee 边调用 func_vid 的 operator 顶点。

        Returns:
            调用者顶点索引列表。
        """
        result = []
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            if _vattr(e, "label") == EdgeLabel.USE.value:
                result.append(e.source)
        # JS 等语言用 ast[role=callee]
        for e in self.graph.es.select(_target=func_vid, label=EdgeLabel.AST.value):
            if _vattr(e, "role") == "callee":
                result.append(e.source)
        return result

    def _get_edges_by_label(self, label: str) -> list[int]:
        """获取指定标签的所有边 ID。"""
        result = []
        for e in self.graph.es:
            if _vattr(e, "label") == label:
                result.append(e.index)
        return result

    def _get_scope_parent(self, vid: int) -> int | None:
        """沿 own/ast 边向上找到最近的 function/file 作用域节点。

        identifier 节点通常通过 ast 边挂在 operator 下，operator 再通过 own
        边挂在 function/file 下，因此需要同时遍历 own 和 ast 两种边。

        Args:
            vid: 任意节点的索引。

        Returns:
            作用域节点的索引（function 或 file），或 None。
        """
        cur = vid
        seen: set[int] = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            label = _vattr(self.graph.vs[cur], "label", "")
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return cur
            # 优先沿 own 边向上（operator → function/file）
            inc_own = self.graph.es.select(_target=cur, label="own")
            if inc_own:
                cur = inc_own[0].source
            else:
                # 回退：沿 ast 边向上（identifier → operator）
                inc_ast = self.graph.es.select(_target=cur, label="ast")
                cur = inc_ast[0].source if inc_ast else None
        # Fallback: if no scope found via edges, use file node from path
        node_path = _vattr(self.graph.vs[vid], "path", "")
        if node_path:
            for v in self.graph.vs.select(label=NodeLabel.FILE.value):
                if _vattr(v, "path", "") == node_path:
                    return v.index
        return None

    def _get_callee_name(self, vid: int) -> str:
        """获取调用 operator 的被调用函数名。

        优先从 ast[callee] 子节点获取 name，
        若无可尝试从 operator 的 name 属性获取。
        """
        callee_children = self._get_ast_children(vid, role=AstRole.CALLEE.value)
        if callee_children:
            return _vattr(self.graph.vs[callee_children[0]], "name", "")
        # 回退：operator 节点的 name 属性
        return _vattr(self.graph.vs[vid], "name", "")

    def _resolve_function(self, func_vid: int) -> int:
        """尝试将函数节点/identifier callee 解析到真正的定义。

        优先使用 fullname 精确匹配；fullname 无匹配时，仅在同作用域内
        用短名匹配，不做全局短名回退。

        Args:
            func_vid: 函数节点或 identifier callee 节点索引。

        Returns:
            解析后的函数定义节点索引。若无法解析，返回原始 func_vid。
        """
        # 检查是否已有 own 子节点（有则已经是真正的定义）
        if self._has_function_body(func_vid):
            return func_vid

        node = self.graph.vs[func_vid]
        func_fullname = _vattr(node, "fullname", "")
        func_name = _vattr(node, "name", "")

        # 查找 func_vid 所在的父作用域
        parent_vid = None
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            elabel = _vattr(e, "label")
            if elabel in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                parent_vid = e.source
                break

        # 优先 fullname 精确匹配
        if func_fullname:
            candidates = self._func_fullname_index.get(func_fullname, [])
            for vid in candidates:
                if vid != func_vid and self._has_function_body(vid):
                    return vid

        # fullname 无匹配时，仅在同作用域内用短名匹配（不做全局回退）
        if func_name:
            candidates = self._func_name_index.get(func_name, [])
            if parent_vid is not None:
                for vid in candidates:
                    if vid != func_vid and self._has_function_body(vid):
                        for eid2 in self.graph.incident(vid, mode="in"):
                            e2 = self.graph.es[eid2]
                            if _vattr(e2, "label") in (
                                EdgeLabel.OWN.value, EdgeLabel.AST.value
                            ) and e2.source == parent_vid:
                                return vid

        return func_vid

    def _find_assign_lhs_for_callee(self, caller_vid: int) -> Optional[int]:
        """找到调用 operator 作为某个赋值语句 RHS 时的 LHS 顶点。

        场景：$result = foo($x)
        - assign operator → ast[rhs] → call operator (caller_vid)
        - assign operator → ast[lhs] → $result identifier

        我们需要找到包含 caller_vid 作为 rhs 子节点的 assign 节点的 lhs。

        Returns:
            LHS 顶点索引，若无则返回 None。
        """
        # 查找 incoming ast 边：caller_vid 是某个 operator 的 rhs
        for eid in self.graph.incident(caller_vid, mode="in"):
            e = self.graph.es[eid]
            if _vattr(e, "label") != EdgeLabel.AST.value:
                continue
            if _vattr(e, "role") != AstRole.RHS.value:
                continue

            # e.source 是父节点（assign operator）
            parent_vid = e.source
            parent_label = _vattr(self.graph.vs[parent_vid], "label", "")
            parent_type = _vattr(self.graph.vs[parent_vid], "type", "")

            if parent_label == NodeLabel.OPERATOR.value and parent_type == OperatorType.ASSIGN.value:
                # 获取该 assign 的 lhs
                lhs_nodes = self._get_ast_children(parent_vid, role=AstRole.LHS.value)
                if lhs_nodes:
                    return lhs_nodes[0]

        return None

    # -- 辅助方法：内置知识与函数摘要 -----------------------------------------

    def _load_builtin_knowledge(self, language: str) -> Optional[dict]:
        """加载指定语言的内置知识库。

        Args:
            language: 语言标识（如 "php"、"c"）。

        Returns:
            内置知识字典，若无对应语言或导入失败返回 None。
        """
        try:
            if language == "php":
                from core.core_engine.php.builtin_knowledge import KNOWLEDGE as PHP_BUILTIN_KNOWLEDGE
                return PHP_BUILTIN_KNOWLEDGE
            elif language == "c":
                from core.graph.normalizers.c.builtin_knowledge import C_BUILTIN_KNOWLEDGE
                return C_BUILTIN_KNOWLEDGE
        except ImportError:
            return None
        return None

    def _apply_builtin_knowledge(
        self,
        vid: int,
        callee_name: str,
        arg_children: dict[int, int],
        knowledge: dict,
    ) -> None:
        """根据内置知识的 passthrough / param_flow 创建 dfg 边。

        Args:
            vid: 调用 operator 顶点索引。
            callee_name: 被调函数名。
            arg_children: {arg_index: arg_vid} 参数映射。
            knowledge: KNOWLEDGE 字典。
        """
        entry = knowledge.get(callee_name, {})
        if not isinstance(entry, dict):
            return

        # passthrough: 返回值依赖哪些参数 → arg → operator（代表返回值）
        passthrough = entry.get("passthrough", [])
        if isinstance(passthrough, list):
            for param_idx in passthrough:
                arg_vid = arg_children.get(param_idx)
                if arg_vid is not None:
                    self._add_dfg_edge(
                        arg_vid, vid, DfgType.FORWARD_SLICE.value
                    )

        # param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引或列表}
        param_flow = entry.get("param_flow", {})
        if isinstance(param_flow, dict):
            for output_idx_str, input_idx in param_flow.items():
                try:
                    output_idx = int(output_idx_str)
                    # input_idx 可以是 int（单参数）或 list/tuple（多参数合并）
                    if isinstance(input_idx, (list, tuple)):
                        input_vids = [arg_children.get(int(i)) for i in input_idx]
                    else:
                        input_vids = [arg_children.get(int(input_idx))]
                    output_vid = arg_children.get(output_idx)
                    if output_vid is None:
                        continue
                    for input_vid in input_vids:
                        if input_vid is not None and input_vid != output_vid:
                            self._add_dfg_edge(
                                input_vid, output_vid, DfgType.FORWARD_SLICE.value
                            )
                except (ValueError, TypeError):
                    continue

    def _apply_function_summary(
        self,
        vid: int,
        callee_name: str,
        arg_children: dict[int, int],
    ) -> None:
        """根据函数摘要的 return_flow.dep_params 创建 dfg 边。

        Args:
            vid: 调用 operator 顶点索引。
            callee_name: 被调函数名。
            arg_children: {arg_index: arg_vid} 参数映射。
        """
        try:
            from core.core_engine.php.summary_generator import lookup_summary
        except ImportError:
            return

        summary = lookup_summary(callee_name)
        if summary is None:
            return

        # 遍历所有 return_flow 条目，提取 dep_params
        for flow_item in summary.return_flow:
            dep_params = getattr(flow_item, "dep_params", [])
            if not dep_params:
                continue

            # 对 dep_params 中的每个参数位置，创建 arg → operator 的 dfg 边
            for param_idx in dep_params:
                arg_vid = arg_children.get(param_idx)
                if arg_vid is not None:
                    self._add_dfg_edge(
                        arg_vid, vid, DfgType.FORWARD_SLICE.value
                    )
