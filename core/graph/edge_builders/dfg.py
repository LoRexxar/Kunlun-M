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

    # -- 公共接口 ------------------------------------------------------------

    def build(self, graph: "ig.Graph", language: str = "php", **kwargs) -> int:
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

        # 依次执行各分析步骤
        self._analyze_operator_flows()
        self._analyze_method_receiver_flows()
        self._analyze_assignments()
        self._analyze_parameter_passing()
        self._analyze_return_values()
        # NOTE: builtin_and_summary (step 5) must run BEFORE same_variables
        # (step 4) so that param_flow DFG edges (e.g. snprintf output params)
        # are already accumulated in _dfg_edges when same_variables checks
        # for DFG incoming edges on output param identifiers.
        self._analyze_builtin_and_summary(language)
        self._analyze_same_variables()

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

            # 在 parent 的 own/ast 直接子节点中查找同名 parameter/identifier
            for eid in self.graph.incident(parent_vid, mode="out"):
                e = self.graph.es[eid]
                if _vattr(e, "label") not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
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

            if receiver_vid is None:
                continue

            self._add_dfg_edge(receiver_vid, vid, DfgType.FORWARD_SLICE.value)

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

        若 func_vid 对应的节点没有 own 子节点（占位/identifier callee），
        则在图中搜索同名且有 own 子节点的 function 节点。

        Args:
            func_vid: 函数节点或 identifier callee 节点索引。

        Returns:
            解析后的函数定义节点索引。若无法解析，返回原始 func_vid。
        """
        # 检查是否已有 own 子节点（有则已经是真正的定义）
        if self._has_function_body(func_vid):
            return func_vid

        func_name = _vattr(self.graph.vs[func_vid], "name", "")
        if not func_name:
            return func_vid

        # 通过同名匹配找真正的函数定义（支持 function 和 identifier callee）
        # 查找 func_vid 所在的文件/函数作用域（用于优先同作用域匹配）
        parent_vid = None
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            elabel = _vattr(e, "label")
            if elabel == EdgeLabel.OWN.value or elabel == EdgeLabel.AST.value:
                parent_vid = e.source
                break

        best_match = func_vid  # 默认返回自身
        first_global = None  # 记录第一个全局匹配（用于 parent 不匹配时回退）
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.FUNCTION.value:
                continue
            if v.index == func_vid:
                continue
            if _vattr(v, "name") != func_name:
                continue

            if self._has_function_body(v.index):
                if first_global is None:
                    first_global = v.index
                # 优先选择同文件/同作用域的
                if parent_vid is not None:
                    for eid2 in self.graph.incident(v.index, mode="in"):
                        e2 = self.graph.es[eid2]
                        if _vattr(e2, "label") in (EdgeLabel.OWN.value, EdgeLabel.AST.value) and e2.source == parent_vid:
                            best_match = v.index
                            break
                    if best_match != func_vid:
                        break
                else:
                    best_match = v.index
                    break

        # 同作用域未匹配到，回退到全局匹配
        if best_match == func_vid and first_global is not None:
            best_match = first_global

        return best_match

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
