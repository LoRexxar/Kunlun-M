"""数据流分析器 — 在已构建的 AST 图上生成 dfg 边。

纯结构化分析器，不执行任何漏洞判定或可控性检查。
基于 igraph Graph 中已有的 ast/own/cg 边，推导出 5 类数据流（dfg）边：

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

from core.graph.node_edge_schema import (
    AstRole, CgCallType, CrgType, DfgType, EdgeLabel, NodeLabel, OperatorType,
)
from utils.igraph_compat import _vattr

__all__ = ["DataFlowAnalyzer"]


# ---------------------------------------------------------------------------
# DataFlowAnalyzer
# ---------------------------------------------------------------------------

class DataFlowAnalyzer:
    """在已构建的 AST 图上生成 dfg 边。

    接收一个已完成 ast/own/cg 边构建的 igraph Graph，
    通过结构化分析推导数据流关系，批量添加 dfg 边。

    用法::

        analyzer = DataFlowAnalyzer(graph)
        analyzer.analyze(language="php")
    """

    def __init__(self, graph: "ig.Graph") -> None:
        """初始化数据流分析器。

        Args:
            graph: 已包含 ast/own/cg 等边的 igraph 有向图。
        """
        self.graph = graph
        self._dfg_edges: list[tuple[int, int, str]] = []  # (src, tgt, dfg_type)

    # -- 公共接口 ------------------------------------------------------------

    def analyze(self, language: str = "php") -> int:
        """主入口：生成所有 dfg 边并添加到图中。

        执行顺序：
            1. 赋值传播
            2. 参数传递
            3. 返回值传播
            4. 同名变量链接
            5. 内置知识 + 函数摘要传递
            6. 批量写入 dfg 边

        Args:
            language: 目标语言标识，目前仅 ``php`` 支持内置知识。

        Returns:
            新增的 dfg 边数量。
        """
        if self.graph.vcount() == 0:
            return 0

        # 依次执行各分析步骤
        self._analyze_assignments()
        self._analyze_parameter_passing()
        self._analyze_return_values()
        self._analyze_same_variables()
        self._analyze_builtin_and_summary(language)

        # 批量写入
        self._apply_dfg_edges()

        return len(self._dfg_edges)

    # -- 分析步骤 1：赋值传播 -------------------------------------------------

    def _analyze_assignments(self) -> None:
        """#1: 赋值传播 — 为每个 assign/aug_assign 创建 dfg 边。

        规则：
        - 找到 operator(type=assign) 的 RHS 子节点（ast[role=rhs]）
        - 找到 operator(type=assign) 的 LHS 子节点（ast[role=lhs]）
        - 若 RHS 是 identifier/operator → 创建 dfg(RHS → LHS)
        - aug_assign 同理
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

    # -- 分析步骤 2：参数传递 -------------------------------------------------

    def _analyze_parameter_passing(self) -> None:
        """#2: 参数传递 — 将调用参数与函数定义参数关联。

        规则：
        - 找到 operator(type=call/static_call/method_call) 的 cg 目标（函数节点）
        - 若 cg 目标是占位节点（无 own 子节点），尝试通过同名解析到真正的函数定义
        - 调用者的 ast[arg, arg_index=N] 对应函数定义的 own[index=N] 参数
        - 创建 dfg(arg_identifier → parameter)
        - 若无 cg 目标（外部函数），则跳过
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

            # 通过 cg 边找到函数节点
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
        - 通过 cg 边找到函数节点，再解析到真正的函数定义
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

            # 通过 cg 边找到函数节点，并解析到真正的定义
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
        """#4: 同名变量链接 — 在同一作用域内链接同名变量。

        规则：
        - 在同一函数/文件作用域下（通过 own 边的公共父节点）
        - 收集所有 identifier 节点（包括嵌套在 operator ast 子树中的）
        - 按 name 分组，组内按 lineno 排序，创建 dfg(same) 边（低行号 → 高行号）
        """
        # 收集作用域 → identifier 映射
        # scope: (parent_vid, parent_label)
        scope_vars: dict[tuple[int, str], dict[str, list[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

        # 遍历所有 identifier 节点，确定其所属作用域
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.IDENTIFIER.value:
                continue
            vname = _vattr(v, "name", "")
            if not vname:
                continue
            # 沿 own 边向上找到最近的 function/file 作用域
            scope_vid = self._get_scope_parent(v.index)
            if scope_vid is None:
                continue
            scope_label = _vattr(self.graph.vs[scope_vid], "label", "")
            scope_vars[(scope_vid, scope_label)][vname].append(v.index)

        # 对每个作用域中同名的 identifier 组，按 lineno 排序后建边
        for scope_key, name_groups in scope_vars.items():
            for name, vids in name_groups.items():
                if len(vids) < 2:
                    continue

                # 按 lineno 排序
                vids_sorted = sorted(vids, key=lambda vid: _vattr(self.graph.vs[vid], "lineno", 0))

                # 创建 dfg(same) 边：低行号 → 高行号
                for i in range(len(vids_sorted) - 1):
                    self._add_dfg_edge(
                        vids_sorted[i], vids_sorted[i + 1], DfgType.SAME.value
                    )

    # -- 分析步骤 5：内置知识 + 函数摘要传递 ----------------------------------

    def _analyze_builtin_and_summary(self, language: str) -> None:
        """#5: 内置知识 + 函数摘要传递。

        对 PHP 语言：
        - 检查 builtin_knowledge 中的 passthrough / param_flow 信息
        - 检查 function summary 中的 return_flow.dep_params 信息
        - 创建对应的 dfg 边

        其他语言：跳过此步骤。
        """
        if language != "php":
            return

        # 延迟导入，避免非 Django 环境下的导入错误
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        # 加载 PHP 内置知识
        builtin_knowledge = self._load_builtin_knowledge()

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
            else:
                # 再检查函数摘要
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
            if _vattr(e, "label") != EdgeLabel.OWN.value:
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
            if _vattr(e, "label") != EdgeLabel.OWN.value:
                continue
            idx = _vattr(e, "index")
            if idx is not None:
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
            if _vattr(e, "label") != EdgeLabel.OWN.value:
                continue
            target_label = _vattr(self.graph.vs[e.target], "label", "")
            if target_label == child_label:
                result.append(e.target)
        return result

    def _get_cg_target(self, vid: int) -> Optional[int]:
        """获取从调用 operator 出发的 cg 边的目标函数顶点。

        Returns:
            函数顶点索引，若无 cg 边则返回 None。
        """
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if _vattr(e, "label") == EdgeLabel.CG.value:
                return e.target
        return None

    def _get_cg_callers(self, func_vid: int) -> list[int]:
        """获取所有通过 cg 边调用 func_vid 的 operator 顶点。

        Returns:
            调用者顶点索引列表。
        """
        result = []
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            if _vattr(e, "label") == EdgeLabel.CG.value:
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
        """尝试将函数节点解析到真正的定义。

        若 func_vid 对应的 function 节点没有 own 子节点（即占位节点/外部函数），
        则在图中搜索同名且有 own 子节点的 function 节点。

        Args:
            func_vid: 函数节点索引。

        Returns:
            解析后的函数定义节点索引。若无法解析，返回原始 func_vid。
        """
        # 检查是否已有 own 子节点（有则已经是真正的定义）
        own_children = self._get_own_children_by_index(func_vid)
        if own_children:
            return func_vid

        # 占位节点：通过同名匹配找到真正的函数定义
        func_name = _vattr(self.graph.vs[func_vid], "name", "")
        if not func_name:
            return func_vid

        # 同一文件作用域下找同名函数定义
        # 通过 incoming own 边找到 func_vid 所在的文件节点
        parent_vid = None
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            if _vattr(e, "label") == EdgeLabel.OWN.value:
                parent_vid = e.source
                break

        # 在同一 parent 下找同名且有 own 子节点的 function
        best_match = func_vid  # 默认返回自身
        for v in self.graph.vs:
            if _vattr(v, "label") != NodeLabel.FUNCTION.value:
                continue
            if v.index == func_vid:
                continue
            if _vattr(v, "name") != func_name:
                continue

            # 检查是否有 own 子节点（真正有函数体）
            if self._get_own_children_by_index(v.index):
                # 优先选择同文件的
                if parent_vid is not None:
                    for eid2 in self.graph.incident(v.index, mode="in"):
                        e2 = self.graph.es[eid2]
                        if _vattr(e2, "label") == EdgeLabel.OWN.value and e2.source == parent_vid:
                            best_match = v.index
                            break
                    if best_match != func_vid:
                        break
                else:
                    best_match = v.index
                    break

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

    def _load_builtin_knowledge(self) -> Optional[dict]:
        """延迟加载 PHP 内置知识库。"""
        try:
            from core.core_engine.php.builtin_knowledge import KNOWLEDGE as PHP_BUILTIN_KNOWLEDGE
            return PHP_BUILTIN_KNOWLEDGE
        except ImportError:
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

        # param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引}
        param_flow = entry.get("param_flow", {})
        if isinstance(param_flow, dict):
            for output_idx_str, input_idx in param_flow.items():
                try:
                    output_idx = int(output_idx_str)
                    input_vid = arg_children.get(int(input_idx))
                    output_vid = arg_children.get(output_idx)
                    if input_vid is not None and output_vid is not None and input_vid != output_vid:
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
