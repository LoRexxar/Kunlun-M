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

logger = logging.getLogger("KunlunLog")

# PHP type casts that sanitize taint by destroying string content.
# Must match graph_analyzer._TYPE_CAST_SAFE — when the DFG builder encounters
# one of these as an assign RHS, it must NOT pierce through the cast node.
# Keeping the cast as the RHS lets the BFS trace in graph_analyzer see the
# TYPE_CAST node and stop taint propagation.
_DFG_TYPE_CAST_SAFE: frozenset[str] = frozenset({
    "int", "integer", "float", "double", "real",
    "bool", "boolean", "array", "object",
})

# Call operator types that represent function/method invocations.
_CALL_TYPES_DFG: frozenset[str] = frozenset({
    "call", "method_call", "static_call", "new",
})

# NOTE: Safe-callee detection for assignment RHS is now delegated to the
# per-language builtin_knowledge system.  When an assignment RHS is a call
# whose callee is marked {"safe": True} in builtin_knowledge, no DFG edge
# is created.  This avoids hard-coding function names in this module —
# new framework sanitizers are added to the appropriate builtin_knowledge.py.


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
        self._dfg_edges: set[tuple[int, int, str]] = set()  # (src, tgt, dfg_type)
        # _dfg_edges 的 target 索引，O(1) 查某个 vid 是否是某条 dfg 边的 target
        self._dfg_tgt_set: set[int] = set()
        # 函数名→vid列表索引（build() 中预构建，用于 _resolve_function O(1) 查找）
        self._func_name_index: dict[str, list[int]] = {}
        self._func_fullname_index: dict[str, list[int]] = {}
        # 边索引：预构建以替代 es.select() 的 O(E) 遍历
        self._edge_src_idx: dict[tuple[str, int], list[int]] = {}  # (label, src_vid) → [tgt_vids]
        self._edge_tgt_idx: dict[tuple[str, int], list[int]] = {}  # (label, tgt_vid) → [src_vids]

    # -- 边索引查询 helpers (O(1) 替代 es.select 的 O(E)) ------------------

    def _edges_from(self, src_vid: int, label: str) -> list[int]:
        """返回从 src_vid 出发的、标签为 label 的边的目标 vid 列表。"""
        return self._edge_src_idx.get((label, src_vid), [])

    def _edges_to(self, tgt_vid: int, label: str) -> list[int]:
        """返回指向 tgt_vid 的、标签为 label 的边的源 vid 列表。"""
        return self._edge_tgt_idx.get((label, tgt_vid), [])

    def _has_edge_from(self, src_vid: int, label: str) -> bool:
        """快速判断 src_vid 是否有标签为 label 的出边。"""
        return (label, src_vid) in self._edge_src_idx

    def _has_edge_to(self, tgt_vid: int, label: str) -> bool:
        """快速判断 tgt_vid 是否有标签为 label 的入边。"""
        return (label, tgt_vid) in self._edge_tgt_idx

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
        self._dfg_edges = set()
        self._dfg_tgt_set = set()

        if self.graph.vcount() == 0:
            return 0

        # 预缓存属性数组 — O(V+E) 构建，O(1) 查询 ──
        self._language = language  # saved for _is_safe_callee lookups
        # 预缓存边属性数组
        ec = self.graph.ecount()
        self._elabel = [''] * ec
        self._erole = [''] * ec
        self._earg_index = [None] * ec
        self._eindex_attr = [''] * ec
        for e in self.graph.es:
            ei = e.index
            self._elabel[ei] = e['label'] or ''
            self._erole[ei] = e['role'] or ''
            try:
                self._earg_index[ei] = e['arg_index']
            except KeyError:
                self._earg_index[ei] = None
            self._eindex_attr[ei] = e['index'] or ''

        # 预缓存顶点属性数组
        vc = self.graph.vcount()
        self._vlabel = [''] * vc
        self._vtype = [''] * vc
        self._vname = [''] * vc
        self._vpath = [''] * vc
        self._vfile_path = [''] * vc
        self._vlineno = [0] * vc
        self._vfullname = [''] * vc
        self._vlocation = [''] * vc
        self._vraw_type = [''] * vc
        self._vsource = [''] * vc
        from utils.igraph_compat import _vattr
        for v in self.graph.vs:
            vi = v.index
            self._vlabel[vi] = _vattr(v, 'label', '')
            self._vtype[vi] = _vattr(v, 'type', '')
            self._vname[vi] = _vattr(v, 'name', '')
            self._vpath[vi] = _vattr(v, 'path', '')
            self._vfile_path[vi] = _vattr(v, 'file_path', '')
            self._vlineno[vi] = _vattr(v, 'lineno', 0) or 0
            self._vfullname[vi] = _vattr(v, 'fullname', '')
            self._vlocation[vi] = _vattr(v, 'location', '')
            self._vraw_type[vi] = _vattr(v, 'raw_type', '')
            self._vsource[vi] = _vattr(v, 'source', '')

        # 预构建边索引：O(E) 一次遍历，替代后续所有 es.select() 的 O(E) 逐次查询
        self._edge_src_idx = defaultdict(list)
        self._edge_tgt_idx = defaultdict(list)
        for e in self.graph.es:
            elabel = self._elabel[e.index]
            self._edge_src_idx[(elabel, e.source)].append(e.target)
            self._edge_tgt_idx[(elabel, e.target)].append(e.source)
        # 转为普通 dict 避免 defaultdict 开销
        self._edge_src_idx = dict(self._edge_src_idx)
        self._edge_tgt_idx = dict(self._edge_tgt_idx)

        # ast 边 role 索引：(src_vid, role) → [tgt_vids]
        # 替代 es.select(_source=vid, label=AST, role=...) 的 O(E) 查询
        self._ast_role_from: dict[tuple[int, str], list[int]] = {}
        for e in self.graph.es:
            if self._elabel[e.index] == EdgeLabel.AST.value:
                role = self._erole[e.index]
                if role:
                    key = (e.source, role)
                    if key not in self._ast_role_from:
                        self._ast_role_from[key] = []
                    self._ast_role_from[key].append(e.target)

        # 节点标签索引：label → [vids]，替代 vs.select(label=...) 的 O(V) 遍历
        self._node_label_idx: dict[str, list[int]] = {}
        for v in self.graph.vs:
            vlabel = self._vlabel[v.index]
            if vlabel:
                self._node_label_idx.setdefault(vlabel, []).append(v.index)

        # (name, label) → [vids] 索引，替代 vs.select(label=X, name=Y) 的 O(V) 查询
        self._name_label_idx: dict[tuple[str, str], list[int]] = {}
        for v in self.graph.vs:
            vlabel = self._vlabel[v.index]
            vname = self._vname[v.index]
            if vlabel and vname:
                self._name_label_idx.setdefault((vname, vlabel), []).append(v.index)

        # path → file vid 索引，替代 _get_scope_parent fallback 中 vs.select 的 O(V) 遍历
        self._path_to_file_vid: dict[str, int] = {}
        for vid in self._node_label_idx.get(NodeLabel.FILE.value, []):
            path = self._vpath[vid]
            if path:
                self._path_to_file_vid[path] = vid

        # 预构建函数名索引：name → [vid1, vid2, ...]
        # 避免在 _resolve_function 中对每个函数调用做 O(V) 全图遍历
        self._func_name_index = {}
        self._func_fullname_index = {}
        for v in self.graph.vs:
            if self._vlabel[v.index] != NodeLabel.FUNCTION.value:
                continue
            # fullname 索引（精确匹配）
            fullname = self._vfullname[v.index]
            if fullname:
                self._func_fullname_index.setdefault(fullname, []).append(v.index)
            # 短名索引（仅用于无 fullname 的局部函数）
            fname = self._vname[v.index]
            if fname and not fullname:
                self._func_name_index.setdefault(fname, []).append(v.index)

        # 依次执行各分析步骤（分两阶段）
        # Phase 1: 不依赖 use 边的分析步骤
        # Phase 2: 依赖 use 边的分析步骤（参数传递、返回值传播、fluent API）
        if phase == 1:
            self._analyze_operator_flows()
            self._analyze_method_receiver_flows()
            self._analyze_chained_call_returns()
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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in expr_types:
                continue

            vid = v.index
            # 获取所有 ast 子节点（操作数）
            for child_vid in self._edges_from(vid, EdgeLabel.AST.value):
                child_label = self._vlabel[child_vid]
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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
                continue
            vid = v.index
            for child_vid in self._ast_role_from.get((vid, AstRole.ARG.value), []):
                child_label = self._vlabel[child_vid]
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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
                continue

            vid = v.index

            # 1. 优先沿 callee member 边链回溯 receiver（JS/Go member expression chain）
            #    call --[ast/callee]--> callee_member <--[member]-- chain <--[member]-- identifier
            receiver_vid = None
            for eid in self.graph.incident(vid, mode="out"):
                e = self.graph.es[eid]
                if self._elabel[e.index] != EdgeLabel.AST.value:
                    continue
                if self._erole[e.index] != "callee":
                    continue
                callee_vid = e.target
                current = callee_vid
                visited_chain = {current}
                while True:
                    member_found = False
                    for eid2 in self.graph.incident(current, mode="in"):
                        e2 = self.graph.es[eid2]
                        if self._elabel[e2.index] == EdgeLabel.MEMBER.value:
                            member_source = e2.source
                            if member_source not in visited_chain:
                                visited_chain.add(member_source)
                                src_label = self._vlabel[member_source]
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
            name = self._vname[v.index] or ""
            dot_pos = name.find(".")
            if dot_pos <= 0:
                continue
            receiver_name = name[:dot_pos]

            # 通过 own 边向上找到 parent function/file
            parent_vid = None
            for eid in self.graph.incident(vid, mode="in"):
                e = self.graph.es[eid]
                if self._elabel[e.index] in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
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
                    if self._elabel[e.index] not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                        continue
                    ancestor_vid = e.source
                    if ancestor_vid in visited_scopes:
                        continue
                    ancestor_label = self._vlabel[ancestor_vid]
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
                    if self._elabel[e.index] not in (
                        EdgeLabel.OWN.value, EdgeLabel.AST.value
                    ):
                        continue
                    child = self.graph.vs[e.target]
                    child_name = self._vname[child.index] or ""
                    child_label = self._vlabel[child.index]
                    if child_name == receiver_name and child_label in (
                        NodeLabel.PARAMETER.value,
                        NodeLabel.IDENTIFIER.value,
                    ):
                        receiver_vid = e.target
                        break
                    # 搜索 assign/var 子节点的 lhs identifier
                    # （如 var template = new Template(...) → template 在
                    # assign 的 lhs 中而非 function 的直接子节点）
                    if child_label == NodeLabel.OPERATOR.value and self._vtype[child.index] == OperatorType.ASSIGN.value:
                        lhs_nodes = self._get_ast_children(
                            e.target, role=AstRole.LHS.value
                        )
                        for lhs_vid in lhs_nodes:
                            lhs_v = self.graph.vs[lhs_vid]
                            if self._vname[lhs_v.index] == receiver_name:
                                receiver_vid = lhs_vid
                                break
                        if receiver_vid is not None:
                            break
                if receiver_vid is not None:
                    break

            if receiver_vid is None:
                continue

            self._add_dfg_edge(receiver_vid, vid, DfgType.FORWARD_SLICE.value)

    def _analyze_chained_call_returns(self) -> None:
        """#0c: Chained call returns — inner call → outer call DFG.

        For method chaining (e.g., Rust `env::var("X").unwrap()` or
        JS `obj.method1().method2()`), the inner call's return value is
        implicitly the receiver/argument of the outer call. We add a
        DFG edge from inner call operator to outer call operator.

        Detection: a call operator has an AST child that is also a
        call operator (reached via callee chain: outer --[ast/callee]-->
        callee_id --[ast]--> inner_call_operator).
        """
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        # Collect all call operator vids
        call_vids = set()
        for v in self.graph.vs:
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] in call_types:
                call_vids.add(v.index)

        for vid in call_vids:
            # Walk AST children to find any child that is also a call operator
            # The inner call may be nested: outer --[ast/callee]--> callee_id --[ast]--> inner_call
            for child_vid in self._edges_from(vid, EdgeLabel.AST.value):
                child_label = self._vlabel[child_vid]
                child_type = self._vtype[child_vid]

                # Direct: ast child is itself a call operator
                if child_label == NodeLabel.OPERATOR.value and child_type in call_types:
                    self._add_dfg_edge(
                        child_vid, vid, DfgType.FORWARD_SLICE.value
                    )
                    continue

                # Indirect: ast child is an identifier/qualified_id that points to
                # a call operator via its own ast children
                if child_label in (NodeLabel.IDENTIFIER.value, NodeLabel.OPERATOR.value):
                    for inner_vid in self._edges_from(child_vid, EdgeLabel.AST.value):
                        inner_label = self._vlabel[inner_vid]
                        inner_type = self._vtype[inner_vid]
                        if (inner_label == NodeLabel.OPERATOR.value
                                and inner_type in call_types
                                and inner_vid != vid):
                            self._add_dfg_edge(
                                inner_vid, vid, DfgType.FORWARD_SLICE.value
                            )
                            break

    def _analyze_member_access_flows(self) -> None:
        """#0c: member access chain — 创建 identifier(receiver) → identifier(property) 的 DFG 边。

        对于 member 边 (receiver --member--> property)，当 property 是 identifier 且
        receiver 也是 identifier 时，创建 DFG 边使 parameters_back 能沿 member chain 追溯。

        例: request.args → identifier(request) --dfg--> identifier(args)
        例: request.data → identifier(request) --dfg--> identifier(data)

        注意: self/this/$this 的字段访问不创建 DFG 边。
        对象字段 (self._pattern vs self._host) 是独立的，整体传播会导致
        field-insensitivity 误报（如 aiohttp self._pattern 被误判为
        受 self._host = request.headers 污染）。
        """
        # self/this 变量名集合（各语言）
        self_names = {"self", "this", "$this", "Me", "@me"}

        for (elabel, src_vid), tgt_vids in self._edge_src_idx.items():
            if elabel != EdgeLabel.MEMBER.value:
                continue
            for tgt_vid in tgt_vids:
                src_label = self._vlabel[src_vid]
                tgt_label = self._vlabel[tgt_vid]
                if (src_label == NodeLabel.IDENTIFIER.value
                        and tgt_label == NodeLabel.IDENTIFIER.value):
                    # Skip self/this member access — field insensitivity
                    # causes FP when one field is tainted from user input
                    # and another field is read in a different method.
                    src_name = self._vname[src_vid]
                    if src_name in self_names:
                        continue
                    # Skip array offset member edges ($arr[$key]) —
                    # the subscript value comes from the array, not from
                    # the index key. Creating a DFG edge here would
                    # propagate taint from key to subscript result,
                    # causing FPs like call_user_func($callbacks[$user_input]).
                    edge_idx = self.graph.get_eid(src_vid, tgt_vid, error=False)
                    if edge_idx != -1:
                        at = self.graph.es[edge_idx]["access_type"] or ""
                        if at == "array_offset":
                            continue
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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in assign_types:
                continue

            vid = v.index

            # 获取 LHS 和 RHS 子节点
            lhs_nodes = self._get_ast_children(vid, role=AstRole.LHS.value)
            rhs_nodes = self._get_ast_children(vid, role=AstRole.RHS.value)

            # 变体：rhs 子节点是 identifier 且有 value 子边（JS VariableDeclaration）
            # 此时 rhs 就是 lhs（被声明的变量），value 是赋值来源
            if not lhs_nodes and rhs_nodes:
                rhs_vid = rhs_nodes[0]
                rhs_label = self._vlabel[rhs_vid]
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
                        rlabel = self._vlabel[rvid]
                        rtype = self._vtype[rvid]
                        raw_type = self._vraw_type[rvid]
                        if rlabel == NodeLabel.OPERATOR.value and rtype == OperatorType.TYPE_CAST.value:
                            cast_name = self._vname[rvid] or ""
                            if cast_name in _DFG_TYPE_CAST_SAFE:
                                # Sanitizer cast (e.g. PHP (int), (float)) — do NOT pierce.
                                # Keep the TYPE_CAST node as RHS so graph_analyzer BFS
                                # can detect it and stop taint propagation.
                                continue
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
            lhs_label = self._vlabel[lhs_vid]
            if lhs_label not in (NodeLabel.IDENTIFIER.value, NodeLabel.CONST.value):
                continue

            # RHS 可以是 identifier、const 或 operator（如函数调用）
            rhs_label = self._vlabel[rhs_vid]
            # Check if RHS is a safe/sanitizer function call.
            # If so, do NOT create a DFG edge — the return value is
            # framework-generated, not user-controlled data.
            # Safe-callee detection uses the per-language builtin_knowledge
            # system (same source as enrich_taint and _analyze_builtin_and_summary).
            if rhs_label == NodeLabel.OPERATOR.value:
                rhs_type = self._vtype[rhs_vid]
                if rhs_type in _CALL_TYPES_DFG:
                    callee = self._get_callee_name(rhs_vid)
                    if callee and self._is_safe_callee(callee, self._language):
                        continue  # skip DFG edge
            if rhs_label in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.CONST.value,
                NodeLabel.OPERATOR.value,
            ):
                self._add_dfg_edge(rhs_vid, lhs_vid, DfgType.FORWARD_SLICE.value)

            # TernaryOp (branch type): iftrue/iffalse values flow to LHS.
            # The condition must NOT flow — it controls which branch is taken,
            # but its value does not become the result.
            if rhs_label == NodeLabel.BRANCH.value:
                rhs_type = self._vtype[rhs_vid].lower()
                if rhs_type == "ternary":
                    # Only iftrue/iffalse children (skip condition) dfg to LHS
                    for branch_role in ("iftrue", "iffalse"):
                        for child_vid in self._ast_role_from.get((rhs_vid, branch_role), []):
                            child_label = self._vlabel[child_vid]
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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
                continue

            vid = v.index

            # 通过 use 边找到函数节点
            func_vid = self._get_cg_target(vid)
            if func_vid is None:
                continue

            # 尝试解析到真正的函数定义（占位节点无 own 子节点）
            resolved_vid = self._resolve_function(func_vid)

            # Java overload resolution: if the resolved function's parameter
            # types don't match the call site arg types, try other overloads
            # with the same name in the same file.
            resolved_vid = self._resolve_overload(vid, resolved_vid)

            # 获取该调用的所有 arg 子节点
            arg_children = self._get_ast_children_by_arg_index(vid)

            # 获取函数定义的参数（按 own index）
            param_map = self._get_own_children_by_index(resolved_vid)

            # 对于 method_call，函数定义的第一个参数是 self/this，
            # 但调用参数中不包含 receiver（receiver 通过 member chain 传递）。
            # 因此 arg_index 需要 +1 来对齐函数定义的参数 index。
            is_method_call = self._vtype[vid] == OperatorType.METHOD_CALL.value
            # 检查第一个参数是否是 self/this（确认需要偏移）
            if is_method_call and param_map:
                first_param_vid = param_map.get(0)
                if first_param_vid is not None:
                    first_param_name = self._vname[first_param_vid]
                    if first_param_name in ("self", "this", "$this", "Me"):
                        # 重建偏移后的 param_map
                        param_map = {k + 1: v for k, v in param_map.items()}

            # 匹配 arg_index → parameter own index
            for arg_idx, arg_vid in arg_children.items():
                param_vid = param_map.get(arg_idx)
                if param_vid is not None:
                    # Overload resolution: skip if arg java_type doesn't
                    # match param java_type (e.g. String arg → File param).
                    param_jt = _vattr(self.graph.vs[param_vid], "java_type", "")
                    if param_jt and param_jt not in ("", "Object"):
                        arg_jt = _vattr(self.graph.vs[arg_vid], "java_type", "")
                        if not arg_jt:
                            # Try resolving type from callee (method return type)
                            arg_jt = self._resolve_arg_java_type(arg_vid)
                        if arg_jt and arg_jt not in ("", "Object"):
                            # Check type compatibility (handle autoboxing)
                            if not self._java_type_compatible(arg_jt, param_jt):
                                logger.debug("[DFG] overload skip: arg java_type=%s → param java_type=%s (mismatch)", arg_jt, param_jt)
                                continue  # Skip: type mismatch → wrong overload
                    self._add_dfg_edge(arg_vid, param_vid, DfgType.FORWARD_SLICE.value)

    def _resolve_overload(self, call_vid: int, resolved_vid: int) -> int:
        """Java overload resolution: find the correct overload by matching
        call site argument types to parameter java_type.

        If the resolved function's parameter types don't match the call args,
        search for other same-name overloads in the same file and return the
        best-matching one.
        """
        # Only applicable to Java
        call_lang = _vattr(self.graph.vs[call_vid], "language", "")
        if call_lang != "java":
            return resolved_vid

        # Get call site arg types
        arg_children = self._get_ast_children_by_arg_index(call_vid)
        call_arg_types = []
        for _idx in sorted(arg_children.keys()):
            arg_vid = arg_children[_idx]
            arg_jt = _vattr(self.graph.vs[arg_vid], "java_type", "")
            if not arg_jt:
                arg_jt = self._resolve_arg_java_type(arg_vid)
            call_arg_types.append(arg_jt)

        if not call_arg_types:
            return resolved_vid  # No args → no overload ambiguity

        # Get resolved function's parameter types
        resolved_name = self._vname[resolved_vid]
        resolved_params = self._get_own_children_by_index(resolved_vid)
        param_types = []
        for _idx in sorted(resolved_params.keys()):
            param_jt = _vattr(self.graph.vs[resolved_params[_idx]], "java_type", "")
            param_types.append(param_jt)

        # Check if current resolution matches
        if self._types_match(call_arg_types, param_types):
            return resolved_vid  # Good match, keep it

        # Search for other overloads with the same name
        candidates = self._func_name_index.get(resolved_name, [])
        best_match = resolved_vid
        best_score = 0
        for cand_vid in candidates:
            if cand_vid == resolved_vid:
                continue
            if not self._has_function_body(cand_vid):
                continue
            cand_params = self._get_own_children_by_index(cand_vid)
            # For method calls, skip the self/this param offset
            cand_param_types = []
            for _idx in sorted(cand_params.keys()):
                cand_param_types.append(
                    _vattr(self.graph.vs[cand_params[_idx]], "java_type", ""))
            # Adjust for self/this offset
            if self._vtype[call_vid] == OperatorType.METHOD_CALL.value and cand_params:
                first_pname = self._vname[cand_params.get(0, -1)] if 0 in cand_params else ""
                if first_pname in ("self", "this", "$this", "Me"):
                    cand_param_types = cand_param_types[1:]
            score = self._match_score(call_arg_types, cand_param_types)
            if score > best_score:
                best_score = score
                best_match = cand_vid

        if best_match != resolved_vid:
            logger.debug("[DFG] overload resolved: %s → %s (score=%d)",
                        resolved_name, _vattr(self.graph.vs[best_match], "signature", ""), best_score)
        return best_match

    @staticmethod
    def _types_match(call_types: list[str], param_types: list[str]) -> bool:
        """Check if call arg types are compatible with param types."""
        if len(call_types) != len(param_types):
            return False
        for ct, pt in zip(call_types, param_types):
            if not ct or not pt:
                continue  # Unknown types → assume compatible
            if not DataFlowBuilder._java_type_compatible(ct, pt):
                return False
        return True

    @staticmethod
    def _match_score(call_types: list[str], param_types: list[str]) -> int:
        """Score how well call types match param types (higher = better)."""
        if len(call_types) != len(param_types):
            return 0
        score = 0
        for ct, pt in zip(call_types, param_types):
            if not ct or not pt:
                score += 1  # Unknown → partial match
            elif DataFlowBuilder._java_type_compatible(ct, pt):
                score += 2
            else:
                return 0  # Mismatch → no match
        return score

    def _resolve_arg_java_type(self, arg_vid: int) -> str:
        """Try to determine the java_type of a call argument.

        For method call args (e.g. obj.getMethod()), resolve the return
        type of the callee by following use → function → java_return_type.
        """
        arg_v = self.graph.vs[arg_vid]
        arg_type = _vattr(arg_v, "type", "")
        arg_label = _vattr(arg_v, "label", "")
        # Direct identifier with java_type
        jt = _vattr(arg_v, "java_type", "")
        if jt:
            return jt
        # Method call: resolve return type via use edge
        if arg_label == NodeLabel.OPERATOR.value and arg_type in (
            "call", "method_call", "static_call"
        ):
            for eid in self.graph.incident(arg_vid, mode="out"):
                e = self.graph.es[eid]
                if self._elabel[e.index] == EdgeLabel.USE.value:
                    fv = self.graph.vs[e.target]
                    ret_type = _vattr(fv, "return_type", "") or _vattr(fv, "java_return_type", "")
                    if ret_type:
                        return ret_type
        return ""

    @staticmethod
    def _java_type_compatible(arg_type: str, param_type: str) -> bool:
        """Check if arg java_type is assignment-compatible with param java_type.

        Handles autoboxing (int→Integer) and inheritance for common cases.
        Returns True if compatible (or if either type is unknown/generic).
        """
        if not arg_type or not param_type:
            return True
        if arg_type == param_type:
            return True
        # Autoboxing pairs
        box_pairs = {
            "int": "Integer", "Integer": "int",
            "long": "Long", "Long": "long",
            "boolean": "Boolean", "Boolean": "boolean",
            "char": "Character", "Character": "char",
            "byte": "Byte", "Byte": "byte",
            "short": "Short", "Short": "short",
            "float": "Float", "Float": "float",
            "double": "Double", "Double": "double",
        }
        if box_pairs.get(arg_type) == param_type:
            return True
        # String → char[] or char[] → String is NOT compatible
        # (Java does not auto-convert these)
        string_types = {"String", "java.lang.String"}
        file_types = {"File", "java.io.File"}
        char_array_types = {"char[]", "char[]", "[C"}
        if arg_type in string_types and param_type in file_types:
            return False
        if arg_type in string_types and param_type in char_array_types:
            return False
        if arg_type in file_types and param_type in string_types:
            return False
        if arg_type in char_array_types and param_type in string_types:
            return False
        # Same simple name (ignore package prefix)
        if arg_type.split(".")[-1] == param_type.split(".")[-1]:
            return True
        # Default: allow if we can't determine (avoid false negatives)
        return True

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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
                continue

            caller_vid = v.index

            # Skip functions already handled by builtin_knowledge.
            # When a function has a passthrough/param_flow entry, its
            # arg→return data flow is precisely controlled by step 5
            # (_analyze_builtin_and_summary). Tracing the function body's
            # return statements here would re-introduce taint paths that
            # builtin_knowledge was designed to suppress (e.g. apply_filters
            # where arg0 flows into return via internal variable usage).
            callee_name = self._get_callee_name(caller_vid)
            if callee_name:
                bk = self._load_builtin_knowledge(self._language)
                if bk and callee_name in bk:
                    continue

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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
                continue

            vid = v.index

            # 找到流入此 call 的 DFG receiver 来源
            receiver_vid = None
            for eid in self.graph.incident(vid, mode="in"):
                e = self.graph.es[eid]
                if self._elabel[e.index] != EdgeLabel.DFG.value:
                    continue
                src = self.graph.vs[e.source]
                src_label = self._vlabel[src.index]
                if src_label in (
                    NodeLabel.IDENTIFIER.value,
                    NodeLabel.PARAMETER.value,
                ):
                    # 确认此来源确实是 receiver（同名检查）
                    src_name = self._vname[src.index]
                    op_name = self._vname[v.index]
                    # receiver name 是 op_name 的第一段（如 "cart" in "cart.append"）
                    dot_pos = op_name.find(".")
                    if dot_pos > 0:
                        receiver_name = op_name[:dot_pos]
                        if src_name == receiver_name:
                            receiver_vid = src.index
                            break

            if receiver_vid is None:
                continue

            # 跳过 static field receiver（如 Logger LOGGER）。
            # static field 是类级成员，不参与 fluent API 链。
            # 例: LOGGER.debug(x) — LOGGER 是 static final field，
            #    debug() 是 void 方法，不存在返回值回传语义。
            receiver_type = self._vtype[receiver_vid]
            if receiver_type == 'field':
                continue

            # 检查此 receiver 是否在同作用域内有其他 method_call（多次使用）
            receiver_name = self._vname[receiver_vid]
            other_calls = 0
            for eid2 in self.graph.incident(receiver_vid, mode="out"):
                e2 = self.graph.es[eid2]
                if self._elabel[e2.index] == EdgeLabel.DFG.value:
                    tgt = self.graph.vs[e2.target]
                    if (tgt.index != vid
                            and self._vlabel[tgt.index] == NodeLabel.OPERATOR.value
                            and self._vtype[tgt.index] in call_types):
                        other_calls += 1

            # 只有当 receiver 被多次使用时才回传（避免对单次调用过度传播）
            if other_calls == 0:
                continue

            # 检查是否已有此 DFG 边（避免重复）
            if (vid, receiver_vid) in self._dfg_edges:
                continue

            # 跳过已知的 mutator 方法名 — 这些方法修改对象但不返回 this，
            # 不应创建 fluent API 回传边。
            # 例: trackingCode.set("field", value) — set() 是 void mutator，
            # 不会返回 trackingCode 对象用于链式调用。
            # 创建回传边会导致 field-insensitivity FP：
            # set(field_A, user_input) 的 DFG 回传到 trackingCode，
            # 使 getString(field_B) 的返回值被误判为受污染。
            _MUTATOR_NAMES = frozenset({
                "set", "put", "remove", "clear", "delete",
                "addCookie", "setHeader", "setAttribute",
            })
            callee_short = self._vname[vid]
            dot = callee_short.rfind(".")
            if dot >= 0:
                method_short = callee_short[dot + 1:]
            else:
                method_short = callee_short
            if method_short in _MUTATOR_NAMES:
                continue

            # Skip getter methods (getXxx, isXxx, hasXxx) — these return
            # a property value (String, int, etc.), NOT the receiver object.
            # Creating a call→receiver back-edge for getters causes the
            # getter's return value to pollute the receiver, linking
            # unrelated data flows across method boundaries.
            if (method_short.startswith("get")
                    or method_short.startswith("is")
                    or method_short.startswith("has")):
                continue

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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in assign_types:
                continue
            lhs_nodes = self._get_ast_children(v.index, role=AstRole.LHS.value)
            for lhv in lhs_nodes:
                lhs_label = self._vlabel[lhv]
                if lhs_label in (NodeLabel.IDENTIFIER.value, NodeLabel.CONST.value):
                    assign_lhs_vids.add(lhv)
            # JS VariableDeclarator: rhs 子节点是 identifier，它有 value 子边
            # 此时 rhs identifier 就是声明变量的 LHS
            if not lhs_nodes:
                rhs_nodes = self._get_ast_children(v.index, role=AstRole.RHS.value)
                for rhv in rhs_nodes:
                    if self._vlabel[rhv] == NodeLabel.IDENTIFIER.value:
                        value_nodes = self._get_ast_children(rhv, role="value")
                        if value_nodes:
                            assign_lhs_vids.add(rhv)

        # Parameter 节点是定义端点（类似 assign LHS）
        # 函数参数没有显式的赋值，但同名 identifier/parameter 使用应回溯到它
        for v in self.graph.vs:
            if self._vlabel[v.index] == NodeLabel.PARAMETER.value:
                assign_lhs_vids.add(v.index)

        # C/Go normalizer may label function parameters as "identifier" (not
        # "parameter").  An identifier that is an own-child of a function node
        # with an "ast[value]" edge (initialiser) is a definition site
        # (e.g. C: char *args[] = {...}).  Treat as LHS.
        for v in self.graph.vs:
            if self._vlabel[v.index] != NodeLabel.IDENTIFIER.value:
                continue
            has_own = False
            for own_src in self._edges_to(v.index, "own"):
                parent_label = self._vlabel[own_src]
                if parent_label == NodeLabel.FUNCTION.value:
                    has_own = True
                    break
            if has_own:
                # Only treat as LHS if it has an initialiser (ast[value] edge)
                has_init = bool(self._ast_role_from.get((v.index, "value"), []))
                if has_init:
                    assign_lhs_vids.add(v.index)

        # 收集作用域 → identifier 映射
        scope_vars: dict[tuple[int, str], dict[str, list[int]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for v in self.graph.vs:
            if self._vlabel[v.index] not in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                continue
            vname = self._vname[v.index]
            if not vname:
                continue
            scope_vid = self._get_scope_parent(v.index)
            if scope_vid is None:
                continue
            scope_label = self._vlabel[scope_vid]
            scope_vars[(scope_vid, scope_label)][vname].append(v.index)

        # 对每个作用域中同名 identifier，建立使用→最近LHS 的 same 链
        for scope_key, name_groups in scope_vars.items():
            scope_vid, scope_label = scope_key
            # Skip file-level scope ONLY for identifiers inside functions.
            # Global-scope code (not inside any function) should still get
            # same-name links — e.g. PHP global code:
            #   $id = $_GET['id'];
            #   mysql_query("..." . $id);
            # We filter to keep only identifiers NOT inside any function,
            # to avoid cross-method taint pollution (all 'prefix' params
            # in a 1200-line file getting linked).
            if scope_label == NodeLabel.FILE.value:
                assert self.graph is not None
                global_vids = []
                for vid in sum(name_groups.values(), []):
                    # Check if this identifier is inside a function by
                    # walking up the own-edge chain.
                    in_func = False
                    current = vid
                    for _ in range(10):  # max depth
                        parents = self._edges_to(current, "own")
                        if not parents:
                            break
                        for p in parents:
                            if self._vlabel[p] == NodeLabel.FUNCTION.value:
                                in_func = True
                                break
                        if in_func:
                            break
                        current = parents[0]
                    if not in_func:
                        global_vids.append(vid)
                # Rebuild name_groups with only global identifiers
                new_groups: dict[str, list[int]] = defaultdict(list)
                for vid in global_vids:
                    vn = self._vname[vid]
                    if vn:
                        new_groups[vn].append(vid)
                name_groups = new_groups
                if not name_groups:
                    continue
            for name, vids in name_groups.items():
                if len(vids) < 2:
                    continue
                vids_sorted = sorted(
                    vids, key=lambda vid: self._vlineno[vid]
                )
                # 从每个非 LHS 的 identifier，向前找最近的同名 LHS
                for i, vid in enumerate(vids_sorted):
                    if vid in assign_lhs_vids:
                        continue  # LHS 不向前链接（已有 dfg(RHS→LHS)）
                    # 跳过 array offset index 节点 ($arr[$key] 中的 $key)
                    # — index 是 lookup key，不是 subscript 值。
                    if any(
                        True for eid in self.graph.incident(vid, mode="in")
                        if self.graph.es[eid]["label"] == "member"
                        and (self.graph.es[eid]["access_type"] or "") == "array_offset"
                    ):
                        continue
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
                        has_dfg_in = self._has_edge_to(target_vid, "dfg") \
                            or target_vid in self._dfg_tgt_set
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
                        if self._vlabel[vids_sorted[j]] == NodeLabel.PARAMETER.value:
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
        # 预收集全图 assign LHS（提到循环外，避免每个 function 重复扫描）
        assign_lhs_vids: set[int] = set()
        for vid in self._node_label_idx.get(NodeLabel.IDENTIFIER.value, []):
            if self._ast_role_from.get((vid, "lhs"), []) or self._ast_role_from.get((vid, "assign_lhs"), []):
                assign_lhs_vids.add(vid)

        for func_vid in self._node_label_idx.get(NodeLabel.FUNCTION.value, []):
            func_path = self._vpath[func_vid]

            # 收集此 function 的所有 parameter
            params: dict[str, list[int]] = defaultdict(list)
            for own_tgt in self._edges_from(func_vid, "own"):
                cv = self.graph.vs[own_tgt]
                if self._vlabel[cv.index] == NodeLabel.PARAMETER.value:
                    pname = self._vname[cv.index]
                    if pname:
                        params[pname].append(cv.index)
            if not params:
                continue

            # 在同 file 内查找同名 identifier（无 DFG 入边且非 LHS）
            for pname, param_vids in params.items():
                for ident_vid in self._name_label_idx.get((pname, NodeLabel.IDENTIFIER.value), []):
                    # 跳过 parameter 自身
                    if ident_vid in param_vids:
                        continue
                    # 跳过有 DFG 入边的（已有数据流来源）
                    has_dfg_in = self._has_edge_to(ident_vid, "dfg")
                    if has_dfg_in:
                        continue
                    # 跳过 assign LHS
                    if ident_vid in assign_lhs_vids:
                        continue
                    # 跳过 array offset index 节点 ($arr[$key] 中的 $key)
                    # — index 是 lookup key，不是 subscript 值本身。
                    # 同名 parameter 传播到 index 节点会导致 FP：
                    # call_user_func($callbacks[$user_input]) 中
                    # $user_input 是 key，不是被调用的函数。
                    if any(
                        True for eid in self.graph.incident(ident_vid, mode="in")
                        if self.graph.es[eid]["label"] == "member"
                        and (self.graph.es[eid]["access_type"] or "") == "array_offset"
                    ):
                        continue
                    # 跳过不同 file 的
                    if self._vpath[ident_vid] != func_path:
                        continue
                    # 跳过不同 function 的（同名参数在不同方法里不应连接）
                    ident_scope = self._get_scope_parent(ident_vid)
                    if ident_scope != func_vid:
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
            if self._vlabel[v.index] == NodeLabel.FILE.value:
                # file 节点的路径在 location 属性中
                fp = (
                    self._vlocation[v.index]
                    or self._vpath[v.index]
                    or self._vfile_path[v.index]
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
            if self._vlabel[v.index] not in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                continue
            vname = self._vname[v.index]
            if not _is_global_var(vname):
                continue  # 按语言规则过滤变量名

            # 直接用 identifier 的 file_path 属性确定所属文件
            # （不依赖 _get_scope_parent，因为 identifier 可能没有 own/ast 入边）
            v_fp = self._vfile_path[v.index] or self._vpath[v.index]
            if not v_fp:
                continue
            norm_v_fp = os.path.normpath(v_fp)
            file_vid = file_path_to_vid.get(norm_v_fp)
            if file_vid is None:
                continue

            # 检查是否有 DFG 入边（含已累积未 flush 的）
            has_dfg_in = self._has_edge_to(v.index, "dfg") \
                or v.index in self._dfg_tgt_set

            cat = "defined" if has_dfg_in else "undefined"

            # C/C++/PHP: 函数内变量不参与跨文件链接。
            # - defined: 函数局部变量（$query inside a function）不应流向其他文件。
            #   PHP include 语义中，被包含文件的函数作用域是封闭的，
            #   同名局部变量不应与包含方的全局变量建立 DFG 边。
            # - undefined: 函数内未定义变量保留（可能是引用全局/超全局变量）。
            if language in ("c", "cpp", "php"):
                in_function = False
                for eid in self.graph.incident(v.index, mode="in"):
                    e = self.graph.es[eid]
                    elabel = self._elabel[e.index]
                    if elabel in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                        ancestor = e.source
                        visited_scope = {v.index}
                        while ancestor is not None and ancestor not in visited_scope:
                            visited_scope.add(ancestor)
                            alabel = self._vlabel[ancestor]
                            if alabel == NodeLabel.FUNCTION.value:
                                in_function = True
                                break
                            if alabel == NodeLabel.FILE.value:
                                break
                            found_up = False
                            for eid2 in self.graph.incident(ancestor, mode="in"):
                                e2 = self.graph.es[eid2]
                                if self._elabel[e2.index] in (
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
            if self._vlabel[v.index] != "import":
                continue
            if self._vtype[v.index] not in import_types:
                continue

            import_vid = v.index
            import_fp = self._vfile_path[v.index] or self._vpath[v.index]
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
        _visited: set[int] | None = None,
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

        # 防止循环递归（同文件 import 链可能互相引用）
        if _visited is None:
            _visited = set()
        if import_vid in _visited:
            return []
        _visited.add(import_vid)

        # Case S: source 属性直接提供路径（C/C++ #include "utils.h"）
        # C/C++ import 节点没有 ast[arg] 子节点，路径存在 source 属性中
        if not arg_vids:
            source = self._vsource[import_vid]
            if source:
                resolved = os.path.normpath(os.path.join(parent_dir, source))
                vid = file_path_map.get(resolved)
                if vid is not None:
                    return [vid]
                return self._fuzzy_match_file(source, file_path_map)
            return []

        arg_vid = arg_vids[0]
        arg_v = self.graph.vs[arg_vid]
        arg_label = self._vlabel[arg_v.index]
        arg_type = self._vtype[arg_v.index]


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
            if self._vlabel[v.index] != "import":
                continue
            if self._vtype[v.index] not in import_types:
                continue
            v_fp = self._vfile_path[v.index] or self._vpath[v.index]
            if os.path.normpath(v_fp) != norm_parent:
                continue
            # 递归 resolve（边界：静态 import 返回结果，不再递归）
            child_arg_vids = self._get_ast_children(v.index, role="arg")
            if child_arg_vids:
                ca = self.graph.vs[child_arg_vids[0]]
                if (self._vlabel[ca.index] == NodeLabel.OPERATOR.value
                        and self._vtype[ca.index] in ("binary_op", "concat")):
                    resolved = self._resolve_import_targets(
                        v.index, v_fp, file_path_map, _visited
                    )
                    for r in resolved:
                        candidates.add(r)

        # 策略 2: 动态 include 变量的同名候选
        # include($file) → $file 在 target 文件中有 DFG 入边
        # 注意：策略 1 的 fuzzy match 可能返回大量误匹配，策略 2 始终追加
        if arg_label == NodeLabel.IDENTIFIER.value:
            var_name = self._vname[arg_v.index]
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
        for child_vid in self._edges_from(vid, "ast"):
            child = self.graph.vs[child_vid]
            child_label = self._vlabel[child.index]
            child_type = self._vtype[child.index]
            child_name = self._vname[child.index]

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
            if self._vlabel[v.index] != NodeLabel.OPERATOR.value:
                continue
            if self._vtype[v.index] not in call_types:
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
        """累积一条 dfg 边（set 自动去重）。"""
        if src == tgt:
            return
        edge = (src, tgt, dfg_type)
        if edge not in self._dfg_edges:
            self._dfg_edges.add(edge)
            self._dfg_tgt_set.add(tgt)

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
            if self._elabel[e.index] != EdgeLabel.AST.value:
                continue
            if role is not None and self._erole[e.index] != role:
                continue
            result.append(e.target)
        return result

    def _get_ast_children_by_arg_index(self, vid: int) -> dict[int, int]:
        """获取调用节点的所有 arg 子节点，返回 {arg_index: child_vid} 映射。"""
        result: dict[int, int] = {}
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if self._elabel[e.index] != EdgeLabel.AST.value:
                continue
            if self._erole[e.index] != AstRole.ARG.value:
                continue
            arg_index = self._earg_index[e.index]
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
            if self._elabel[e.index] not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            if index is not None and self._eindex_attr[e.index] != index:
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
            if self._elabel[e.index] not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            idx = self._eindex_attr[e.index]
            if idx is not None and idx != "":
                # 只取 parameter 子节点
                target_label = self._vlabel[e.target]
                if target_label == NodeLabel.PARAMETER.value:
                    result[int(idx)] = e.target
        return result

    def _get_own_children_by_label(self, vid: int, child_label: str) -> list[int]:
        """获取从 vid 出发的 own 边中指定标签的子顶点。"""
        result = []
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if self._elabel[e.index] not in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                continue
            target_label = self._vlabel[e.target]
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
            if self._elabel[e.index] in (EdgeLabel.OWN.value, EdgeLabel.AST.value):
                return True
        return False

    def _get_cg_target(self, vid: int) -> Optional[int]:
        """获取从调用 operator 出发的 use/callee 边的目标函数顶点。

        Returns:
            函数顶点索引，若无相关边则返回 None。
        """
        for eid in self.graph.incident(vid, mode="out"):
            e = self.graph.es[eid]
            if self._elabel[e.index] == EdgeLabel.USE.value:
                return e.target
        # JS 等语言用 ast[role=callee] 而非 use 边
        callee_vids = self._ast_role_from.get((vid, "callee"), [])
        if callee_vids:
            return callee_vids[0]
        return None

    def _get_cg_callers(self, func_vid: int) -> list[int]:
        """获取所有通过 use/callee 边调用 func_vid 的 operator 顶点。

        Returns:
            调用者顶点索引列表。
        """
        result = []
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            if self._elabel[e.index] == EdgeLabel.USE.value:
                result.append(e.source)
        # JS 等语言用 ast[role=callee]
        for (src_vid, role), tgt_vids in self._ast_role_from.items():
            if role == "callee" and func_vid in tgt_vids:
                result.append(src_vid)
        return result

    def _get_edges_by_label(self, label: str) -> list[int]:
        """获取指定标签的所有边 ID。"""
        result = []
        for e in self.graph.es:
            if self._elabel[e.index] == label:
                result.append(e.index)
        return result

    def _get_scope_parent(self, vid: int) -> int | None:
        """沿 own/ast 边向上找到最近的 function/file 作用域节点。

        identifier 节点通常通过 ast 边挂在 operator 下，operator 再通过 own
        边挂在 function/file 下，因此需要同时遍历 own 和 ast 两种边。

        PHP method receiver ($obj in $obj->method()) 没有 ast 边连到
        method_call operator — 它只通过 member 边连到 callee property。
        对这类节点，沿 member/dfg 边间接找到关联的 operator，再向上找 scope。

        Args:
            vid: 任意节点的索引。

        Returns:
            作用域节点的索引（function 或 file），或 None。
        """
        cur = vid
        seen: set[int] = set()
        while cur is not None and cur not in seen:
            seen.add(cur)
            label = self._vlabel[cur]
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return cur
            # 优先沿 own 边向上（operator → function/file）
            own_sources = self._edges_to(cur, "own")
            if own_sources:
                cur = own_sources[0]
            else:
                # 回退：沿 ast 边向上（identifier → operator）
                ast_sources = self._edges_to(cur, "ast")
                cur = ast_sources[0] if ast_sources else None
        # Fallback for nodes without ast/own parents (e.g. PHP method receiver):
        # try reaching an operator via member or dfg edges, then resume scope search.
        if cur is None:
            for edge_label in ("member", "dfg"):
                for nbr in self._edges_from(vid, edge_label):
                    if nbr == vid or nbr in seen:
                        continue
                    scope = self._scope_from_node(nbr, seen | {vid})
                    if scope is not None:
                        return scope
        # Final fallback: use file node from path
        node_path = self._vpath[vid]
        if node_path:
            return self._path_to_file_vid.get(node_path)
        return None

    def _scope_from_node(self, vid: int, seen: set[int]) -> int | None:
        """Resume scope search from a node reached via member/dfg edges."""
        cur = vid
        while cur is not None and cur not in seen:
            seen.add(cur)
            label = self._vlabel[cur]
            if label in (NodeLabel.FUNCTION.value, NodeLabel.FILE.value):
                return cur
            own_sources = self._edges_to(cur, "own")
            if own_sources:
                cur = own_sources[0]
            else:
                ast_sources = self._edges_to(cur, "ast")
                cur = ast_sources[0] if ast_sources else None
        return None

    def _get_callee_name(self, vid: int) -> str:
        """获取调用 operator 的被调用函数名。

        优先从 ast[callee] 子节点获取 name，
        若无可尝试从 operator 的 name 属性获取。
        """
        callee_children = self._get_ast_children(vid, role=AstRole.CALLEE.value)
        if callee_children:
            return self._vname[callee_children[0]]
        # 回退：operator 节点的 name 属性
        return self._vname[vid]

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
        func_fullname = self._vfullname[node.index]
        func_name = self._vname[node.index]

        # 查找 func_vid 所在的父作用域
        parent_vid = None
        for eid in self.graph.incident(func_vid, mode="in"):
            e = self.graph.es[eid]
            elabel = self._elabel[e.index]
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
                            if self._elabel[e2.index] in (
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
            if self._elabel[e.index] != EdgeLabel.AST.value:
                continue
            if self._erole[e.index] != AstRole.RHS.value:
                continue

            # e.source 是父节点（assign operator）
            parent_vid = e.source
            parent_label = self._vlabel[parent_vid]
            parent_type = self._vtype[parent_vid]

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
            language: 语言标识（如 "php"、"java"、"python"）。

        Returns:
            内置知识字典，若无对应语言或导入失败返回 None。
        """
        try:
            mod_path = f"core.core_engine.{language}.builtin_knowledge"
            import importlib
            mod = importlib.import_module(mod_path)
            return getattr(mod, 'KNOWLEDGE', None)
        except (ImportError, AttributeError):
            pass
        try:
            if language == "c":
                from core.graph.normalizers.c.builtin_knowledge import C_BUILTIN_KNOWLEDGE
                return C_BUILTIN_KNOWLEDGE
        except ImportError:
            pass
        return None

    def _is_safe_callee(self, callee: str, language: str) -> bool:
        """Check whether a callee is marked safe in builtin_knowledge.

        Queries the per-language builtin_knowledge dict.  Both the exact
        callee name and the tail segment (after '::' or '.') are tried.
        A function is "safe" when its knowledge entry has safe: True,
        meaning its return value is not user-controlled (sanitizer, type
        cast to non-string, framework config reader, etc.).
        """
        bk = self._load_builtin_knowledge(language)
        if not bk:
            return False
        entry = bk.get(callee)
        if entry and entry.get("safe"):
            return True
        callee_tail = callee.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
        if callee_tail != callee:
            entry = bk.get(callee_tail)
            if entry and entry.get("safe"):
                return True
        return False

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

        # safe 函数：返回值是安全的，不应有 DFG passthrough 边
        safe = entry.get("safe", False)
        if safe:
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
