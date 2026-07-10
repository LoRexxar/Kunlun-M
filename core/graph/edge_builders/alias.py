"""Alias edge builder - resolves indirect function call chains.

After DFG and CG builders have run, this builder identifies call operators
whose use->function target is an external placeholder (no own children)
and traces the DFG chain backward from the callee identifier to discover
the real target function.

Creates alias edges: identifier -> function (placeholder or existing).

Triggers:
- CG builder created use -> function(is_external=True, no own children)
- The callee identifier has incoming DFG edges (meaning it was assigned)
- DFG backward tracking can resolve to a real function name

Resolution strategies (in order):
1. DFG chain ends at identifier with member edge -> compose qualified name
   (e.g. os -> system via member -> os.system)
2. DFG chain ends at identifier leaf -> return name as function reference
   (e.g. func = eval -> name is eval)
3. DFG chain passes through known resolver operators (getattr, globals().get)
   -> extract string argument as target name
4. DFG chain ends at const(string) -> use string value as function name
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from core.graph.node_edge_schema import (
    AliasType,
    EdgeLabel,
    NodeLabel,
    OperatorType,
)
from utils.igraph_compat import _vattr

if TYPE_CHECKING:
    import igraph

logger = logging.getLogger(__name__)


class AliasBuilder:
    """Build alias edges for indirect function calls.

    Runs after DFG and CG builders.  Scans all call operators whose
    use->function target is an external placeholder and attempts
    DFG backward resolution.
    """

    def __init__(self) -> None:
        self.graph = None
        self.language = ""
        self._alias_count = 0
        # 边索引：O(E) 一次构建，替代所有 es.select 的 O(E) 逐次查询
        self._edge_src_idx: dict[tuple[str, int], list[int]] = {}
        self._edge_tgt_idx: dict[tuple[str, int], list[int]] = {}
        # ast role 索引：(src_vid, role) → [tgt_vids]
        self._ast_role_from: dict[tuple[int, str], list[int]] = {}
        # 节点标签索引：label → [vids]
        self._node_label_idx: dict[str, list[int]] = {}

    # -- public entry ---------------------------------------------------------

    def build(self, graph: "ig.Graph", language: str, **kwargs) -> int:
        """Main entry: scan all call operators and create alias edges."""
        self.graph = graph
        self.language = language
        self._alias_count = 0

        # 预构建边索引
        self._edge_src_idx.clear()
        self._edge_tgt_idx.clear()
        self._ast_role_from.clear()
        self._node_label_idx.clear()
        for e in self.graph.es:
            elabel = _vattr(e, "label", "")
            src, tgt = e.source, e.target
            self._edge_src_idx.setdefault((elabel, src), []).append(tgt)
            self._edge_tgt_idx.setdefault((elabel, tgt), []).append(src)
            if elabel == "ast":
                role = _vattr(e, "role", "")
                if role:
                    self._ast_role_from.setdefault((src, role), []).append(tgt)
        for v in self.graph.vs:
            vlabel = _vattr(v, "label", "")
            if vlabel:
                self._node_label_idx.setdefault(vlabel, []).append(v.index)

        # Helper methods — 存为实例属性，供所有内部方法使用
        # 注意：不能直接 .get 绑定，否则 _ef(vid, label) 会被解释为 dict.get(vid, label)
        # 即 label 变成了 default 参数。必须用 lambda 包装。
        self._ef = lambda src, label: self._edge_src_idx.get((label, src), [])
        self._et = lambda tgt, label: self._edge_tgt_idx.get((label, tgt), [])

        # 预构建 identifier/parameter 名字索引：name -> [(vid, parent_func_vid), ...]
        # 用于 _find_callee_identifier 的 O(1) fallback 查找
        self._name_to_idents: dict[str, list[tuple[int, int | None]]] = {}
        for v in self.graph.vs:
            if v["label"] in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value):
                name = _vattr(v, "name", "")
                if name:
                    parent_func = self._find_own_parent_function(v.index)
                    self._name_to_idents.setdefault(name, []).append((v.index, parent_func))
        # 预构建函数名→vid索引（用于 _find_or_create_function O(1) 查找）
        self._func_name_to_vid: dict[str, int] = {}
        # fullname 索引：支持 PHP class::method 等模糊匹配
        self._func_fullname_to_vid: dict[str, int] = {}
        for v in self.graph.vs:
            if v["label"] == NodeLabel.FUNCTION.value:
                fname = _vattr(v, "name", "")
                if fname:
                    self._func_name_to_vid[fname] = v.index
                fullname = _vattr(v, "fullname", "") or ""
                if fullname:
                    self._func_fullname_to_vid[fullname] = v.index
        # 预构建 (file, name) → [(vid, has_dfg)] 索引（用于 _find_same_name_with_dfg O(1) 查找）
        self._file_name_idents: dict[str, list[tuple[int, bool]]] = {}
        for v in self.graph.vs:
            if v["label"] in (NodeLabel.IDENTIFIER.value, NodeLabel.PARAMETER.value):
                name = _vattr(v, "name", "")
                if not name:
                    continue
                fpath = _vattr(v, "file_path", "") or _vattr(v, "path", "")
                if not fpath:
                    continue
                has_dfg = bool(self._et(v.index, "dfg"))
                key = f"{fpath}\x00{name}"
                self._file_name_idents.setdefault(key, []).append((v.index, has_dfg))
        call_types = {
            OperatorType.CALL.value,
            OperatorType.STATIC_CALL.value,
            OperatorType.METHOD_CALL.value,
        }

        for v in self.graph.vs:
            if v["label"] != NodeLabel.OPERATOR.value:
                continue
            if v["type"] not in call_types:
                continue

            op_vid = v.index
            use_func = self._find_use_function(op_vid)
            if use_func is None:
                continue

            func_vid, func_name = use_func

            # Skip if function has own children (real definition)
            if self._ef(func_vid, "own"):
                continue

            # Check for method_call indirect invocation patterns:
            # Ruby: op.call(arg), PHP: $func(), etc.
            # When the method name is a generic call mechanism ('call', '__call__'),
            # the real function reference is in the operand (receiver).
            op_type = _vattr(v, "type", "")
            callee_id = self._find_callee_identifier(op_vid, func_name)
            if callee_id is None and op_type == OperatorType.METHOD_CALL.value:
                callee_id = self._find_operand_identifier(op_vid)

            if callee_id is None:
                continue

            # Resolve through DFG backward tracking
            resolved_name, alias_type, target_func_vid = self._resolve_alias(
                callee_id, func_name
            )

            if resolved_name is None:
                continue

            # Create alias edge: use->function target -> resolved_function
            # This ensures _resolve_callee_name's use-fallback path can find it.
            self._create_alias_edge(
                func_vid, resolved_name, alias_type, target_func_vid
            )

        if self._alias_count:
            logger.info(
                "[ALIAS] Created %d alias edges for %s",
                self._alias_count,
                self.language,
            )
        return self._alias_count

    # -- internal helpers -----------------------------------------------------

    def _find_use_function(self, op_vid: int) -> tuple[int, str] | None:
        """Find the use->function edge target from a call operator."""
        for tgt_vid in self._ef(op_vid, "use"):
            target = self.graph.vs[tgt_vid]
            if target["label"] == NodeLabel.FUNCTION.value:
                return tgt_vid, target["name"]
        return None

    def _find_callee_identifier(self, op_vid: int, func_name: str) -> int | None:
        """Find the callee identifier vertex for a call operator."""
        # Look for ast[role=callee] child that is an identifier
        for callee_vid in self._ast_role_from.get((op_vid, "callee"), []):
            t = self.graph.vs[callee_vid]
            if t["label"] == NodeLabel.IDENTIFIER.value:
                return callee_vid
        # Fallback: 从预构建索引查找 identifier/parameter by name
        candidates = self._name_to_idents.get(func_name, [])
        if candidates:
            enclosing_func = self._find_own_parent_function(op_vid)
            # 优先同作用域
            for vid, parent_func in candidates:
                if enclosing_func and parent_func == enclosing_func:
                    return vid
            # 回退到跨作用域
            return candidates[0][0]
        return None

    def _find_own_parent_function(self, vid: int) -> int | None:
        """Find the nearest function/file ancestor via incoming own/ast edges."""
        visited: set[int] = set()
        queue = [vid]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            # Walk up own chain, then AST chain from intermediate nodes
            for src_vid in self._et(current, "own"):
                parent_label = self.graph.vs[src_vid]["label"]
                if parent_label in ("function", "file"):
                    return src_vid
                queue.append(src_vid)
            for src_vid in self._et(current, "ast"):
                parent_label = self.graph.vs[src_vid]["label"]
                if parent_label in ("function", "file"):
                    return src_vid
                queue.append(src_vid)
        return None

    def _find_operand_identifier(self, op_vid: int) -> int | None:
        """Find the operand (receiver) identifier for a method_call operator.

        Used for indirect call patterns like Ruby's ``obj.call(arg)`` where
        the method name ``call`` is a generic dispatch mechanism and the real
        function reference is the receiver object.
        """
        for operand_vid in self._ast_role_from.get((op_vid, "operand"), []):
            t = self.graph.vs[operand_vid]
            if t["label"] in (
                NodeLabel.IDENTIFIER.value,
                NodeLabel.PARAMETER.value,
            ):
                return operand_vid
        return None

    def _resolve_alias(
        self, callee_id: int, callee_name: str, max_depth: int = 8
    ) -> tuple[str | None, str | None, int | None]:
        """Trace DFG backward from callee identifier to resolve real function.

        Uses iterative DFS with backtracking to explore all DFG source paths
        when a node has multiple incoming DFG edges.

        Returns:
            (resolved_name, alias_type, target_func_vid or None)
        """
        visited: set[int] = set()

        def _try(current: int, depth: int) -> tuple[str | None, str | None, int | None]:
            if depth > max_depth or current in visited:
                return None, None, None
            visited.add(current)

            cur_v = self.graph.vs[current]
            cur_label = cur_v["label"]
            cur_name = _vattr(cur_v, "name", "")

            # Terminal: identifier
            if cur_label == NodeLabel.IDENTIFIER.value and cur_name:
                # Check if any member edge points TO this identifier
                member_sources = self._et(current, "member")
                if member_sources:
                    parent_vid = member_sources[0]
                    parent_name = _vattr(self.graph.vs[parent_vid], "name", "")
                    composed = f"{parent_name}.{cur_name}"
                    func_vid = self._find_or_create_function(composed)
                    return composed, AliasType.VIA_MEMBER.value, func_vid

                # Leaf identifier: no DFG upstream
                dfg_sources = self._et(current, "dfg")
                if not dfg_sources:
                    # Cross-scope fallback
                    cross_scope_id = self._find_same_name_with_dfg(
                        current, cur_name
                    )
                    if cross_scope_id is not None:
                        result = _try(cross_scope_id, depth + 1)
                        if result[0] is not None:
                            return result

                    # No cross-scope match; treat as direct reference
                    func_vid = self._find_or_create_function(cur_name)
                    atype = (
                        AliasType.VIA_DFG_CHAIN.value
                        if current != callee_id
                        else AliasType.DIRECT.value
                    )
                    return cur_name, atype, func_vid

                # Has DFG upstream — try each path
                for src_vid in dfg_sources:
                    result = _try(src_vid, depth + 1)
                    if result[0] is not None:
                        return result
                return None, None, None

            # Terminal: const(string)
            if cur_label == NodeLabel.CONST.value and cur_name:
                clean = cur_name.strip("'\"")
                func_vid = self._find_or_create_function(clean)
                return clean, AliasType.DIRECT.value, func_vid

            # Terminal: function node
            if cur_label == NodeLabel.FUNCTION.value and cur_name:
                return cur_name, AliasType.DIRECT.value, current

            # Transit: operator node — check for resolver patterns
            if cur_label == NodeLabel.OPERATOR.value and cur_name:
                string_arg = self._extract_string_arg(current)
                if string_arg:
                    alias_type = (
                        AliasType.VIA_GETATTR.value
                        if "getattr" in cur_name
                        else AliasType.VIA_GLOBALS.value
                    )
                    func_vid = self._find_or_create_function(string_arg)
                    return string_arg, alias_type, func_vid

            # Transit: any other node — follow DFG sources
            for src_vid in self._et(current, "dfg"):
                result = _try(src_vid, depth + 1)
                if result[0] is not None:
                    return result

            return None, None, None

        return _try(callee_id, 0)

    def _extract_string_arg(self, op_vid: int) -> str | None:
        """Extract a string argument from an operator's ast[arg] children.

        Used for getattr(obj, 'method_name'), globals().get('func_name'),
        and Ruby method(:symbol) patterns.
        """
        for arg_vid in self._ast_role_from.get((op_vid, "arg"), []):
            arg_v = self.graph.vs[arg_vid]
            if arg_v["label"] == NodeLabel.CONST.value:
                name = _vattr(arg_v, "name", "")
                if name:
                    name = name.strip("'\"")
                    # Strip Ruby symbol prefix (:system → system)
                    if name.startswith(":") and not name.startswith("::"):
                        name = name[1:]
                    return name
        return None

    def _find_or_create_function(self, name: str) -> int | None:
        """Find an existing function node with the given name, or create one."""
        # O(1) 索引查找
        vid = self._func_name_to_vid.get(name)
        if vid is not None:
            return vid
        # Fallback: 在 fullname 索引中模糊查找（如 PHP 类方法 class::method）
        # keys 数量远小于全图节点数
        for fn, vid in self._func_fullname_to_vid.items():
            if name in fn or fn.endswith("." + name):
                return vid

        # Create a placeholder function node
        vid = self.graph.vcount()
        self.graph.add_vertex(vid)
        self.graph.vs[vid]["label"] = NodeLabel.FUNCTION.value
        self.graph.vs[vid]["name"] = name
        self.graph.vs[vid]["type"] = "function"
        self.graph.vs[vid]["is_external"] = True
        self.graph.vs[vid]["lineno"] = 0
        return vid

    def _find_same_name_with_dfg(
        self, current: int, name: str
    ) -> int | None:
        """Find a same-name identifier/parameter in another scope that has DFG edges.

        Used as a cross-scope fallback in _resolve_alias when the callee
        identifier has no DFG upstream within its own scope, but a same-name
        variable definition exists in an outer scope.

        Only searches within the same file to avoid cross-language pollution
        (e.g. C's 'system' resolving to Python's os.system).
        """
        # Get the file of the current identifier to scope the search
        current_file = _vattr(self.graph.vs[current], "file_path", "") or _vattr(self.graph.vs[current], "path", "")
        if not current_file:
            return None
        # O(1) 索引查找：candidates = [(vid, has_dfg), ...]
        key = f"{current_file}\x00{name}"
        candidates = self._file_name_idents.get(key, [])
        best = None
        best_has_dfg = False
        for vid, has_dfg in candidates:
            if vid == current:
                continue
            if has_dfg and not best_has_dfg:
                best = vid
                best_has_dfg = True
            elif best is None:
                best = vid
        return best

    def _create_alias_edge(
        self,
        source_vid: int,
        resolved_name: str,
        alias_type: str,
        target_func_vid: int | None,
    ) -> None:
        """Create an alias edge from callee identifier to resolved function."""
        attrs = {
            "alias_type": alias_type,
            "resolved_name": resolved_name,
        }
        if target_func_vid is not None:
            self.graph.add_edge(
                source_vid, target_func_vid, label="alias", **attrs
            )
        else:
            # Self-loop as marker - consumers check resolved_name attribute
            self.graph.add_edge(
                source_vid, source_vid, label="alias", **attrs
            )
        self._alias_count += 1
        logger.debug(
            "[ALIAS] v%d -> '%s' (type=%s, target=%s)",
            source_vid,
            resolved_name,
            alias_type,
            target_func_vid,
        )
