"""PHP AST Normalizer — maps phply AST nodes to UnifiedNode / UnifiedEdge.

Converts PHP source parsed by phply into the unified intermediate
representation used by the AST graph engine.  Each PHP file produces:
  - 1 file node
  - N class/function/import/dependency nodes (top-level declarations)
  - M operator/branch/return/identifier/const nodes (statement/expression level)
  - edges: own, ast, use, member, crg, frg
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from phply.phpparse import make_parser
from phply.phplex import lexer
from phply import phpast

from core.graph.node_edge_schema import (
    NodeLabel,
    EdgeLabel,
    UnifiedNode,
    UnifiedEdge,
    ClassType,
    FunctionType,
    OperatorType,
    BranchType,
    ImportType,
    IdentifierType,
    ConstType,
    CgCallType,
    AstRole,
    MemberAccessType,
    CrgType,
    FrgType,
)

__all__ = ["Normalizer"]


# ---------------------------------------------------------------------------
# phply node type → unified label mapping
# ---------------------------------------------------------------------------

_CLASS_NODES = {
    "Class", "Interface", "Trait", "Enum",
}

_FUNCTION_NODES = {
    "Function", "Method", "Closure", "ArrowFunction",
}

_CALL_NODES = {
    "FunctionCall", "MethodCall", "StaticMethodCall",
    "NullsafeMethodCall",
}

_BRANCH_NODES = {
    "If", "ElseIf", "Else", "TernaryOp",
    "For", "While", "Foreach", "DoWhile",
    "Switch", "Case", "Default",
    "Try", "Catch", "Finally",
    "Match",
}

_IMPORT_NODES = {
    "Include", "Require", "UseDeclaration",
}

_OPERATOR_NODES = {
    "Assignment", "AssignOp",
    "BinaryOp", "UnaryOp", "PostIncDecOp", "PreIncDecOp",
    "New", "Cast", "Throw", "Yield",
    "Break", "Continue",
    "Echo", "Print",
    "Eval", "Silence", "IsSet", "Empty", "Unset",
    "Clone", "Exit",
    "ListAssignment",
}


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts phply AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ast.parse(tokens),
            file_path="/path/to/file.php",
            source_content="<?php ...",
        )
    """

    language = "php"

    def normalize(
        self,
        ast_nodes: list,
        file_path: str,
        source_content: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Convert phply AST nodes to unified graph data.

        Args:
            ast_nodes: List of top-level phply AST nodes (from ``phpast.parse()``).
            file_path: Absolute path to the PHP file.
            source_content: Optional source text for content_hash.

        Returns:
            A 3-tuple:
            - file_node dict (label, name, lineno, language, attrs)
            - nodes list (non-file node dicts)
            - edges list (label, source, target, attrs)
        """
        # File node
        content_hash = ""
        if source_content:
            content_hash = hashlib.md5(source_content.encode("utf-8", errors="ignore")).hexdigest()

        file_node: dict[str, Any] = {
            "label": NodeLabel.FILE.value,
            "name": os.path.basename(file_path),
            "lineno": 0,
            "language": self.language,
            "attrs": {
                "location": file_path,
                "content_hash": content_hash,
            },
        }

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        # Index: maps id → position in nodes list (0-based)
        # file node is always index 0
        node_index: dict[int, int] = {}
        idx_counter = [0]  # mutable counter for closures

        def _add_node(node_dict: dict[str, Any]) -> int:
            pos = len(nodes)
            nodes.append(node_dict)
            return pos

        def _add_edge(edge_dict: dict[str, Any]) -> None:
            edges.append(edge_dict)

        # file_node 作为位置 0 加入 nodes 列表（用于 ctx_stack 的 own 边锚点）
        file_pos = _add_node(file_node)

        # Context stack for tracking current class/function/branch
        # Each entry: (node_position, node_label)
        ctx_stack: list[tuple[int, str]] = [(file_pos, NodeLabel.FILE.value)]

        def current_ctx() -> tuple[int, str] | None:
            return ctx_stack[-1] if ctx_stack else None

        # -- walk top-level AST nodes ----------------------------------------

        top_idx = 0
        for ast_node in ast_nodes:
            self._walk_node(
                ast_node=ast_node,
                add_node=_add_node,
                add_edge=_add_edge,
                ctx_stack=ctx_stack,
                file_path=file_path,
                depth=top_idx,
            )
            top_idx += 1

        # file_node 在 nodes[0]，提取后返回（nodes 不再包含 file_node）
        assert nodes[0] is file_node
        return file_node, nodes[1:], edges

    # -- internal walkers -----------------------------------------------------

    # -- Main node walker (defined below, after member-access handlers) ----
    # The canonical _walk_node lives after _walk_node_base; it handles
    # member-access nodes directly and delegates everything else to
    # _walk_node_base.

    # -- Class ----------------------------------------------------------------

    def _walk_class(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        name = getattr(node, "name", "")
        extends = getattr(node, "extends", None)
        implements = getattr(node, "implements", [])
        traits = getattr(node, "traits", None)
        cls_nodes = getattr(node, "nodes", [])

        # Determine unified class type
        cls_type_map = {
            "Class": ClassType.CLASS,
            "Interface": ClassType.INTERFACE,
            "Enum": ClassType.ENUM,
        }
        # Trait is stored as class type in the unified schema
        unified_type = cls_type_map.get(node_type_name, ClassType.CLASS)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": getattr(node, "lineno", 0),
            "end_lineno": getattr(node, "end_lineno", 0),
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": unified_type.value,
                "inherits_from": extends if isinstance(extends, str) else "",
                "raw_type": node_type_name,
            },
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        # crg edges for extends
        if extends and isinstance(extends, str) and extends:
            # Create a placeholder class node for the parent (if not already exists)
            parent_pos = add_node({
                "label": NodeLabel.CLASS.value,
                "name": extends,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": extends,
                    "type": ClassType.CLASS.value,
                    "is_external": True,
                },
            })
            add_edge({"label": EdgeLabel.CRG.value, "source": pos, "target": parent_pos,
                       "attrs": {"type": CrgType.EXTENDS.value}})

        # Walk child nodes (methods, properties, etc.)
        ctx_stack.append((pos, NodeLabel.CLASS.value))
        if cls_nodes:
            for child in cls_nodes:
                self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)
        ctx_stack.pop()

        return pos

    # -- Function / Method / Closure -----------------------------------------

    def _walk_function(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        name = getattr(node, "name", "")
        params = getattr(node, "params", []) or []
        stmt_nodes = getattr(node, "nodes", [])
        is_ref = getattr(node, "is_ref", False)
        return_type = getattr(node, "return_type", None)

        # Determine function type
        func_type_map = {
            "Function": FunctionType.FUNCTION,
            "Method": FunctionType.METHOD,
            "Closure": FunctionType.LAMBDA,
            "ArrowFunction": FunctionType.LAMBDA,
        }
        func_type = func_type_map.get(node_type_name, FunctionType.FUNCTION)

        # For closures/arrows, generate a synthetic name
        if node_type_name in ("Closure", "ArrowFunction"):
            name = f"<{node_type_name}>"

        # Build signature string
        param_strs = []
        for p in params:
            pname = getattr(p, "name", "")
            ptype = getattr(p, "type", None)
            p_default = getattr(p, "default", None)
            s = ""
            if ptype:
                s += f"{ptype} "
            s += pname
            if p_default is not None:
                s += " = ..."
            param_strs.append(s)
        if is_ref:
            signature = f"&{name}({', '.join(param_strs)})"
        else:
            signature = f"{name}({', '.join(param_strs)})"
        if return_type:
            signature += f": {return_type}"

        # Modifiers (only for Method)
        modifiers = ""
        if node_type_name == "Method":
            mods = getattr(node, "modifiers", []) or []
            modifiers = " ".join(mods)

        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", 0)

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": func_type.value,
                "signature": signature,
                "modifiers": modifiers,
                "file_path": file_path,
                "raw_type": node_type_name,
            },
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        # Push context and walk body
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, p in enumerate(params):
            p_pos = self._walk_parameter(p, add_node, file_path)
            if p_pos is not None:
                add_edge({"label": EdgeLabel.OWN.value, "source": pos, "target": p_pos,
                           "attrs": {"index": idx}})

        # Body statements — own index 从参数数量之后开始，避免与 parameter index 冲突
        body_offset = len(params)
        if stmt_nodes:
            for child_idx, child in enumerate(stmt_nodes):
                self._walk_node(child, add_node, add_edge, ctx_stack, file_path, body_offset + child_idx)

        # ArrowFunction: expr instead of nodes
        if node_type_name == "ArrowFunction":
            expr = getattr(node, "expr", None)
            if expr:
                self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # -- Parameter ------------------------------------------------------------

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        name = getattr(param_node, "name", "")
        if not name:
            return None
        lineno = getattr(param_node, "lineno", 0)
        type_hint = getattr(param_node, "type", None) or ""
        default = getattr(param_node, "default", None)

        pos = add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type_hint": str(type_hint) if type_hint else "",
                "default_value": repr(default)[:80] if default else "",
            },
        })
        return pos

    # -- Import / Include / Require / Use ------------------------------------

    def _walk_import(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        lineno = getattr(node, "lineno", 0)
        attrs: dict[str, Any] = {}
        frg_type = None

        if node_type_name in ("Include", "Require"):
            expr = getattr(node, "expr", None)
            once = getattr(node, "once", False)

            # Extract name from expr
            name = ""
            if expr:
                if isinstance(expr, phpast.Constant):
                    name = expr.name
                elif isinstance(expr, phpast.Variable):
                    name = f"${expr.name}"
                else:
                    name = str(expr)

            imp_type = ImportType.INCLUDE if node_type_name == "Include" else ImportType.REQUIRE
            if once:
                imp_type = ImportType.INCLUDE_ONCE if node_type_name == "Include" else ImportType.REQUIRE_ONCE
            frg_type = FrgType.INCLUDE

            attrs = {
                "type": imp_type.value,
                "fullname": name,
                "alias": "",
            }

        elif node_type_name == "UseDeclaration":
            name = getattr(node, "name", "")
            alias = getattr(node, "alias", None) or ""
            frg_type = FrgType.USE
            attrs = {
                "type": ImportType.USE.value,
                "fullname": name,
                "alias": alias,
            }

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": attrs,
        })

        # own edge from context (file or namespace)
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        return pos

    # -- Branch nodes ---------------------------------------------------------

    def _walk_branch(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int | None:
        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", 0)

        branch_type_map = {
            "If": BranchType.IF,
            "ElseIf": BranchType.ELIF,
            "Else": BranchType.ELSE,
            "TernaryOp": BranchType.TERNARY,
            "For": BranchType.FOR,
            "While": BranchType.WHILE,
            "Foreach": BranchType.FOREACH,
            "DoWhile": BranchType.WHILE,
            "Switch": BranchType.SWITCH,
            "Case": BranchType.CASE,
            "Default": BranchType.DEFAULT,
            "Try": BranchType.TRY,
            "Catch": BranchType.CATCH,
            "Finally": BranchType.FINALLY,
            "Match": BranchType.MATCH,
        }
        btype = branch_type_map.get(node_type_name, BranchType.IF)

        # Extract condition
        condition = ""
        if node_type_name == "If":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "ElseIf":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "TernaryOp":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "While":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "Switch":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "Case":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "Match":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""
        elif node_type_name == "Foreach":
            expr = getattr(node, "expr", None)
            condition = self._expr_text(expr) if expr else ""

        # Get current function name from context
        func_name = ""
        for ctx_pos, ctx_label in reversed(ctx_stack):
            if ctx_label == NodeLabel.FUNCTION.value:
                if ctx_pos < len([n for n in []]):  # can't access here, skip
                    pass
                break

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or f"<{node_type_name}>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": btype.value,
                "condition": condition,
                "raw_type": node_type_name,
            },
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        # Walk condition expression into graph (ast[role=condition])
        _COND_EXPR_NODES = {
            "If", "ElseIf", "TernaryOp", "While", "DoWhile",
            "Switch", "Case", "Match", "Foreach",
        }
        if node_type_name in _COND_EXPR_NODES:
            expr = getattr(node, "expr", None)
            if expr:
                cond_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if cond_pos is not None:
                    add_edge({
                        "label": EdgeLabel.AST.value, "source": pos, "target": cond_pos,
                        "attrs": {"role": AstRole.CONDITION.value},
                    })
                elif isinstance(expr, (str, int, float, bool)):
                    # phply Case/Switch expr can be raw Python types
                    cond_pos = add_node({
                        "label": NodeLabel.CONST.value,
                        "name": repr(expr),
                        "lineno": getattr(node, "lineno", 0),
                        "language": self.language,
                        "attrs": {"type": "literal"},
                    })
                    add_edge({
                        "label": EdgeLabel.AST.value, "source": pos, "target": cond_pos,
                        "attrs": {"role": AstRole.CONDITION.value},
                    })

        # Walk body children
        ctx_stack.append((pos, NodeLabel.BRANCH.value))

        body_attr_map = {
            "If": "node",
            "ElseIf": "node",
            "Else": "node",
            "While": "node",
            "DoWhile": "node",
            "Try": "nodes",
            "Catch": "nodes",
            "Finally": "nodes",
            "Switch": "nodes",
            "Case": "nodes",
            "Default": "nodes",
            "Foreach": "node",
        }

        if node_type_name in body_attr_map:
            body = getattr(node, body_attr_map[node_type_name], None)
            if body:
                if isinstance(body, list):
                    for idx, child in enumerate(body):
                        self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
                else:
                    self._walk_node(body, add_node, add_edge, ctx_stack, file_path, 0)

        # If node: also walk elseif and else
        if node_type_name == "If":
            for elif_node in (getattr(node, "elseifs", []) or []):
                self._walk_node(elif_node, add_node, add_edge, ctx_stack, file_path, depth + 1)
            else_node = getattr(node, "else_", None)
            if else_node:
                self._walk_node(else_node, add_node, add_edge, ctx_stack, file_path, depth + 1)

        # Try: walk catches and finally
        if node_type_name == "Try":
            for catch_node in (getattr(node, "catches", []) or []):
                self._walk_node(catch_node, add_node, add_edge, ctx_stack, file_path, 0)
            finally_node = getattr(node, "finally", None)
            if finally_node:
                self._walk_node(finally_node, add_node, add_edge, ctx_stack, file_path, 0)

        # Switch: walk cases
        if node_type_name == "Switch":
            switch_nodes = getattr(node, "nodes", []) or []
            for idx, child in enumerate(switch_nodes):
                self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)

        # Match: walk arms
        if node_type_name == "Match":
            arms = getattr(node, "arms", []) or []
            for idx, arm in enumerate(arms):
                self._walk_node(arm, add_node, add_edge, ctx_stack, file_path, idx)

        # For: walk start, test, count, body
        if node_type_name == "For":
            for attr in ("start", "test", "count"):
                val = getattr(node, attr, None)
                if val:
                    self._walk_node(val, add_node, add_edge, ctx_stack, file_path, 0)
            body = getattr(node, "node", None)
            if body:
                self._walk_node(body, add_node, add_edge, ctx_stack, file_path, 0)

        # TernaryOp: walk iftrue and iffalse, connect via ast[role=iftrue/iffalse]
        if node_type_name == "TernaryOp":
            for branch_attr, role_name in [("iftrue", "iftrue"), ("iffalse", "iffalse")]:
                branch_val = getattr(node, branch_attr, None)
                if branch_val:
                    # 先创建节点（获取 pos），再加 ast 边到 branch
                    if isinstance(branch_val, (str, int, float)):
                        val_pos = add_node({
                            "label": NodeLabel.CONST.value,
                            "name": repr(branch_val),
                            "lineno": getattr(node, "lineno", 0),
                            "language": self.language,
                            "attrs": {"type": "literal"},
                        })
                    else:
                        val_pos = self._walk_node(branch_val, add_node, add_edge, ctx_stack, file_path, 0)
                    if val_pos is not None:
                        add_edge({
                            "label": EdgeLabel.AST.value, "source": pos, "target": val_pos,
                            "attrs": {"role": role_name},
                        })

        # Foreach: walk keyvar, valvar
        if node_type_name == "Foreach":
            for attr in ("keyvar", "valvar"):
                val = getattr(node, attr, None)
                if val:
                    self._walk_node(val, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # -- Call nodes (FunctionCall / MethodCall / StaticMethodCall) -------------

    def _walk_call(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", 0)
        params = getattr(node, "params", []) or []

        callee_name = ""
        call_type = CgCallType.DIRECT

        if node_type_name == "FunctionCall":
            callee_name = getattr(node, "name", "")
            if not isinstance(callee_name, str):
                callee_name = self._expr_text(callee_name) if callee_name else ""
        elif node_type_name in ("MethodCall", "NullsafeMethodCall"):
            callee_name = getattr(node, "name", "")
            call_type = CgCallType.METHOD
        elif node_type_name == "StaticMethodCall":
            callee_name = getattr(node, "name", "")
            call_type = CgCallType.STATIC

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CALL.value,
                "callee": callee_name,
                "raw_type": node_type_name,
            },
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        # use edge to function (if callee is a simple name)
        if callee_name and isinstance(callee_name, str):
            # Create target function node (may be external)
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": callee_name,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": callee_name,
                    "type": FunctionType.FUNCTION.value,
                    "is_external": True,
                },
            })
            add_edge({"label": EdgeLabel.USE.value, "source": pos, "target": target_pos,
                       "attrs": {
                           "call_type": call_type.value,
                           "lineno": lineno,
                       }})

        # member edge: for method calls, the object is on the left
        if node_type_name in ("MethodCall", "NullsafeMethodCall"):
            obj_node = getattr(node, "node", None)
            if obj_node:
                obj_pos = self._walk_node(obj_node, add_node, add_edge, ctx_stack, file_path, 0)
                if obj_pos is not None:
                    # The callee name is a member of the object
                    member_pos = self._emit_identifier(
                        add_node, name=callee_name, lineno=lineno,
                        id_type=IdentifierType.PROPERTY, file_path=file_path,
                    )
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": obj_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.PROPERTY.value}})

        # ast edges for parameters
        for idx, param in enumerate(params):
            param_pos = self._walk_node(param, add_node, add_edge, ctx_stack, file_path, idx)
            if param_pos is not None:
                add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": param_pos,
                           "attrs": {"role": AstRole.ARG.value, "arg_index": idx}})

        return pos

    # -- Operator nodes -------------------------------------------------------

    def _walk_operator(self, node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        lineno = getattr(node, "lineno", 0)
        end_lineno = getattr(node, "end_lineno", 0)

        op_type = OperatorType.CALL  # fallback
        op_name = ""
        op_symbol = ""

        if node_type_name == "Assignment":
            op_type = OperatorType.ASSIGN
            target_node = getattr(node, "node", None)
            op_name = self._expr_text(target_node) if target_node else ""
        elif node_type_name == "AssignOp":
            op_type = OperatorType.AUG_ASSIGN
            op_symbol = getattr(node, "op", "")
            target_node = getattr(node, "left", None)
            op_name = self._expr_text(target_node) if target_node else ""
        elif node_type_name in ("BinaryOp",):
            op_type = OperatorType.BINARY_OP
            op_symbol = getattr(node, "op", "")
            op_name = op_symbol
        elif node_type_name in ("UnaryOp", "PostIncDecOp", "PreIncDecOp"):
            op_type = OperatorType.UNARY_OP
            op_symbol = getattr(node, "op", "")
            op_name = op_symbol
        elif node_type_name == "New":
            op_type = OperatorType.NEW
            op_name = self._expr_text(getattr(node, "name", None)) or ""
        elif node_type_name == "Cast":
            op_type = OperatorType.TYPE_CAST
            op_name = getattr(node, "type", "") or ""
        elif node_type_name == "Throw":
            op_type = OperatorType.THROW
        elif node_type_name == "Yield":
            op_type = OperatorType.YIELD
        elif node_type_name == "Break":
            op_type = OperatorType.BREAK
        elif node_type_name == "Continue":
            op_type = OperatorType.CONTINUE
        elif node_type_name == "Echo":
            op_type = OperatorType.CALL
            op_name = "echo"
        elif node_type_name == "Print":
            op_type = OperatorType.CALL
            op_name = "print"
        elif node_type_name == "Eval":
            op_type = OperatorType.CALL
            op_name = "eval"
        elif node_type_name == "Clone":
            op_type = OperatorType.CALL
            op_name = "clone"
        elif node_type_name == "Exit":
            op_type = OperatorType.CALL
            op_name = "exit"
        elif node_type_name == "Silence":
            op_type = OperatorType.UNARY_OP
            op_symbol = "@"
            op_name = "@"
        elif node_type_name == "IsSet":
            op_type = OperatorType.CALL
            op_name = "isset"
        elif node_type_name == "Empty":
            op_type = OperatorType.CALL
            op_name = "empty"
        elif node_type_name == "ListAssignment":
            op_type = OperatorType.ASSIGN

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
                "operator": op_symbol,
                "raw_type": node_type_name,
            },
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        # Walk children based on node type
        if node_type_name == "Assignment":
            target = getattr(node, "node", None)
            expr = getattr(node, "expr", None)
            if target:
                t_pos = self._walk_node(target, add_node, add_edge, ctx_stack, file_path, 0)
                if t_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": t_pos,
                               "attrs": {"role": AstRole.LHS.value}})
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.RHS.value}})

        elif node_type_name == "AssignOp":
            left = getattr(node, "left", None)
            right = getattr(node, "right", None)
            if left:
                l_pos = self._walk_node(left, add_node, add_edge, ctx_stack, file_path, 0)
                if l_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": l_pos,
                               "attrs": {"role": AstRole.LHS.value}})
            if right:
                r_pos = self._walk_node(right, add_node, add_edge, ctx_stack, file_path, 0)
                if r_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": r_pos,
                               "attrs": {"role": AstRole.RHS.value}})

        elif node_type_name == "BinaryOp":
            left = getattr(node, "left", None)
            right = getattr(node, "right", None)
            if left:
                l_pos = self._walk_node(left, add_node, add_edge, ctx_stack, file_path, 0)
                if l_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": l_pos,
                               "attrs": {"role": AstRole.LEFT.value}})
                elif isinstance(left, (str, int, float, bool)):
                    # phply string/number literals are raw Python types, not AST nodes
                    l_pos = add_node({
                        "label": NodeLabel.CONST.value,
                        "name": repr(left),
                        "lineno": getattr(node, "lineno", 0),
                        "language": self.language,
                        "attrs": {"type": "literal"},
                    })
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": l_pos,
                               "attrs": {"role": AstRole.LEFT.value}})
            if right:
                r_pos = self._walk_node(right, add_node, add_edge, ctx_stack, file_path, 0)
                if r_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": r_pos,
                               "attrs": {"role": AstRole.RIGHT.value}})
                elif isinstance(right, (str, int, float, bool)):
                    # phply string/number literals are raw Python types, not AST nodes
                    r_pos = add_node({
                        "label": NodeLabel.CONST.value,
                        "name": repr(right),
                        "lineno": getattr(node, "lineno", 0),
                        "language": self.language,
                        "attrs": {"type": "literal"},
                    })
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": r_pos,
                               "attrs": {"role": AstRole.RIGHT.value}})

        elif node_type_name in ("UnaryOp",):
            expr = getattr(node, "expr", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.OPERAND.value}})

        elif node_type_name in ("PostIncDecOp", "PreIncDecOp"):
            expr = getattr(node, "node", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.OPERAND.value}})

        elif node_type_name == "New":
            new_name = getattr(node, "name", None)
            if new_name:
                n_pos = self._walk_node(new_name, add_node, add_edge, ctx_stack, file_path, 0)
                if n_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": n_pos,
                               "attrs": {"role": AstRole.CALLEE.value}})
            for idx, param in enumerate(node.params if hasattr(node, "params") else []):
                p_pos = self._walk_node(param, add_node, add_edge, ctx_stack, file_path, idx)
                if p_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": p_pos,
                               "attrs": {"role": AstRole.ARG.value, "arg_index": idx}})

        elif node_type_name == "Cast":
            expr = getattr(node, "expr", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.OPERAND.value}})

        elif node_type_name in ("Throw",):
            expr = getattr(node, "node", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.VALUE.value}})

        elif node_type_name == "Silence":
            expr = getattr(node, "expr", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.OPERAND.value}})

        elif node_type_name == "Echo":
            # Echo uses `nodes` (list of expressions)
            echo_nodes = getattr(node, "nodes", []) or []
            for idx, en in enumerate(echo_nodes):
                e_pos = self._walk_node(en, add_node, add_edge, ctx_stack, file_path, idx)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.ARG.value, "arg_index": idx}})

        elif node_type_name == "Eval":
            # Eval uses `expr` attribute for its single argument
            eval_expr = getattr(node, "expr", None)
            if eval_expr:
                e_pos = self._walk_node(eval_expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.ARG.value, "arg_index": 0}})

        elif node_type_name == "Print":
            # Print has a single child via `node`, not `nodes`
            echo_expr = getattr(node, "node", None)
            if echo_expr:
                e_pos = self._walk_node(echo_expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                              "attrs": {"role": AstRole.ARG.value, "arg_index": 0}})

        elif node_type_name in ("IsSet", "Empty"):
            check_nodes = getattr(node, "nodes", []) or []
            for idx, cn in enumerate(check_nodes):
                c_pos = self._walk_node(cn, add_node, add_edge, ctx_stack, file_path, idx)
                if c_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": c_pos,
                               "attrs": {"role": AstRole.ARG.value, "arg_index": idx}})

        elif node_type_name == "ListAssignment":
            list_nodes = getattr(node, "nodes", []) or []
            expr = getattr(node, "expr", None)
            for idx, ln in enumerate(list_nodes):
                l_pos = self._walk_node(ln, add_node, add_edge, ctx_stack, file_path, idx)
                if l_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": l_pos,
                               "attrs": {"role": AstRole.LHS.value, "arg_index": idx}})
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.RHS.value}})

        elif node_type_name == "Yield":
            expr = getattr(node, "node", None)
            if expr:
                e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
                if e_pos is not None:
                    add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                               "attrs": {"role": AstRole.VALUE.value}})

        # Fallback: walk any remaining children
        elif hasattr(node, "children"):
            idx = 0
            for attr_name, child in node.children():
                if child is not None:
                    self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
                    idx += 1

        return pos

    # -- Return ---------------------------------------------------------------

    def _walk_return(self, node, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        lineno = getattr(node, "lineno", 0)

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "",
            "lineno": lineno,
            "language": self.language,
            "attrs": {},
        })

        # own edge from context
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({"label": EdgeLabel.OWN.value, "source": ctx[0], "target": pos,
                       "attrs": {"index": depth}})

        expr = getattr(node, "node", None)
        if expr:
            e_pos = self._walk_node(expr, add_node, add_edge, ctx_stack, file_path, 0)
            if e_pos is not None:
                add_edge({"label": EdgeLabel.AST.value, "source": pos, "target": e_pos,
                           "attrs": {"role": AstRole.VALUE.value}})

        return pos

    # -- Identifier / Const helpers -------------------------------------------

    def _emit_identifier(self, add_node, name: str, lineno: int, id_type, file_path: str) -> int:
        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": id_type.value,
                "file_path": file_path,
            },
        })
        return pos

    def _emit_const(self, add_node, name: str, lineno: int, const_type) -> int:
        pos = add_node({
            "label": NodeLabel.CONST.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": const_type.value,
            },
        })
        return pos

    # -- ObjectProperty / ArrayOffset / StaticProperty → member edges ----------

    def _walk_node(self, ast_node, add_node, add_edge, ctx_stack, file_path, depth) -> int | None:
        """Override the main _walk_node to handle member access patterns."""
        if ast_node is None:
            return None

        if isinstance(ast_node, list):
            for child in ast_node:
                self._walk_node(child, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        # Python primitive types from phply (string/int literals in params etc.)
        if isinstance(ast_node, (str, int, float, bool)):
            return self._emit_const(add_node, name=repr(ast_node),
                                    lineno=0, const_type=ConstType.STRING)

        node_type_name = type(ast_node).__name__
        lineno = getattr(ast_node, "lineno", 0)

        # -- ObjectProperty → member edge -------------------------------------
        if node_type_name == "ObjectProperty":
            obj = getattr(ast_node, "node", None)
            prop_name = getattr(ast_node, "name", "")
            if obj:
                obj_pos = self._walk_node(obj, add_node, add_edge, ctx_stack, file_path, 0)
                member_pos = self._emit_identifier(
                    add_node, name=prop_name, lineno=lineno,
                    id_type=IdentifierType.PROPERTY, file_path=file_path,
                )
                if obj_pos is not None:
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": obj_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.PROPERTY.value}})
                return member_pos
            return self._emit_identifier(add_node, name=prop_name, lineno=lineno,
                                        id_type=IdentifierType.PROPERTY, file_path=file_path)

        # -- NullsafeProperty → member edge -----------------------------------
        if node_type_name == "NullsafeProperty":
            obj = getattr(ast_node, "node", None)
            prop_name = getattr(ast_node, "name", "")
            if obj:
                obj_pos = self._walk_node(obj, add_node, add_edge, ctx_stack, file_path, 0)
                member_pos = self._emit_identifier(
                    add_node, name=prop_name, lineno=lineno,
                    id_type=IdentifierType.PROPERTY, file_path=file_path,
                )
                if obj_pos is not None:
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": obj_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.PROPERTY.value}})
                return member_pos

        # -- ArrayOffset → member edge ----------------------------------------
        if node_type_name == "ArrayOffset":
            arr = getattr(ast_node, "node", None)
            idx_expr = getattr(ast_node, "expr", None)
            if arr:
                arr_pos = self._walk_node(arr, add_node, add_edge, ctx_stack, file_path, 0)
                # The index expression becomes the member
                idx_name = self._expr_text(idx_expr) if idx_expr else "?"
                member_pos = self._emit_identifier(
                    add_node, name=idx_name, lineno=lineno,
                    id_type=IdentifierType.PROPERTY, file_path=file_path,
                )
                if arr_pos is not None:
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": arr_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.ARRAY_OFFSET.value}})
                return member_pos

        # -- StaticProperty → member edge -------------------------------------
        if node_type_name == "StaticProperty":
            cls_ref = getattr(ast_node, "node", None)
            prop_name = getattr(ast_node, "name", "")
            if cls_ref:
                cls_pos = self._walk_node(cls_ref, add_node, add_edge, ctx_stack, file_path, 0)
                member_pos = self._emit_identifier(
                    add_node, name=prop_name, lineno=lineno,
                    id_type=IdentifierType.STATIC, file_path=file_path,
                )
                if cls_pos is not None:
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": cls_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.STATIC_PROPERTY.value}})
                return member_pos

        # -- StringOffset → member edge ---------------------------------------
        if node_type_name == "StringOffset":
            obj = getattr(ast_node, "node", None)
            idx_expr = getattr(ast_node, "expr", None)
            if obj:
                obj_pos = self._walk_node(obj, add_node, add_edge, ctx_stack, file_path, 0)
                idx_name = self._expr_text(idx_expr) if idx_expr else "?"
                member_pos = self._emit_const(add_node, name=idx_name, lineno=lineno,
                                              const_type=ConstType.STRING)
                if obj_pos is not None:
                    add_edge({"label": EdgeLabel.MEMBER.value, "source": obj_pos, "target": member_pos,
                               "attrs": {"access_type": MemberAccessType.ARRAY_OFFSET.value}})
                return member_pos

        # -- ForeachVariable --------------------------------------------------
        if node_type_name == "ForeachVariable":
            var = getattr(ast_node, "node", None)
            if var:
                return self._walk_node(var, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        # -- ClassVariable / StaticVariable → identifier -------------------------
        if node_type_name in ("ClassVariable", "StaticVariable"):
            var_name = getattr(ast_node, "name", "")
            id_type = IdentifierType.STATIC if node_type_name == "StaticVariable" else IdentifierType.PROPERTY
            pos = self._emit_identifier(add_node, name=var_name, lineno=lineno,
                                         id_type=id_type, file_path=file_path)
            initial = getattr(ast_node, "initial", None)
            if initial:
                init_pos = self._walk_node(initial, add_node, add_edge, ctx_stack, file_path, 0)
            return pos

        # -- ClassConstant → const --------------------------------------------
        if node_type_name == "ClassConstant":
            const_name = getattr(ast_node, "name", "")
            return self._emit_const(add_node, name=const_name, lineno=lineno,
                                    const_type=ConstType.CONSTANT)

        # -- MagicConstant (e.g. __FILE__, __LINE__) → const -------------------
        if node_type_name == "MagicConstant":
            const_name = getattr(ast_node, "name", "")
            return self._emit_const(add_node, name=const_name, lineno=lineno,
                                    const_type=ConstType.CONSTANT)

        # -- Global / LexicalVariable → identifier -----------------------------
        if node_type_name == "Global":
            var_name = getattr(ast_node, "name", "")
            if var_name:
                return self._emit_identifier(add_node, name=var_name, lineno=lineno,
                                              id_type=IdentifierType.GLOBAL, file_path=file_path)
            return None

        if node_type_name == "LexicalVariable":
            var_name = getattr(ast_node, "name", "")
            if var_name:
                return self._emit_identifier(add_node, name=var_name, lineno=lineno,
                                              id_type=IdentifierType.VARIABLE, file_path=file_path)
            return None

        # -- Parameter (function call argument wrapper in phply) ---------------
        if node_type_name == "Parameter":
            # phply wraps FunctionCall/MethodCall arguments in Parameter nodes.
            # The actual expression is in the `node` attribute.
            expr_node = getattr(ast_node, "node", None)
            if expr_node:
                return self._walk_node(expr_node, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        # -- NamedParameter → identifier ---------------------------------------
        if node_type_name == "NamedParameter":
            param_name = getattr(ast_node, "name", "")
            if param_name:
                return self._emit_identifier(add_node, name=param_name, lineno=lineno,
                                              id_type=IdentifierType.VARIABLE, file_path=file_path)
            return None

        # Delegate to the main walk for all other node types
        return self._walk_node_base(ast_node, add_node, add_edge, ctx_stack, file_path, depth)

    def _walk_node_base(self, ast_node, add_node, add_edge, ctx_stack, file_path, depth) -> int | None:
        """The original walk logic for non-member nodes."""
        if ast_node is None:
            return None

        if isinstance(ast_node, list):
            for child in ast_node:
                self._walk_node_base(child, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        node_type_name = type(ast_node).__name__
        lineno = getattr(ast_node, "lineno", 0)

        if node_type_name in _CLASS_NODES:
            return self._walk_class(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name in _FUNCTION_NODES:
            return self._walk_function(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name in _IMPORT_NODES:
            return self._walk_import(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name in _BRANCH_NODES:
            return self._walk_branch(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name in _CALL_NODES:
            return self._walk_call(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name in _OPERATOR_NODES:
            return self._walk_operator(ast_node, node_type_name, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name == "Variable":
            name = getattr(ast_node, "name", "")
            return self._emit_identifier(add_node, name=name, lineno=lineno,
                                          id_type=IdentifierType.VARIABLE, file_path=file_path)
        if node_type_name == "Constant":
            name = getattr(ast_node, "name", "")
            return self._emit_const(add_node, name=name, lineno=lineno,
                                    const_type=ConstType.CONSTANT)
        if node_type_name == "Return":
            return self._walk_return(ast_node, add_node, add_edge, ctx_stack, file_path, depth)
        if node_type_name == "Namespace":
            child_nodes = getattr(ast_node, "nodes", [])
            if child_nodes:
                for child in child_nodes:
                    self._walk_node(child, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        # Block: transparent wrapper, walk its nodes directly
        if node_type_name == "Block":
            block_nodes = getattr(ast_node, "nodes", []) or []
            for idx, child in enumerate(block_nodes):
                self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
            return None

        # Fallback: walk children
        if hasattr(ast_node, "children"):
            for attr_name, child in ast_node.children():
                if child is not None:
                    self._walk_node(child, add_node, add_edge, ctx_stack, file_path, depth)
            return None

        return None

    # -- Utility: extract text representation of an expression ----------------

    def _expr_text(self, node) -> str:
        """Best-effort extraction of a text representation from an AST node."""
        if node is None:
            return ""
        if isinstance(node, str):
            return node
        if isinstance(node, phpast.Variable):
            return node.name  # phply already includes the $ prefix
        if isinstance(node, phpast.Constant):
            return node.name
        if isinstance(node, phpast.ObjectProperty):
            obj_text = self._expr_text(node.node)
            return f"{obj_text}->{node.name}"
        if isinstance(node, phpast.ArrayOffset):
            arr_text = self._expr_text(node.node)
            idx_text = self._expr_text(node.expr)
            return f"{arr_text}[{idx_text}]"
        if isinstance(node, phpast.StaticProperty):
            cls_text = self._expr_text(node.node)
            return f"{cls_text}::{node.name}"
        if isinstance(node, phpast.FunctionCall):
            return f"{self._expr_text(node.name)}()"
        if isinstance(node, phpast.MethodCall):
            return f"{self._expr_text(node.node)}->{node.name}()"
        if isinstance(node, phpast.StaticMethodCall):
            cls_text = self._expr_text(node.class_)
            return f"{cls_text}::{node.name}()"
        if isinstance(node, phpast.BinaryOp):
            return f"{self._expr_text(node.left)} {node.op} {self._expr_text(node.right)}"
        if isinstance(node, phpast.Assignment):
            return f"{self._expr_text(node.node)} = {self._expr_text(node.expr)}"
        if isinstance(node, phpast.Cast):
            return f"({node.type}){self._expr_text(node.expr)}"
        return str(getattr(node, "name", "")) or type(node).__name__
