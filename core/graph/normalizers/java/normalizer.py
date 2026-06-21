"""Java AST Normalizer — maps javalang AST output to UnifiedNode / UnifiedEdge.

Converts Java source parsed by ``javalang.parse.parse()`` into the unified
intermediate representation used by the AST graph engine.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from core.graph.node_edge_schema import (
    NodeLabel,
    EdgeLabel,
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
# javalang node type → classification sets
# ---------------------------------------------------------------------------

_CLASS_TYPES = {
    "ClassDeclaration", "EnumDeclaration", "InterfaceDeclaration",
    "RecordDeclaration",
}

_FUNCTION_TYPES = {
    "MethodDeclaration", "ConstructorDeclaration",
    "LambdaExpression",
}

_CALL_TYPES = {
    "MethodInvocation",
}

_BRANCH_TYPES = {
    "IfStatement", "TernaryExpression",
    "ForStatement", "WhileStatement", "DoStatement",
    "SwitchStatement", "SwitchStatementCase",
    "TryStatement", "CatchClause",
}

_IMPORT_TYPES = {
    "Import",
}

_BINARY_OP_TYPES = {
    "BinaryOperation",
}


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts javalang AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=javalang.parse.parse(source),
            file_path="/path/to/File.java",
            source_content=source,
        )
    """

    language = "java"

    def normalize(
        self,
        ast_nodes: Any,
        file_path: str,
        source_content: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        content_hash = ""
        if source_content:
            content_hash = hashlib.md5(
                source_content.encode("utf-8", errors="ignore")
            ).hexdigest()

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

        def _add_node(nd: dict[str, Any]) -> int:
            pos = len(nodes)
            nodes.append(nd)
            return pos

        def _add_edge(ed: dict[str, Any]) -> None:
            edges.append(ed)

        file_pos = _add_node(file_node)
        ctx_stack: list[tuple[int, str]] = [(file_pos, NodeLabel.FILE.value)]

        # CompilationUnit: imports + types
        imports = getattr(ast_nodes, "import", None) or getattr(ast_nodes, "imports", []) or []
        for imp in imports:
            self._walk_node(imp, _add_node, _add_edge, ctx_stack, file_path, 0)

        top_types = getattr(ast_nodes, "types", []) or []
        top_idx = len(imports)
        for td in top_types:
            self._walk_node(td, _add_node, _add_edge, ctx_stack, file_path, top_idx)
            top_idx += 1

        assert nodes[0] is file_node
        return file_node, nodes[1:], edges

    # ===================================================================
    # Walk dispatch
    # ===================================================================

    def _walk_node(
        self,
        ast_node: Any,
        add_node,
        add_edge,
        ctx_stack: list[tuple[int, str]],
        file_path: str,
        depth: int,
    ) -> int | None:
        if ast_node is None:
            return None

        node_type = type(ast_node).__name__

        # ---- Class ----------------------------------------------------
        if node_type in _CLASS_TYPES:
            return self._walk_class(ast_node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Function / Method / Constructor / Lambda ----------------
        if node_type in _FUNCTION_TYPES:
            return self._walk_function(ast_node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Import ----------------------------------------------------
        if node_type in _IMPORT_TYPES:
            return self._walk_import(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Branch: IfStatement --------------------------------------
        if node_type == "IfStatement":
            return self._walk_if(ast_node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: TernaryExpression --------------------------------
        if node_type == "TernaryExpression":
            return self._walk_ternary(ast_node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Branch: ForStatement -------------------------------------
        if node_type == "ForStatement":
            return self._walk_for(ast_node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Branch: WhileStatement -----------------------------------
        if node_type == "WhileStatement":
            return self._walk_while(ast_node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Branch: DoStatement --------------------------------------
        if node_type == "DoStatement":
            return self._walk_do_while(ast_node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Branch: SwitchStatement ----------------------------------
        if node_type == "SwitchStatement":
            return self._walk_switch(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Branch: TryStatement ------------------------------------
        if node_type == "TryStatement":
            return self._walk_try(ast_node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Operators -----------------------------------------------
        if node_type == "MethodInvocation":
            return self._walk_call(ast_node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        if node_type == "ClassCreator":
            return self._walk_new(ast_node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        if node_type == "Assignment":
            return self._walk_assign(ast_node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        if node_type in _BINARY_OP_TYPES:
            return self._walk_binary(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if node_type == "This":
            return self._emit_identifier(add_node, "this", 0,
                                           IdentifierType.THIS)

        if node_type == "MemberReference":
            return self._walk_member_ref(ast_node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        if node_type == "Cast":
            return self._walk_cast(ast_node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        if node_type == "SuperMethodInvocation":
            return self._walk_super_call(ast_node, add_node, add_edge,
                                          ctx_stack, file_path, depth)

        if node_type == "SuperConstructorInvocation":
            return self._walk_super_call(ast_node, add_node, add_edge,
                                          ctx_stack, file_path, depth)

        # ---- Control flow ---------------------------------------------
        if node_type == "ReturnStatement":
            return self._walk_return(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if node_type == "ThrowStatement":
            return self._walk_throw(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if node_type == "BreakStatement":
            return self._walk_break(add_node, add_edge, ctx_stack, file_path,
                                     depth)

        if node_type == "ContinueStatement":
            return self._walk_continue(add_node, add_edge, ctx_stack, file_path,
                                        depth)

        if node_type == "YieldStatement":
            return self._walk_yield(ast_node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        if node_type == "AssertStatement":
            return self._walk_assert(ast_node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if node_type == "SynchronizedStatement":
            return self._walk_synchronized(ast_node, add_node, add_edge,
                                            ctx_stack, file_path, depth)

        # ---- Variable declarations ------------------------------------
        if node_type == "LocalVariableDeclaration":
            return self._walk_var_decl(ast_node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        if node_type == "FieldDeclaration":
            return self._walk_field_decl(ast_node, add_node, add_edge,
                                          ctx_stack, file_path, depth)

        # ---- Statements -----------------------------------------------
        if node_type == "BlockStatement":
            return self._walk_block(ast_node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        if node_type == "StatementExpression":
            return self._walk_expr_stmt(ast_node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Leaf nodes -----------------------------------------------
        if node_type == "Literal":
            return self._walk_literal(ast_node, add_node, file_path)

        if node_type == "Annotation":
            return self._walk_annotation(ast_node, add_node, add_edge,
                                           ctx_stack, file_path, depth)

        # ---- Fallback: walk children ----------------------------------
        return self._walk_children(ast_node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Leaf helpers
    # ===================================================================

    def _emit_identifier(self, add_node, name: str, lineno: int,
                          id_type: IdentifierType) -> int:
        return add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {"type": id_type.value},
        })

    def _emit_const(self, add_node, name: str, lineno: int,
                     const_type: ConstType) -> int:
        return add_node({
            "label": NodeLabel.CONST.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {"type": const_type.value},
        })

    def _own_edge(self, add_edge, ctx_stack, pos, depth):
        if ctx_stack:
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": ctx_stack[-1][0],
                "target": pos,
                "attrs": {"index": depth},
            })

    def _ast_edge(self, add_edge, source, target, role: str, extra=None):
        attrs: dict[str, Any] = {"role": role}
        if extra:
            attrs.update(extra)
        add_edge({
            "label": EdgeLabel.AST.value,
            "source": source,
            "target": target,
            "attrs": attrs,
        })

    # ===================================================================
    # Location helper
    # ===================================================================

    @staticmethod
    def _loc(node) -> tuple[int, int]:
        lineno = 0
        pos = getattr(node, "position", None)
        if pos and hasattr(pos, "line"):
            lineno = pos.line
        return lineno, lineno  # javalang doesn't provide end_lineno reliably

    # ===================================================================
    # Class
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        name = getattr(node, "name", "") or "<anonymous>"
        node_type = type(node).__name__

        cls_type = ClassType.CLASS.value
        if node_type == "InterfaceDeclaration":
            cls_type = ClassType.INTERFACE.value
        elif node_type == "EnumDeclaration":
            cls_type = ClassType.ENUM.value
        elif node_type == "RecordDeclaration":
            cls_type = ClassType.CLASS.value

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": cls_type,
                "raw_type": node_type,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # CRG: extends
        extends = getattr(node, "extends", None)
        if extends is not None:
            ext_name = getattr(extends, "name", "")
            if ext_name:
                parent_pos = add_node({
                    "label": NodeLabel.CLASS.value,
                    "name": ext_name,
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "fullname": ext_name,
                        "type": ClassType.CLASS.value,
                        "is_external": True,
                    },
                })
                add_edge({
                    "label": EdgeLabel.CRG.value,
                    "source": pos,
                    "target": parent_pos,
                    "attrs": {"type": CrgType.EXTENDS.value},
                })

        # CRG: implements
        implements = getattr(node, "implements", []) or []
        for impl in implements:
            impl_name = getattr(impl, "name", "")
            if impl_name:
                impl_pos = add_node({
                    "label": NodeLabel.CLASS.value,
                    "name": impl_name,
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "fullname": impl_name,
                        "type": ClassType.INTERFACE.value,
                        "is_external": True,
                    },
                })
                add_edge({
                    "label": EdgeLabel.CRG.value,
                    "source": pos,
                    "target": impl_pos,
                    "attrs": {"type": CrgType.IMPLEMENTS.value},
                })

        # Annotations
        annotations = getattr(node, "annotations", []) or []
        for ann in annotations:
            self._walk_node(ann, add_node, add_edge, ctx_stack, file_path, 0)

        # Body (methods, fields, inner classes)
        body = getattr(node, "body", []) or []
        ctx_stack.append((pos, NodeLabel.CLASS.value))
        for idx, child in enumerate(body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path,
                           idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Function / Method / Constructor / Lambda
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        node_type = type(node).__name__

        if node_type == "MethodDeclaration":
            name = getattr(node, "name", "") or "<anonymous>"
            return_type = getattr(node, "return_type", "")
            modifiers = getattr(node, "modifiers", set()) or set()
            is_static = "static" in modifiers
        elif node_type == "ConstructorDeclaration":
            name = getattr(node, "name", "") or "<init>"
            return_type = ""
            modifiers = getattr(node, "modifiers", set()) or set()
            is_static = False
        elif node_type == "LambdaExpression":
            name = "<lambda>"
            return_type = ""
            modifiers = set()
            is_static = False
        else:
            name = "<anonymous>"
            return_type = ""
            modifiers = set()
            is_static = False

        # Parameters
        params = getattr(node, "parameters", []) or []
        param_strs = []
        for p in params:
            pname = getattr(p, "name", "?")
            ptype = getattr(p, "type", None)
            type_text = self._type_text(ptype) if ptype else "?"
            param_strs.append(f"{type_text} {pname}")

        signature = f"{name}({', '.join(param_strs)})"
        if return_type:
            rt_text = self._type_text(return_type) if not isinstance(return_type, str) else return_type
            signature = f"{rt_text} {signature}"

        if node_type == "ConstructorDeclaration":
            func_type = FunctionType.CONSTRUCTOR.value
        elif node_type == "LambdaExpression":
            func_type = FunctionType.LAMBDA.value
        else:
            func_type = FunctionType.METHOD.value

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": func_type,
                "signature": signature,
                "file_path": file_path,
                "raw_type": node_type,
                "static": is_static,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Annotations
        annotations = getattr(node, "annotations", []) or []
        for ann in annotations:
            self._walk_node(ann, add_node, add_edge, ctx_stack, file_path, 0)

        # Push context
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, param in enumerate(params):
            p_pos = self._walk_parameter(param, add_node, file_path)
            if p_pos is not None:
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": p_pos,
                    "attrs": {"index": idx},
                })

        # Body
        body = getattr(node, "body", None)
        if body is not None:
            if isinstance(body, list):
                body_offset = len(params)
                for child_idx, child in enumerate(body):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, body_offset + child_idx)
            elif hasattr(body, "statements"):
                body_offset = len(params)
                for child_idx, child in enumerate(body.statements or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, body_offset + child_idx)
            elif isinstance(body, type(node)):  # Could be a Node
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, len(params))

        ctx_stack.pop()
        return pos

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        if param_node is None:
            return None
        lineno, _ = self._loc(param_node)
        name = getattr(param_node, "name", "")
        if not name:
            return None
        ptype = getattr(param_node, "type", None)
        type_text = self._type_text(ptype) if ptype else ""

        return add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "java_type": type_text,
                "file_path": file_path,
            },
        })

    # ===================================================================
    # Type text helper
    # ===================================================================

    @staticmethod
    def _type_text(tnode) -> str:
        if tnode is None:
            return ""
        if isinstance(tnode, str):
            return tnode
        name = getattr(tnode, "name", "") or ""
        return name

    # ===================================================================
    # Import
    # ===================================================================

    def _walk_import(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        path = getattr(node, "path", "") or ""
        static = getattr(node, "static", False)
        import_type = ImportType.IMPORT.value

        name = path
        if static:
            name = f"static {path}"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": import_type,
                "source": path,
                "raw_type": "Import",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if path:
            dep_pos = add_node({
                "label": NodeLabel.DEPENDENCY.value,
                "name": path,
                "lineno": lineno,
                "language": self.language,
                "attrs": {"source": path},
            })
            add_edge({
                "label": EdgeLabel.FRG.value,
                "source": pos,
                "target": dep_pos,
                "attrs": {"type": FrgType.IMPORT.value},
            })

        return pos

    # ===================================================================
    # Branch: IfStatement
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        condition = getattr(node, "condition", None)
        then_stmt = getattr(node, "then_statement", None)
        else_stmt = getattr(node, "else_statement", None)

        cond_text = self._expr_text(condition)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text or "<if>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": cond_text,
                "raw_type": "IfStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # condition
        if condition is not None:
            cond_pos = self._walk_node(condition, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # then
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if then_stmt is not None:
            self._walk_stmt_list(then_stmt, add_node, add_edge, ctx_stack,
                                file_path, 0)
        ctx_stack.pop()

        # else / elif
        if else_stmt is not None:
            elif_node = else_stmt
            # Check if it's an elif (else with IfStatement inside)
            if isinstance(else_stmt, type(node)) and type(else_stmt).__name__ == "IfStatement":
                # elif
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                self._walk_if(else_stmt, add_node, add_edge, ctx_stack,
                              file_path, depth + 1)
                ctx_stack.pop()
            elif hasattr(else_stmt, "statements"):
                # else block
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<else>",
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "condition": "",
                        "raw_type": "Else",
                    },
                })
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)
                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                for idx, stmt in enumerate(else_stmt.statements or []):
                    self._walk_node(stmt, add_node, add_edge, ctx_stack,
                                   file_path, idx)
                ctx_stack.pop()
            else:
                # else with single statement
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<else>",
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "condition": "",
                        "raw_type": "Else",
                    },
                })
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)
                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                self._walk_node(else_stmt, add_node, add_edge, ctx_stack,
                               file_path, 0)
                ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: TernaryExpression
    # ===================================================================

    def _walk_ternary(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        condition = getattr(node, "condition", None)
        if_true = getattr(node, "if_true", None)
        if_false = getattr(node, "if_false", None)

        cond_text = self._expr_text(condition)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text or "<ternary>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TERNARY.value,
                "condition": cond_text,
                "raw_type": "TernaryExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if condition is not None:
            cond_pos = self._walk_node(condition, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        if if_true is not None:
            true_pos = self._walk_node(if_true, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if true_pos is not None:
                self._ast_edge(add_edge, pos, true_pos, AstRole.IFTRUE.value)

        if if_false is not None:
            false_pos = self._walk_node(if_false, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if false_pos is not None:
                self._ast_edge(add_edge, pos, false_pos, AstRole.IFFALSE.value)

        return pos

    # ===================================================================
    # Branch: ForStatement
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        control = getattr(node, "control", None)
        body = getattr(node, "body", None)

        node_dict = {
            "label": NodeLabel.BRANCH.value,
            "name": "<for>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": "",
                "raw_type": "ForStatement",
            },
        }
        pos = add_node(node_dict)

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if control is not None:
            ctrl_type = type(control).__name__

            if ctrl_type == "ForControl":
                init = getattr(control, "init", None)
                cond = getattr(control, "condition", None)
                update = getattr(control, "update", []) or []

                ctrl_condition = self._expr_text(cond)
                node_dict["attrs"]["condition"] = ctrl_condition

                if init is not None:
                    init_pos = self._walk_node(init, add_node, add_edge,
                                                ctx_stack, file_path, 0)
                    if init_pos is not None:
                        self._ast_edge(add_edge, pos, init_pos, AstRole.LHS.value)

                if cond is not None:
                    cond_pos = self._walk_node(cond, add_node, add_edge,
                                                ctx_stack, file_path, 0)
                    if cond_pos is not None:
                        self._ast_edge(add_edge, pos, cond_pos,
                                        AstRole.CONDITION.value)

                for upd in update:
                    upd_pos = self._walk_node(upd, add_node, add_edge,
                                               ctx_stack, file_path, 0)
                    if upd_pos is not None:
                        self._ast_edge(add_edge, pos, upd_pos, AstRole.RHS.value)

            elif ctrl_type == "EnhancedForControl":
                var = getattr(control, "var", None)
                iterable = getattr(control, "iterable", None)

                # Change type to foreach
                node_dict["attrs"]["type"] = BranchType.FOREACH.value
                node_dict["name"] = "<for-each>"

                if var is not None:
                    var_pos = self._walk_node(var, add_node, add_edge,
                                               ctx_stack, file_path, 0)
                    if var_pos is not None:
                        self._ast_edge(add_edge, pos, var_pos, AstRole.LHS.value)

                if iterable is not None:
                    iter_pos = self._walk_node(iterable, add_node, add_edge,
                                                ctx_stack, file_path, 0)
                    if iter_pos is not None:
                        self._ast_edge(add_edge, pos, iter_pos,
                                        AstRole.RHS.value)

        # Body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            self._walk_stmt_list(body, add_node, add_edge, ctx_stack,
                                file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: WhileStatement
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        condition = getattr(node, "condition", None)
        body = getattr(node, "body", None)

        cond_text = self._expr_text(condition)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text or "<while>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": cond_text,
                "raw_type": "WhileStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if condition is not None:
            cond_pos = self._walk_node(condition, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            self._walk_stmt_list(body, add_node, add_edge, ctx_stack,
                                file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: DoStatement
    # ===================================================================

    def _walk_do_while(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        body = getattr(node, "body", None)
        condition = getattr(node, "condition", None)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<do-while>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": self._expr_text(condition),
                "raw_type": "DoStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            self._walk_stmt_list(body, add_node, add_edge, ctx_stack,
                                file_path, 0)

        if condition is not None:
            cond_pos = self._walk_node(condition, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: SwitchStatement
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        expression = getattr(node, "expression", None)
        cases = getattr(node, "cases", []) or []

        subject = self._expr_text(expression)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"switch {subject}" if subject else "<switch>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": subject,
                "raw_type": "SwitchStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expression is not None:
            expr_pos = self._walk_node(expression, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.CONDITION.value)

        for c_idx, case in enumerate(cases):
            case_val = getattr(case, "case", None)
            statements = getattr(case, "statements", []) or []

            # javalang: case_val is a list (Java supports "case a, b:")
            if not case_val:  # None or empty list
                case_name = "<default>"
                case_type = BranchType.DEFAULT.value
            else:
                # case_val is a list of Literal nodes
                case_parts = [self._expr_text(v) for v in case_val if v is not None]
                case_name = ", ".join(case_parts) if case_parts else f"<case {c_idx}>"
                case_type = BranchType.CASE.value

            case_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": case_name or f"<case {c_idx}>",
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "type": case_type,
                    "condition": case_name if case_val else "",
                    "raw_type": "SwitchStatementCase",
                },
            })

            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": case_pos,
                "attrs": {"index": c_idx},
            })

            if case_val:
                for val_item in case_val:
                    if val_item is not None:
                        val_pos = self._walk_node(val_item, add_node, add_edge,
                                                    ctx_stack, file_path, 0)
                        if val_pos is not None:
                            self._ast_edge(add_edge, case_pos, val_pos,
                                           AstRole.CONDITION.value)

            ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
            for idx, stmt in enumerate(statements):
                self._walk_node(stmt, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: TryStatement
    # ===================================================================

    def _walk_try(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        block = getattr(node, "block", None)
        catches = getattr(node, "catches", []) or []
        finally_block = getattr(node, "finally_block", None)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<try>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TRY.value,
                "condition": "",
                "raw_type": "TryStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # try body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if block is not None:
            self._walk_stmt_list(block, add_node, add_edge, ctx_stack,
                                file_path, 0)

        # catches
        for c_idx, cc in enumerate(catches):
            catch_pos = self._walk_catch(cc, add_node, add_edge, ctx_stack,
                                          file_path, 0)
            if catch_pos is not None:
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": catch_pos,
                    "attrs": {"index": 1 + c_idx},
                })
        ctx_stack.pop()

        # finally
        if finally_block is not None:
            fin_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": "<finally>",
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "type": BranchType.FINALLY.value,
                    "condition": "",
                    "raw_type": "Finally",
                },
            })
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": fin_pos,
                "attrs": {"index": 1 + len(catches)},
            })
            ctx_stack.append((fin_pos, NodeLabel.BRANCH.value))
            self._walk_stmt_list(finally_block, add_node, add_edge, ctx_stack,
                                 file_path, 0)
            ctx_stack.pop()

        return pos

    def _walk_catch(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        parameter = getattr(node, "parameter", None)
        block = getattr(node, "block", None)

        exc_name = ""
        exc_types = []
        if parameter is not None:
            exc_name = getattr(parameter, "name", "")
            exc_types = getattr(parameter, "types", []) or []
            exc_type_text = ", ".join(self._type_text(t) for t in exc_types)
        else:
            exc_type_text = ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"catch {exc_name}" if exc_name else "<catch>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CATCH.value,
                "condition": exc_name,
                "exception_name": exc_name,
                "exception_type": exc_type_text,
                "raw_type": "CatchClause",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk exception type(s)
        for et in exc_types:
            et_pos = self._walk_node(et, add_node, add_edge, ctx_stack,
                                      file_path, 0)
            if et_pos is not None:
                self._ast_edge(add_edge, pos, et_pos, AstRole.CONDITION.value)

        # Walk block
        if block is not None:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_stmt_list(block, add_node, add_edge, ctx_stack,
                                file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Operator: MethodInvocation
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        qualifier = getattr(node, "qualifier", None)
        member = getattr(node, "member", "")
        arguments = getattr(node, "arguments", []) or []
        selectors = getattr(node, "selectors", []) or []

        # Detect static calls: qualifier is a plain type name (str), not a node
        is_static_call = qualifier is not None and isinstance(qualifier, str)
        if is_static_call:
            call_type = OperatorType.STATIC_CALL.value
            cg_call_type = CgCallType.STATIC
            callee_text = qualifier + "." + member
            func_name = member
            func_fullname = callee_text
        elif qualifier:
            call_type = OperatorType.METHOD_CALL.value
            cg_call_type = CgCallType.METHOD
            callee_text = self._expr_text(qualifier) + "." + member
            func_name = member
            func_fullname = callee_text
        else:
            call_type = OperatorType.CALL.value
            cg_call_type = CgCallType.DIRECT
            callee_text = member
            func_name = callee_text
            func_fullname = callee_text

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": call_type,
                "raw_type": "MethodInvocation",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # qualifier
        if qualifier is not None:
            q_pos = self._walk_node(qualifier, add_node, add_edge, ctx_stack,
                                      file_path, 0)
            if q_pos is not None:
                self._ast_edge(add_edge, pos, q_pos, AstRole.CALLEE.value)

        # member name as identifier
        if member:
            mem_pos = self._emit_identifier(add_node, member, lineno,
                                              IdentifierType.PROPERTY)
            self._ast_edge(add_edge, pos, mem_pos, AstRole.CALLEE.value)

        # arguments
        for idx, arg in enumerate(arguments):
            arg_pos = self._walk_node(arg, add_node, add_edge, ctx_stack,
                                       file_path, idx)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                               extra={"arg_index": idx})

        # selectors (chain)
        for sel in selectors:
            self._walk_node(sel, add_node, add_edge, ctx_stack, file_path, 0)

        # use edge to function (callee target, may be external)
        if func_name and isinstance(func_name, str):
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": func_name,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": func_fullname,
                    "type": FunctionType.FUNCTION.value,
                    "is_external": True,
                },
            })
            add_edge({"label": EdgeLabel.USE.value, "source": pos, "target": target_pos,
                       "attrs": {
                           "call_type": cg_call_type.value,
                           "lineno": lineno,
                       }})

        return pos

    # ===================================================================
    # Operator: Super calls
    # ===================================================================

    def _walk_super_call(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        node_type = type(node).__name__

        member = getattr(node, "member", "")
        arguments = getattr(node, "arguments", []) or []
        qualifier = getattr(node, "qualifier", None)

        callee_text = "super"
        if qualifier:
            callee_text = self._expr_text(qualifier) + ".super"
        if member:
            callee_text += "." + member

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.METHOD_CALL.value,
                "raw_type": node_type,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Emit 'super' as SUPER identifier
        super_pos = self._emit_identifier(add_node, "super", lineno,
                                          IdentifierType.SUPER)
        self._ast_edge(add_edge, pos, super_pos, AstRole.CALLEE.value)

        for idx, arg in enumerate(arguments):
            arg_pos = self._walk_node(arg, add_node, add_edge, ctx_stack,
                                       file_path, idx)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                               extra={"arg_index": idx})

        return pos

    # ===================================================================
    # Operator: ClassCreator (new)
    # ===================================================================

    def _walk_new(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        creator_type = getattr(node, "type", None)
        arguments = getattr(node, "arguments", []) or []

        type_text = ""
        if creator_type is not None:
            type_text = getattr(creator_type, "name", "") or ""
            if not type_text:
                type_text = self._type_text(creator_type)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"new {type_text}" if type_text else "<new>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.NEW.value,
                "raw_type": "ClassCreator",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # arguments
        for idx, arg in enumerate(arguments):
            arg_pos = self._walk_node(arg, add_node, add_edge, ctx_stack,
                                       file_path, idx)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                               extra={"arg_index": idx})

        return pos

    # ===================================================================
    # Operator: Assignment
    # ===================================================================

    def _walk_assign(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        # javalang Assignment is actually MemberReference with qualifier
        # In javalang, assignment is part of MemberReference or VariableDeclarator
        # Check for expressionl, expressionr
        expressionl = getattr(node, "expressionl", None)
        expressionr = getattr(node, "expressionr", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "=",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "raw_type": "Assignment",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expressionl is not None:
            left_pos = self._walk_node(expressionl, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LHS.value)

        if expressionr is not None:
            right_pos = self._walk_node(expressionr, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Operator: BinaryOperation
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        operandl = getattr(node, "operandl", None)
        operandr = getattr(node, "operandr", None)
        operator = getattr(node, "operator", "")

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": operator,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": operator,
                "raw_type": "BinaryOperation",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if operandl is not None:
            left_pos = self._walk_node(operandl, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)

        if operandr is not None:
            right_pos = self._walk_node(operandr, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # MemberReference
    # ===================================================================

    def _walk_member_ref(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        qualifier = getattr(node, "qualifier", None)
        member = getattr(node, "member", "")
        selectors = getattr(node, "selectors", []) or []
        postfix = getattr(node, "postfix_operators", []) or []
        prefix = getattr(node, "prefix_operators", []) or []

        # 无 qualifier 的 MemberReference 实际上是简单变量引用（如 "cmd"、"user"）
        # 不应作为 operator(method_call) 处理，而是作为 identifier(variable)
        if not qualifier:
            return self._emit_identifier(add_node, member, lineno,
                                          IdentifierType.VARIABLE)

        qualifier_text = self._expr_text(qualifier)
        full_name = f"{qualifier_text}.{member}" if qualifier_text else member
        if postfix:
            full_name += "".join(postfix)
        if prefix:
            full_name = "".join(prefix) + full_name

        # Detect unary operators on MemberReference (e.g., x++, x--)
        has_unary_op = bool(prefix) or bool(postfix)
        op_type = OperatorType.UNARY_OP.value if has_unary_op else OperatorType.METHOD_CALL.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": full_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type,
                "raw_type": "MemberReference",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if qualifier is not None:
            q_pos = self._walk_node(qualifier, add_node, add_edge, ctx_stack,
                                      file_path, 0)
            if q_pos is not None:
                add_edge({
                    "label": EdgeLabel.MEMBER.value,
                    "source": q_pos,
                    "target": pos,
                    "attrs": {"access_type": MemberAccessType.PROPERTY.value},
                })

        if member:
            mem_pos = self._emit_identifier(add_node, member, lineno,
                                              IdentifierType.PROPERTY)
            self._ast_edge(add_edge, pos, mem_pos, AstRole.RIGHT.value)

        for sel in selectors:
            self._walk_node(sel, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Operator: Cast
    # ===================================================================

    def _walk_cast(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        cast_type = getattr(node, "type", None)
        expression = getattr(node, "expression", None)

        type_text = self._type_text(cast_type) if cast_type else "<unknown>"
        name = f"({type_text})"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.TYPE_CAST.value,
                "raw_type": "Cast",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Expression being cast
        if expression is not None:
            expr_pos = self._walk_node(expression, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Control Flow
    # ===================================================================

    def _walk_return(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        expression = getattr(node, "expression", None)

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "<return>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {"raw_type": "ReturnStatement"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expression is not None:
            expr_pos = self._walk_node(expression, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.VALUE.value)

        return pos

    def _walk_throw(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        expression = getattr(node, "expression", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<throw>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.THROW.value,
                "raw_type": "ThrowStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expression is not None:
            expr_pos = self._walk_node(expression, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.VALUE.value)

        return pos

    def _walk_break(self, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<break>",
            "lineno": 0,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BREAK.value,
                "raw_type": "BreakStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    def _walk_continue(self, add_node, add_edge, ctx_stack, file_path, depth) -> int:
        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<continue>",
            "lineno": 0,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CONTINUE.value,
                "raw_type": "ContinueStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    def _walk_yield(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        expression = getattr(node, "expression", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<yield>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "raw_type": "YieldStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expression is not None:
            expr_pos = self._walk_node(expression, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.VALUE.value)

        return pos

    def _walk_assert(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        condition = getattr(node, "condition", None)
        message = getattr(node, "message", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<assert>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "AssertStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if condition is not None:
            cond_pos = self._walk_node(condition, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        if message is not None:
            msg_pos = self._walk_node(message, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if msg_pos is not None:
                self._ast_edge(add_edge, pos, msg_pos, AstRole.VALUE.value)

        return pos

    def _walk_synchronized(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        lock = getattr(node, "lock", None)
        block = getattr(node, "block", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<synchronized>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {"raw_type": "SynchronizedStatement"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if lock is not None:
            lock_pos = self._walk_node(lock, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if lock_pos is not None:
                self._ast_edge(add_edge, pos, lock_pos, AstRole.CONDITION.value)

        if block is not None:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_stmt_list(block, add_node, add_edge, ctx_stack,
                                file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Variable declarations
    # ===================================================================

    def _walk_var_decl(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        declarators = getattr(node, "declarators", []) or []

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "var",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "raw_type": "LocalVariableDeclaration",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        for decl in declarators:
            decl_name = getattr(decl, "name", "")
            initializer = getattr(decl, "initializer", None)

            id_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": decl_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "raw_type": "VariableDeclarator",
                },
            })

            if initializer is not None:
                init_pos = self._walk_node(initializer, add_node, add_edge,
                                            ctx_stack, file_path, 0)
                if init_pos is not None:
                    self._ast_edge(add_edge, id_pos, init_pos,
                                   AstRole.VALUE.value)

        return pos

    def _walk_field_decl(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        declarators = getattr(node, "declarators", []) or []

        for decl in declarators:
            decl_name = getattr(decl, "name", "")
            initializer = getattr(decl, "initializer", None)

            id_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": decl_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.FIELD.value,
                    "raw_type": "FieldDeclaration",
                },
            })

            self._own_edge(add_edge, ctx_stack, id_pos, depth)

            if initializer is not None:
                init_pos = self._walk_node(initializer, add_node, add_edge,
                                            ctx_stack, file_path, 0)
                if init_pos is not None:
                    self._ast_edge(add_edge, id_pos, init_pos,
                                   AstRole.VALUE.value)

        return id_pos if declarators else None

    # ===================================================================
    # Statements
    # ===================================================================

    def _walk_block(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        stmts = getattr(node, "statements", []) or []
        last_pos = None
        for idx, child in enumerate(stmts):
            pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                 file_path, idx)
            if pos is not None:
                last_pos = pos
        return last_pos

    def _walk_expr_stmt(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        expression = getattr(node, "expression", None)
        if expression is not None:
            return self._walk_node(expression, add_node, add_edge, ctx_stack,
                                    file_path, depth)
        return None

    # ===================================================================
    # Annotation
    # ===================================================================

    def _walk_annotation(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        name = getattr(node, "name", "") or "<annotation>"

        pos = add_node({
            "label": NodeLabel.ANNOTATION.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {"raw_type": "Annotation"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk element-value pairs
        elements = getattr(node, "element", None)
        if elements is not None:
            if isinstance(elements, list):
                for elem in elements:
                    self._walk_node(elem, add_node, add_edge, ctx_stack,
                                   file_path, 0)
            else:
                self._walk_node(elements, add_node, add_edge, ctx_stack,
                               file_path, 0)

        return pos

    # ===================================================================
    # Literal
    # ===================================================================

    def _walk_literal(self, node, add_node, file_path) -> int:
        lineno, _ = self._loc(node)
        value = getattr(node, "value", None)

        if value is None:
            return None

        # Check for prefix/postfix unary operators (e.g., !true, -1, ++count)
        prefix = getattr(node, "prefix_operators", []) or []
        postfix = getattr(node, "postfix_operators", []) or []

        # If unary operators present, emit as UNARY_OP operator node
        if prefix or postfix:
            val_str = str(value)
            full_name = ""
            if prefix:
                full_name += "".join(prefix)
            full_name += val_str
            if postfix:
                full_name += "".join(postfix)
            pos = add_node({
                "label": NodeLabel.OPERATOR.value,
                "name": full_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": OperatorType.UNARY_OP.value,
                    "raw_type": "Literal",
                },
            })
            return pos

        # javalang Literal.value is source text: "10", '"hello"', 'true', etc.
        val_str = str(value)
        if val_str.startswith('"') or val_str.startswith("'"):
            const_type = ConstType.STRING
            name = val_str
        elif val_str == "true" or val_str == "false":
            const_type = ConstType.BOOLEAN
            name = val_str
        elif val_str == "null":
            const_type = ConstType.NULL
            name = val_str
        else:
            # Try numeric
            try:
                float(val_str)
                const_type = ConstType.NUMBER
                name = val_str
            except ValueError:
                const_type = ConstType.CONSTANT
                name = val_str

        return self._emit_const(add_node, name=name, lineno=lineno,
                                 const_type=const_type)

    # ===================================================================
    # Fallback: walk children
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        if node is None:
            return None

        child_fields = [
            "body", "statements", "declarators", "properties", "elements",
            "arguments", "parameters", "expression", "expressionl",
            "expressionr", "condition", "operandl", "operandr", "qualifier",
            "member", "selectors", "init", "update", "control", "block",
            "catches", "finally_block", "parameter", "name", "value",
            "types", "iterable", "var", "cases", "case", "type", "elements",
            "annotations", "element",
        ]

        last_pos = None
        for field_name in child_fields:
            child = getattr(node, field_name, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if item is not None:
                        pos = self._walk_node(item, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                        if pos is not None:
                            last_pos = pos
            elif hasattr(child, "position") or hasattr(child, "children"):
                pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                      file_path, 0)
                if pos is not None:
                    last_pos = pos

        return last_pos

    # ===================================================================
    # Utility: walk statement list (handles list vs BlockStatement)
    # ===================================================================

    def _walk_stmt_list(self, stmt, add_node, add_edge, ctx_stack,
                        file_path, start_idx) -> None:
        if stmt is None:
            return
        if isinstance(stmt, list):
            for idx, child in enumerate(stmt):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, start_idx + idx)
        elif hasattr(stmt, "statements"):
            for idx, child in enumerate(stmt.statements or []):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, start_idx + idx)
        else:
            self._walk_node(stmt, add_node, add_edge, ctx_stack,
                           file_path, start_idx)

    # ===================================================================
    # Utility: text representation
    # ===================================================================

    def _expr_text(self, node) -> str:
        if node is None:
            return ""
        if isinstance(node, str):
            return node
        if isinstance(node, (int, float, bool)):
            return str(node)
        if not hasattr(node, "position"):
            return str(node) if node else ""

        ntype = type(node).__name__

        if ntype == "MemberReference":
            q = self._expr_text(getattr(node, "qualifier", None))
            m = getattr(node, "member", "")
            pf = "".join(getattr(node, "postfix_operators", []) or [])
            return f"{q}.{m}{pf}" if q else f"{m}{pf}"
        if ntype == "This":
            return "this"
        if ntype == "Literal":
            val = getattr(node, "value", "")
            if isinstance(val, str):
                return repr(val)
            return str(val)
        if ntype == "BinaryOperation":
            l = self._expr_text(getattr(node, "operandl", None))
            r = self._expr_text(getattr(node, "operandr", None))
            op = getattr(node, "operator", "?")
            return f"{l} {op} {r}"
        if ntype == "TernaryExpression":
            c = self._expr_text(getattr(node, "condition", None))
            t = self._expr_text(getattr(node, "if_true", None))
            f = self._expr_text(getattr(node, "if_false", None))
            return f"{t} if {c} else {f}"
        if ntype == "MethodInvocation":
            q = self._expr_text(getattr(node, "qualifier", None))
            m = getattr(node, "member", "")
            return f"{q}.{m}()" if q else f"{m}()"
        if ntype == "ClassCreator":
            t = getattr(node, "type", None)
            tname = getattr(t, "name", "") if t else ""
            return f"new {tname}()"
        if ntype == "ReferenceType":
            return getattr(node, "name", "")
        if ntype == "Assignment":
            l = self._expr_text(getattr(node, "expressionl", None))
            r = self._expr_text(getattr(node, "expressionr", None))
            return f"{l} = {r}"
        if ntype == "LambdaExpression":
            params = getattr(node, "parameters", []) or []
            pnames = [getattr(p, "name", "?") for p in params]
            return f"({', '.join(pnames)}) -> ..."
        if ntype == "SuperMethodInvocation":
            return "super.method()"
        if ntype == "SuperConstructorInvocation":
            return "super()"

        return str(node) if node else ""
