"""JavaScript AST Normalizer — maps esprima AST output to UnifiedNode / UnifiedEdge.

Converts JavaScript source parsed by ``esprima.parse()`` into the unified
intermediate representation used by the AST graph engine.  Each JS file produces:
  - 1 file node
  - N class/function/import/dependency nodes (top-level declarations)
  - M operator/branch/return/identifier/const nodes (statement/expression level)
  - edges: own, ast, use, member, crg, frg
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
# esprima node type → classification sets
# ---------------------------------------------------------------------------

_FUNCTION_TYPES = {
    "FunctionDeclaration", "FunctionExpression",
    "ArrowFunctionExpression",
    "AsyncFunctionDeclaration", "AsyncFunctionExpression",
    "AsyncArrowFunctionExpression",
    "ClassMethod",
}

_CLASS_TYPES = {
    "ClassDeclaration", "ClassExpression",
}

_CALL_TYPES = {
    "CallExpression",
}

_BRANCH_TYPES = {
    "IfStatement", "ConditionalExpression",
    "ForStatement", "WhileStatement", "DoWhileStatement",
    "ForInStatement", "ForOfStatement",
    "SwitchStatement", "SwitchCase",
    "TryStatement", "CatchClause",
}

_IMPORT_TYPES = {
    "ImportDeclaration", "ExportNamedDeclaration",
    "ExportDefaultDeclaration", "ExportAllDeclaration",
}

_BINARY_OP_TYPES = {
    "BinaryExpression", "LogicalExpression",
}

_MEMBER_ACCESS_TYPES = {
    "MemberExpression",  # esprima node.type (computed=False/True 都用这个)
    "StaticMemberExpression",  # esprima Python class name (computed=False)
    "ComputedMemberExpression",  # esprima Python class name (computed=True)
}


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts esprima AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=esprima.parse(code, {"loc": True}),
            file_path="/path/to/file.js",
            source_content="...",
        )
    """

    language = "javascript"

    def normalize(
        self,
        ast_nodes: Any,
        file_path: str,
        source_content: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Convert esprima AST to unified graph data.

        Args:
            ast_nodes: esprima ``Module`` or ``Script`` object (has ``.body`` list).
            file_path: Absolute path to the JavaScript file.
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

        def _add_node(node_dict: dict[str, Any]) -> int:
            pos = len(nodes)
            nodes.append(node_dict)
            return pos

        def _add_edge(edge_dict: dict[str, Any]) -> None:
            edges.append(edge_dict)

        # file_node at position 0
        file_pos = _add_node(file_node)

        # Context stack: (node_position, node_label)
        ctx_stack: list[tuple[int, str]] = [(file_pos, NodeLabel.FILE.value)]

        # Extract .body as top-level statements
        top_stmts = ast_nodes.body if hasattr(ast_nodes, "body") else []
        top_idx = 0
        for stmt in top_stmts:
            self._walk_node(
                ast_node=stmt,
                add_node=_add_node,
                add_edge=_add_edge,
                ctx_stack=ctx_stack,
                file_path=file_path,
                depth=top_idx,
            )
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
        """Main walker — dispatches to specialised handlers based on node.type."""
        if ast_node is None:
            return None

        node_type = getattr(ast_node, "type", None)
        if node_type is None:
            return None

        # ---- Member access (handled first for chain expressions) ------
        if node_type in _MEMBER_ACCESS_TYPES:
            return self._walk_member(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Class ----------------------------------------------------
        if node_type in _CLASS_TYPES:
            return self._walk_class(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Function / Arrow / Async ----------------------------------
        if node_type in _FUNCTION_TYPES:
            return self._walk_function(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Import / Export ------------------------------------------
        if node_type in _IMPORT_TYPES:
            return self._walk_import(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Branch nodes ----------------------------------------------
        if node_type == "IfStatement":
            return self._walk_if(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ConditionalExpression":
            return self._walk_ternary(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ForStatement":
            return self._walk_for(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "WhileStatement":
            return self._walk_while(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "DoWhileStatement":
            return self._walk_do_while(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ForInStatement":
            return self._walk_for_in(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ForOfStatement":
            return self._walk_for_of(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "SwitchStatement":
            return self._walk_switch(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "TryStatement":
            return self._walk_try(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Operators -------------------------------------------------
        if node_type == "CallExpression":
            return self._walk_call(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "NewExpression":
            return self._walk_new(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "AssignmentExpression":
            return self._walk_assign(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type in _BINARY_OP_TYPES:
            return self._walk_binary(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "UnaryExpression":
            return self._walk_unary(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "UpdateExpression":
            return self._walk_update(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "SequenceExpression":
            return self._walk_sequence(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "SpreadElement":
            return self._walk_spread(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ChainExpression":
            return self._walk_chain(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Control flow ---------------------------------------------
        if node_type == "ReturnStatement":
            return self._walk_return(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ThrowStatement":
            return self._walk_throw(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "BreakStatement":
            return self._walk_break(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ContinueStatement":
            return self._walk_continue(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "YieldExpression":
            return self._walk_yield(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "AwaitExpression":
            return self._walk_await(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Variable declarations -----------------------------------
        if node_type == "VariableDeclaration":
            return self._walk_var_decl(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "VariableDeclarator":
            return self._walk_var_declarator(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Statements ----------------------------------------------
        if node_type == "BlockStatement":
            return self._walk_block(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ExpressionStatement":
            return self._walk_expression_stmt(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "LabeledStatement":
            return self._walk_labeled(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "WithStatement":
            return self._walk_with(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Decorators -----------------------------------------------
        if node_type == "Decorator":
            return self._walk_decorator(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Leaf nodes -----------------------------------------------
        if node_type == "Identifier":
            return self._walk_identifier(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "PrivateIdentifier":
            name = "#" + getattr(ast_node, "name", "")
            return self._emit_identifier(add_node, name=name, lineno=0,
                                         id_type=IdentifierType.PROPERTY)
        if node_type in ("StringLiteral", "NumericLiteral", "BooleanLiteral",
                         "NullLiteral", "RegExpLiteral"):
            return self._walk_literal(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "TemplateLiteral":
            return self._walk_template(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if node_type == "ThisExpression":
            return self._emit_identifier(add_node, name="this", lineno=0,
                                         id_type=IdentifierType.THIS)
        if node_type == "Super":
            return self._emit_identifier(add_node, name="super", lineno=0,
                                         id_type=IdentifierType.SUPER)
        if node_type == "MetaProperty":
            return self._walk_meta_property(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Patterns (destructured params / assignments) -------------
        if node_type in ("ObjectPattern", "ArrayPattern", "AssignmentPattern",
                         "RestElement"):
            return self._walk_pattern(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- EmptyStatement, DebuggerStatement → skip ------------------
        if node_type in ("EmptyStatement", "DebuggerStatement"):
            return None

        # ---- Fallback: walk child fields ------------------------------
        return self._walk_children(
            ast_node, add_node, add_edge, ctx_stack, file_path, depth,
        )

    # ===================================================================
    # Leaf helpers
    # ===================================================================

    def _emit_identifier(self, add_node, name: str, lineno: int,
                         id_type: IdentifierType) -> int:
        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": id_type.value,
            },
        })
        return pos

    def _emit_const(self, add_node, name: str, lineno: int,
                    const_type: ConstType) -> int:
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

    def _own_edge(self, add_edge, ctx_stack, pos, depth):
        ctx = ctx_stack[-1] if ctx_stack else None
        if ctx:
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": ctx[0],
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
        """Extract (lineno, end_lineno) from esprima node.loc."""
        lineno = 0
        end_lineno = 0
        if hasattr(node, "loc") and node.loc:
            if hasattr(node.loc, "start"):
                lineno = node.loc.start.line
            if hasattr(node.loc, "end"):
                end_lineno = node.loc.end.line
        return lineno, end_lineno

    # ===================================================================
    # Class
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        class_id = node.id
        name = class_id.name if class_id else "<anonymous>"
        raw_type = node.type

        # Determine function type for methods (stored per-method, not here)
        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.CLASS.value,
                "raw_type": raw_type,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # CRG edges for extends (super class)
        super_class = getattr(node, "superClass", None)
        if super_class is not None:
            super_name = self._expr_text(super_class)
            if super_name:
                parent_pos = add_node({
                    "label": NodeLabel.CLASS.value,
                    "name": super_name,
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "fullname": super_name,
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
            else:
                self._walk_node(
                    super_class, add_node, add_edge, ctx_stack, file_path, 0,
                )

        # Walk decorators (class-level)
        decorators = getattr(node, "decorators", []) or []
        for dec in decorators:
            self._walk_node(dec, add_node, add_edge, ctx_stack, file_path, 0)

        # Walk class body
        class_body = getattr(node, "body", None)
        if class_body:
            body_list = getattr(class_body, "body", []) or []
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            for idx, child in enumerate(body_list):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Function / Method / Arrow / Async
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        node_type = node.type
        func_id = getattr(node, "id", None)
        is_async = node_type.startswith("Async")
        if node_type == "ClassMethod":
            is_async = getattr(node, "is_async", False)
        if func_id and hasattr(func_id, "name"):
            name = func_id.name
        elif node_type == "ClassMethod":
            key = getattr(node, "key", None)
            name = key.name if key and hasattr(key, "name") else "<anonymous>"
        elif node_type in ("ArrowFunctionExpression",
                           "AsyncArrowFunctionExpression"):
            name = "<ArrowFunction>"
        else:
            name = "<anonymous>"

        params = getattr(node, "params", []) or []
        body = getattr(node, "body", None)

        # Build signature
        param_strs = []
        for p in params:
            if p is None:
                param_strs.append("?")
                continue
            if hasattr(p, "type") and p.type == "Identifier":
                param_strs.append(getattr(p, "name", None) or "?")
            elif hasattr(p, "name") and p.name:
                param_strs.append(p.name)
            else:
                param_strs.append(self._expr_text(p) or "?")
        signature = f"{name}({', '.join(param_strs)})"

        # Determine function type
        if node_type == "ClassMethod":
            kind = getattr(node, "kind", "method")
            is_generator = getattr(node, "generator", False)
            is_static = getattr(node, "static", False)
            if kind == "constructor":
                func_type = FunctionType.CONSTRUCTOR.value
            else:
                func_type = FunctionType.METHOD.value
            raw_type = node_type
        elif node_type in ("ArrowFunctionExpression",
                           "AsyncArrowFunctionExpression"):
            func_type = FunctionType.LAMBDA.value
            raw_type = "ArrowFunction"
        else:
            func_type = FunctionType.FUNCTION.value
            raw_type = node_type

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": func_type,
                "signature": signature,
                "file_path": file_path,
                "raw_type": raw_type,
                "async": is_async,
                "generator": is_generator if node_type == "ClassMethod" else False,
                "static": is_static if node_type == "ClassMethod" else False,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context, walk parameters then body
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
        body_offset = len(params)
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                body_stmts = getattr(body, "body", []) or []
                for child_idx, child in enumerate(body_stmts):
                    self._walk_node(
                        child, add_node, add_edge, ctx_stack, file_path,
                        body_offset + child_idx,
                    )
            else:
                # Arrow function with expression body
                self._walk_node(
                    body, add_node, add_edge, ctx_stack, file_path,
                    body_offset,
                )

        ctx_stack.pop()
        return pos

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        """Walk a parameter node (Identifier, AssignmentPattern, etc.)."""
        if param_node is None:
            return None

        p_type = getattr(param_node, "type", "")

        if p_type == "Identifier":
            lineno, _ = self._loc(param_node)
            name = param_node.name
            return add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "file_path": file_path,
                },
            })
        elif p_type == "AssignmentPattern":
            # e.g. function(a = 10) → walk the left as parameter
            left = getattr(param_node, "left", None)
            return self._walk_parameter(left, add_node, file_path)
        elif p_type == "RestElement":
            arg = getattr(param_node, "argument", None)
            return self._walk_parameter(arg, add_node, file_path)
        elif p_type == "ObjectPattern":
            # Walk properties to extract parameter names
            props = getattr(param_node, "properties", []) or []
            lineno, _ = self._loc(param_node)
            pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": "<destructured>",
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "file_path": file_path,
                },
            })
            return pos
        elif p_type == "ArrayPattern":
            elements = getattr(param_node, "elements", []) or []
            lineno, _ = self._loc(param_node)
            pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": "<destructured_array>",
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "file_path": file_path,
                },
            })
            return pos
        elif p_type == "TSParameterProperty":
            param = getattr(param_node, "parameter", None)
            return self._walk_parameter(param, add_node, file_path)

        return None

    # ===================================================================
    # Import / Export
    # ===================================================================

    def _walk_import(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        node_type = node.type

        # ImportDeclaration
        if node_type == "ImportDeclaration":
            source = getattr(node, "source", None)
            source_name = self._expr_text(source) if source else ""
            specifiers = getattr(node, "specifiers", []) or []

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": source_name,
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.IMPORT.value,
                    "source": source_name,
                    "raw_type": node_type,
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            # frg edge to dependency node
            if source_name:
                dep_pos = add_node({
                    "label": NodeLabel.DEPENDENCY.value,
                    "name": source_name,
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "source": source_name,
                    },
                })
                add_edge({
                    "label": EdgeLabel.FRG.value,
                    "source": pos,
                    "target": dep_pos,
                    "attrs": {"type": FrgType.IMPORT.value},
                })

            # Walk specifiers
            for spec in specifiers:
                self._walk_node(spec, add_node, add_edge, ctx_stack,
                               file_path, 0)

            return pos

        # ExportNamedDeclaration
        if node_type == "ExportNamedDeclaration":
            decl = getattr(node, "declaration", None)
            source = getattr(node, "source", None)
            specifiers = getattr(node, "specifiers", []) or []

            name = "export"
            source_name = self._expr_text(source) if source else ""
            if source_name:
                name = f"export {source_name}"

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": name,
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.FROM_IMPORT.value,
                    "source": source_name,
                    "raw_type": node_type,
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            if source:
                dep_pos = add_node({
                    "label": NodeLabel.DEPENDENCY.value,
                    "name": source_name,
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {"source": source_name},
                })
                add_edge({
                    "label": EdgeLabel.FRG.value,
                    "source": pos,
                    "target": dep_pos,
                    "attrs": {"type": FrgType.FROM_IMPORT.value},
                })

            # Walk declaration (e.g. export function foo() {})
            if decl is not None:
                self._walk_node(decl, add_node, add_edge, ctx_stack,
                               file_path, 0)

            for spec in specifiers:
                self._walk_node(spec, add_node, add_edge, ctx_stack,
                               file_path, 0)

            return pos

        # ExportDefaultDeclaration
        if node_type == "ExportDefaultDeclaration":
            decl = getattr(node, "declaration", None)

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": "export default",
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.FROM_IMPORT.value,
                    "raw_type": node_type,
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            if decl is not None:
                self._walk_node(decl, add_node, add_edge, ctx_stack,
                               file_path, 0)

            return pos

        # ExportAllDeclaration
        if node_type == "ExportAllDeclaration":
            source = getattr(node, "source", None)
            source_name = self._expr_text(source) if source else ""

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": f"export * {source_name}",
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.FROM_IMPORT.value,
                    "source": source_name,
                    "raw_type": node_type,
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            return pos

        # ExportSpecifier / ImportSpecifier / ImportDefaultSpecifier /
        # ImportNamespaceSpecifier — just walk as children
        return self._walk_children(
            node, add_node, add_edge, ctx_stack, file_path, depth,
        )



    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        test = getattr(node, "test", None)
        consequent = getattr(node, "consequent", None)
        alternate = getattr(node, "alternate", None)

        condition = self._expr_text(test) if test else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<if>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": condition,
                "raw_type": "IfStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        if test is not None:
            cond_pos = self._walk_node(
                test, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Walk consequent (iftrue branch)
        if consequent is not None:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            if hasattr(consequent, "type") and consequent.type == "BlockStatement":
                for idx, child in enumerate(getattr(consequent, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(consequent, add_node, add_edge, ctx_stack,
                               file_path, 0)
            ctx_stack.pop()

        # Handle alternate: if it's an IfStatement → elif
        if alternate is not None:
            if hasattr(alternate, "type") and alternate.type == "IfStatement":
                # elif — walk as nested If under this branch
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                self._walk_if(alternate, add_node, add_edge, ctx_stack,
                              file_path, depth + 1)
                ctx_stack.pop()
            elif hasattr(alternate, "type") and alternate.type == "BlockStatement":
                # else block
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<else>",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "condition": "",
                        "raw_type": "Else",
                    },
                })
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                for idx, child in enumerate(getattr(alternate, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
                ctx_stack.pop()
            else:
                # else with single statement (no block)
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<else>",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "condition": "",
                        "raw_type": "Else",
                    },
                })
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                self._walk_node(alternate, add_node, add_edge, ctx_stack,
                               file_path, 0)
                ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: ConditionalExpression (ternary)
    # ===================================================================

    def _walk_ternary(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        test = getattr(node, "test", None)
        consequent = getattr(node, "consequent", None)
        alternate = getattr(node, "alternate", None)

        condition = self._expr_text(test) if test else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<ternary>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TERNARY.value,
                "condition": condition,
                "raw_type": "ConditionalExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # condition
        if test is not None:
            cond_pos = self._walk_node(
                test, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # consequent → iftrue
        if consequent is not None:
            body_pos = self._walk_node(
                consequent, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if body_pos is not None:
                self._ast_edge(add_edge, pos, body_pos, AstRole.IFTRUE.value)

        # alternate → iffalse
        if alternate is not None:
            else_pos = self._walk_node(
                alternate, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if else_pos is not None:
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

        return pos

    # ===================================================================
    # Branch: ForStatement
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        init = getattr(node, "init", None)
        test = getattr(node, "test", None)
        update = getattr(node, "update", None)
        body = getattr(node, "body", None)

        condition = self._expr_text(test) if test else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<for>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": condition,
                "raw_type": "ForStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # init → lhs
        if init is not None:
            init_pos = self._walk_node(init, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if init_pos is not None:
                self._ast_edge(add_edge, pos, init_pos, AstRole.LHS.value)

        # test → condition
        if test is not None:
            test_pos = self._walk_node(test, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if test_pos is not None:
                self._ast_edge(add_edge, pos, test_pos, AstRole.CONDITION.value)

        # update → rhs
        if update is not None:
            upd_pos = self._walk_node(update, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if upd_pos is not None:
                self._ast_edge(add_edge, pos, upd_pos, AstRole.RHS.value)

        # body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                for idx, child in enumerate(getattr(body, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: WhileStatement
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        test = getattr(node, "test", None)
        body = getattr(node, "body", None)

        condition = self._expr_text(test) if test else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<while>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": condition,
                "raw_type": "WhileStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if test is not None:
            test_pos = self._walk_node(test, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if test_pos is not None:
                self._ast_edge(add_edge, pos, test_pos, AstRole.CONDITION.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                for idx, child in enumerate(getattr(body, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: DoWhileStatement
    # ===================================================================

    def _walk_do_while(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        body = getattr(node, "body", None)
        test = getattr(node, "test", None)

        condition = self._expr_text(test) if test else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<do-while>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": condition,
                "raw_type": "DoWhileStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                for idx, child in enumerate(getattr(body, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, 0)

        if test is not None:
            test_pos = self._walk_node(test, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if test_pos is not None:
                self._ast_edge(add_edge, pos, test_pos, AstRole.CONDITION.value)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: ForInStatement (→ foreach)
    # ===================================================================

    def _walk_for_in(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        body = getattr(node, "body", None)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<for-in>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": "",
                "raw_type": "ForInStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if left is not None:
            left_pos = self._walk_node(left, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LHS.value)

        if right is not None:
            right_pos = self._walk_node(right, add_node, add_edge, ctx_stack,
                                         file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RHS.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                for idx, child in enumerate(getattr(body, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: ForOfStatement (→ foreach)
    # ===================================================================

    def _walk_for_of(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        body = getattr(node, "body", None)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<for-of>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": "",
                "raw_type": "ForOfStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if left is not None:
            left_pos = self._walk_node(left, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LHS.value)

        if right is not None:
            right_pos = self._walk_node(right, add_node, add_edge, ctx_stack,
                                         file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RHS.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None:
            if hasattr(body, "type") and body.type == "BlockStatement":
                for idx, child in enumerate(getattr(body, "body", []) or []):
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
            else:
                self._walk_node(body, add_node, add_edge, ctx_stack,
                               file_path, 0)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: SwitchStatement
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        discriminant = getattr(node, "discriminant", None)
        cases = getattr(node, "cases", []) or []

        subject = self._expr_text(discriminant) if discriminant else ""

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"switch {subject}" if subject else "<switch>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": subject,
                "raw_type": "SwitchStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk discriminant
        if discriminant is not None:
            disc_pos = self._walk_node(
                discriminant, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if disc_pos is not None:
                self._ast_edge(add_edge, pos, disc_pos, AstRole.CONDITION.value)

        # Walk cases
        for c_idx, case in enumerate(cases):
            case_test = getattr(case, "test", None)
            case_consequent = getattr(case, "consequent", []) or []

            # test is None → default
            if case_test is None:
                case_name = "<default>"
                case_type = BranchType.DEFAULT.value
            else:
                case_name = self._expr_text(case_test)
                case_type = BranchType.CASE.value

            case_lineno, case_end = self._loc(case)

            case_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": case_name or f"<case {c_idx}>",
                "lineno": case_lineno,
                "end_lineno": case_end,
                "language": self.language,
                "attrs": {
                    "type": case_type,
                    "condition": case_name if case_test else "",
                    "raw_type": "SwitchCase",
                },
            })

            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": case_pos,
                "attrs": {"index": c_idx},
            })

            # Walk case test
            if case_test is not None:
                test_pos = self._walk_node(
                    case_test, add_node, add_edge, ctx_stack, file_path, 0,
                )
                if test_pos is not None:
                    self._ast_edge(add_edge, case_pos, test_pos,
                                  AstRole.CONDITION.value)

            # Walk case body
            ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
            for idx, stmt in enumerate(case_consequent):
                self._walk_node(stmt, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: TryStatement
    # ===================================================================

    def _walk_try(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        block = getattr(node, "block", None)
        handler = getattr(node, "handler", None)
        finalizer = getattr(node, "finalizer", None)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<try>",
            "lineno": lineno,
            "end_lineno": end_lineno,
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
        if block is not None and hasattr(block, "body"):
            for idx, child in enumerate(block.body or []):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)

        # catch
        if handler is not None:
            catch_pos = self._walk_catch(
                handler, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if catch_pos is not None:
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": catch_pos,
                    "attrs": {"index": len(block.body or [])},
                })

        ctx_stack.pop()

        # finally
        if finalizer is not None:
            fin_lineno, fin_end = self._loc(finalizer)
            finally_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": "<finally>",
                "lineno": fin_lineno,
                "end_lineno": fin_end,
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
                "target": finally_pos,
                "attrs": {"index": len(block.body or []) + (1 if handler else 0)},
            })
            ctx_stack.append((finally_pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(getattr(finalizer, "body", []) or []):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    def _walk_catch(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        """Walk a CatchClause node."""
        lineno, end_lineno = self._loc(node)
        param = getattr(node, "param", None)
        body = getattr(node, "body", None)

        exc_name = ""
        if param is not None:
            if hasattr(param, "name"):
                exc_name = param.name
            else:
                exc_name = self._expr_text(param)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"catch {exc_name}" if exc_name else "<catch>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CATCH.value,
                "condition": exc_name,
                "exception_name": exc_name,
                "raw_type": "CatchClause",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk param as identifier
        if param is not None:
            p_pos = self._walk_node(param, add_node, add_edge, ctx_stack,
                                    file_path, 0)
            if p_pos is not None:
                self._ast_edge(add_edge, pos, p_pos, AstRole.LHS.value)

        # Walk body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body is not None and hasattr(body, "body"):
            for idx, child in enumerate(body.body or []):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Operator: CallExpression
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        callee = getattr(node, "callee", None)
        arguments = getattr(node, "arguments", []) or []
        optional = getattr(node, "optional", False)

        callee_text = self._expr_text(callee) if callee else ""

        # Determine call type
        call_type = OperatorType.CALL.value
        if callee is not None and hasattr(callee, "type"):
            if callee.type == "MemberExpression":
                call_type = OperatorType.METHOD_CALL.value
            elif callee.type == "Super":
                call_type = OperatorType.METHOD_CALL.value

        # For MemberExpression callees, _walk_member already creates the
        # operator node.  Reuse it instead of creating a duplicate.
        if callee is not None and hasattr(callee, "type") and callee.type == "MemberExpression":
            callee_pos = self._walk_node(callee, add_node, add_edge, ctx_stack,
                                          file_path, 0)
            if callee_pos is not None:
                pos = callee_pos
            else:
                pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": callee_text or "<call>",
                    "lineno": lineno,
                    "end_lineno": end_lineno,
                    "language": self.language,
                    "attrs": {
                        "type": call_type,
                        "raw_type": "CallExpression",
                        "optional": optional,
                    },
                })
                self._own_edge(add_edge, ctx_stack, pos, depth)
        else:
            pos = add_node({
                "label": NodeLabel.OPERATOR.value,
                "name": callee_text or "<call>",
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": call_type,
                    "raw_type": "CallExpression",
                    "optional": optional,
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            # callee (non-MemberExpression)
            if callee is not None:
                callee_pos = self._walk_node(callee, add_node, add_edge, ctx_stack,
                                              file_path, 0)
                if callee_pos is not None:
                    self._ast_edge(add_edge, pos, callee_pos, AstRole.CALLEE.value)

        # arguments
        for idx, arg in enumerate(arguments):
            arg_pos = self._walk_node(arg, add_node, add_edge, ctx_stack,
                                       file_path, idx)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                               extra={"arg_index": idx})

        # NOTE: use edge generation moved to UseEdgeBuilder (phase 2).

        return pos

    # ===================================================================
    # Operator: NewExpression
    # ===================================================================

    def _walk_new(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        callee = getattr(node, "callee", None)
        arguments = getattr(node, "arguments", []) or []

        callee_text = self._expr_text(callee) if callee else ""

        # For MemberExpression callees, _walk_member already creates the
        # operator node.  Reuse it instead of creating a duplicate.
        if callee is not None and hasattr(callee, "type") and callee.type == "MemberExpression":
            callee_pos = self._walk_node(callee, add_node, add_edge, ctx_stack,
                                          file_path, 0)
            if callee_pos is not None:
                pos = callee_pos
            else:
                pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": callee_text or "<new>",
                    "lineno": lineno,
                    "end_lineno": end_lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.NEW.value,
                        "raw_type": "NewExpression",
                    },
                })
                self._own_edge(add_edge, ctx_stack, pos, depth)
        else:
            pos = add_node({
                "label": NodeLabel.OPERATOR.value,
                "name": callee_text or "<new>",
                "lineno": lineno,
                "end_lineno": end_lineno,
                "language": self.language,
                "attrs": {
                    "type": OperatorType.NEW.value,
                    "raw_type": "NewExpression",
                },
            })

            self._own_edge(add_edge, ctx_stack, pos, depth)

            if callee is not None:
                callee_pos = self._walk_node(callee, add_node, add_edge, ctx_stack,
                                              file_path, 0)
                if callee_pos is not None:
                    self._ast_edge(add_edge, pos, callee_pos, AstRole.CALLEE.value)

        for idx, arg in enumerate(arguments):
            arg_pos = self._walk_node(arg, add_node, add_edge, ctx_stack,
                                       file_path, idx)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                               extra={"arg_index": idx})

        return pos

    # ===================================================================
    # Operator: AssignmentExpression
    # ===================================================================

    def _walk_assign(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        operator = getattr(node, "operator", "=")
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)

        op_type = OperatorType.ASSIGN.value
        if operator != "=":
            op_type = OperatorType.AUG_ASSIGN.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": operator,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": op_type,
                "operator": operator,
                "raw_type": "AssignmentExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if left is not None:
            left_pos = self._walk_node(left, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LHS.value)

        if right is not None:
            right_pos = self._walk_node(right, add_node, add_edge, ctx_stack,
                                         file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Operator: BinaryExpression / LogicalExpression
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        operator = getattr(node, "operator", "")
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": operator,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": operator,
                "raw_type": node.type,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if left is not None:
            left_pos = self._walk_node(left, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)

        if right is not None:
            right_pos = self._walk_node(right, add_node, add_edge, ctx_stack,
                                         file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Operator: UnaryExpression
    # ===================================================================

    def _walk_unary(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        operator = getattr(node, "operator", "")
        argument = getattr(node, "argument", None)
        prefix = getattr(node, "prefix", True)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{'prefix ' if prefix else 'postfix '}{operator}",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": operator,
                "prefix": prefix,
                "raw_type": "UnaryExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Operator: UpdateExpression (++, --)
    # ===================================================================

    def _walk_update(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        operator = getattr(node, "operator", "++")
        argument = getattr(node, "argument", None)
        prefix = getattr(node, "prefix", True)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{'prefix ' if prefix else 'postfix '}{operator}",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": operator,
                "prefix": prefix,
                "raw_type": "UpdateExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Operator: SequenceExpression (comma operator)
    # ===================================================================

    def _walk_sequence(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        expressions = getattr(node, "expressions", []) or []
        # Walk all expressions, return the last position
        last_pos = None
        for expr in expressions:
            pos = self._walk_node(expr, add_node, add_edge, ctx_stack,
                                 file_path, depth)
            if pos is not None:
                last_pos = pos
        return last_pos

    # ===================================================================
    # Operator: SpreadElement
    # ===================================================================

    def _walk_spread(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        argument = getattr(node, "argument", None)
        if argument is not None:
            return self._walk_node(argument, add_node, add_edge, ctx_stack,
                                    file_path, depth)
        return None

    # ===================================================================
    # ChainExpression (optional chaining)
    # ===================================================================

    def _walk_chain(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        expression = getattr(node, "expression", None)
        if expression is not None:
            return self._walk_node(expression, add_node, add_edge, ctx_stack,
                                    file_path, depth)
        return None

    # ===================================================================
    # Member Access: StaticMemberExpression / ComputedMemberExpression
    # ===================================================================

    def _walk_member(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        obj = getattr(node, "object", None)
        prop = getattr(node, "property", None)
        computed = getattr(node, "computed", False)

        obj_text = self._expr_text(obj) if obj else ""
        prop_text = self._expr_text(prop) if prop else ""
        full_name = f"{obj_text}.{prop_text}" if not computed else f"{obj_text}[{prop_text}]"

        # Determine access type
        access_type = MemberAccessType.PROPERTY.value
        if computed:
            access_type = MemberAccessType.ARRAY_OFFSET.value

        # Emit the member access as an operator
        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": full_name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.METHOD_CALL.value,
                "raw_type": node.type,
                "computed": computed,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # object → LEFT
        if obj is not None:
            obj_pos = self._walk_node(obj, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if obj_pos is not None:
                add_edge({
                    "label": EdgeLabel.MEMBER.value,
                    "source": obj_pos,
                    "target": pos,
                    "attrs": {"access_type": access_type},
                })

        # property
        if prop is not None:
            prop_pos = self._walk_node(prop, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if prop_pos is not None:
                self._ast_edge(add_edge, pos, prop_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Control Flow: ReturnStatement
    # ===================================================================

    def _walk_return(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        argument = getattr(node, "argument", None)

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "<return>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {"raw_type": "ReturnStatement"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Operator: ThrowStatement
    # ===================================================================

    def _walk_throw(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        argument = getattr(node, "argument", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<throw>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.THROW.value,
                "raw_type": "ThrowStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Operator: BreakStatement
    # ===================================================================

    def _walk_break(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<break>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BREAK.value,
                "raw_type": "BreakStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Operator: ContinueStatement
    # ===================================================================

    def _walk_continue(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<continue>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CONTINUE.value,
                "raw_type": "ContinueStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Operator: YieldExpression
    # ===================================================================

    def _walk_yield(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        argument = getattr(node, "argument", None)
        delegate = getattr(node, "delegate", False)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "yield*" if delegate else "yield",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "delegate": delegate,
                "raw_type": "YieldExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Operator: AwaitExpression
    # ===================================================================

    def _walk_await(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno, end_lineno = self._loc(node)
        argument = getattr(node, "argument", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<await>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AWAIT.value,
                "raw_type": "AwaitExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if argument is not None:
            arg_pos = self._walk_node(argument, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if arg_pos is not None:
                self._ast_edge(add_edge, pos, arg_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Statements
    # ===================================================================

    def _walk_var_decl(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        """VariableDeclaration — walk declarators."""
        declarations = getattr(node, "declarations", []) or []
        kind = getattr(node, "kind", "var")

        # Create a parent node for the declaration
        lineno, end_lineno = self._loc(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": kind,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "raw_type": "VariableDeclaration",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        for idx, decl in enumerate(declarations):
            decl_pos = self._walk_var_declarator(
                decl, add_node, add_edge, ctx_stack, file_path, idx,
            )
            if decl_pos is not None:
                self._ast_edge(add_edge, pos, decl_pos, AstRole.RHS.value)

        return pos

    def _walk_var_declarator(self, node, add_node, add_edge,
                             ctx_stack, file_path, depth) -> int:
        """VariableDeclarator — emit identifier for the declared name."""
        ident = getattr(node, "id", None)
        init = getattr(node, "init", None)

        lineno, end_lineno = self._loc(node)
        name = self._expr_text(ident) if ident else "<unknown>"

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "raw_type": "VariableDeclarator",
            },
        })

        if init is not None:
            init_pos = self._walk_node(init, add_node, add_edge, ctx_stack,
                                        file_path, 0)
            if init_pos is not None:
                self._ast_edge(add_edge, pos, init_pos, AstRole.VALUE.value)

        return pos

    def _walk_block(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        """BlockStatement — walk its body statements."""
        body = getattr(node, "body", []) or []
        last_pos = None
        for idx, child in enumerate(body):
            pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                 file_path, idx)
            if pos is not None:
                last_pos = pos
        return last_pos

    def _walk_expression_stmt(self, node, add_node, add_edge,
                              ctx_stack, file_path, depth) -> int:
        """ExpressionStatement — walk the inner expression."""
        expression = getattr(node, "expression", None)
        if expression is not None:
            return self._walk_node(expression, add_node, add_edge, ctx_stack,
                                    file_path, depth)
        return None

    def _walk_labeled(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        """LabeledStatement — walk the body (label is metadata)."""
        body = getattr(node, "body", None)
        if body is not None:
            return self._walk_node(body, add_node, add_edge, ctx_stack,
                                    file_path, depth)
        return None

    def _walk_with(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        """WithStatement — walk object and body."""
        obj = getattr(node, "object", None)
        body = getattr(node, "body", None)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<with>",
            "lineno": 0,
            "language": self.language,
            "attrs": {"raw_type": "WithStatement"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if obj is not None:
            obj_pos = self._walk_node(obj, add_node, add_edge, ctx_stack,
                                       file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.CONDITION.value)

        if body is not None:
            self._walk_node(body, add_node, add_edge, ctx_stack,
                           file_path, 0)

        return pos

    def _walk_decorator(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        """Decorator — emit as annotation node."""
        lineno, end_lineno = self._loc(node)
        expression = getattr(node, "expression", None)
        expr_text = self._expr_text(expression) if expression else ""

        pos = add_node({
            "label": NodeLabel.ANNOTATION.value,
            "name": expr_text or "<decorator>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {"raw_type": "Decorator"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expression is not None:
            self._walk_node(expression, add_node, add_edge, ctx_stack,
                           file_path, 0)

        return pos

    # ===================================================================
    # Leaf nodes: Identifier, Literal, TemplateLiteral
    # ===================================================================

    def _walk_identifier(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        name = getattr(node, "name", "")
        lineno, _ = self._loc(node)

        return self._emit_identifier(add_node, name=name, lineno=lineno,
                                      id_type=IdentifierType.VARIABLE)

    def _walk_literal(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        node_type = node.type
        lineno, _ = self._loc(node)
        value = getattr(node, "value", None)
        raw = getattr(node, "raw", "")

        # Determine const type
        if node_type == "StringLiteral":
            const_type = ConstType.STRING
            name = raw or repr(value)
        elif node_type == "NumericLiteral":
            const_type = ConstType.NUMBER
            name = str(value) if value is not None else "0"
        elif node_type == "BooleanLiteral":
            const_type = ConstType.BOOLEAN
            name = str(value).lower()
        elif node_type == "NullLiteral":
            const_type = ConstType.NULL
            name = "null"
        elif node_type == "RegExpLiteral":
            const_type = ConstType.CONSTANT
            name = raw or repr(value)
        else:
            const_type = ConstType.CONSTANT
            name = raw or repr(value)

        return self._emit_const(add_node, name=name, lineno=lineno,
                                  const_type=const_type)

    def _walk_template(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno, _ = self._loc(node)
        quasis = getattr(node, "quasis", []) or []

        # Extract the template string parts
        parts = []
        for q in quasis:
            val = getattr(q, "value", None)
            if val and hasattr(val, "cooked"):
                parts.append(str(val.cooked))
            elif hasattr(q, "value"):
                parts.append(str(q.value))

        name = "`" + "".join(parts) + "`"

        str_pos = self._emit_const(add_node, name=name, lineno=lineno,
                                   const_type=ConstType.STRING)

        # Walk interpolated expressions and create DFG edges
        # e.g. `hello ${name}` → dfg(name_node → string_const)
        expressions = getattr(node, "expressions", []) or []
        for expr in expressions:
            expr_pos = self._walk_node(expr, add_node, add_edge,
                                       ctx_stack, file_path, depth)
            if expr_pos is not None:
                add_edge({
                    "label": "dfg",
                    "source": expr_pos,
                    "target": str_pos,
                })
                if ctx_stack:
                    self._own_edge(add_edge, ctx_stack, expr_pos, depth)

        return str_pos

    def _walk_meta_property(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        meta = getattr(node, "meta", None)
        prop = getattr(node, "property", None)

        meta_text = self._expr_text(meta) if meta else ""
        prop_text = self._expr_text(prop) if prop else ""
        name = f"{meta_text}.{prop_text}" if meta_text and prop_text else "<meta>"

        lineno, _ = self._loc(node)
        return self._emit_identifier(add_node, name=name, lineno=lineno,
                                      id_type=IdentifierType.PROPERTY)

    # ===================================================================
    # Patterns (destructuring)
    # ===================================================================

    def _walk_pattern(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        """Walk destructuring patterns — extract identifier children."""
        node_type = getattr(node, "type", "")

        if node_type == "AssignmentPattern":
            # e.g. {a = 10} — walk left side
            left = getattr(node, "left", None)
            right = getattr(node, "right", None)
            pos = None
            if left is not None:
                pos = self._walk_pattern(left, add_node, add_edge, ctx_stack,
                                          file_path, depth)
            if right is not None:
                self._walk_node(right, add_node, add_edge, ctx_stack,
                               file_path, 0)
            return pos

        if node_type == "RestElement":
            arg = getattr(node, "argument", None)
            return self._walk_pattern(arg, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        if node_type == "ObjectPattern":
            properties = getattr(node, "properties", []) or []
            for prop in properties:
                if hasattr(prop, "value"):
                    # ObjectProperty-like: key + value
                    key = getattr(prop, "key", None)
                    value = getattr(prop, "value", None)
                    if key is not None:
                        self._walk_node(key, add_node, add_edge, ctx_stack,
                                       file_path, 0)
                    if value is not None:
                        pos = self._walk_pattern(value, add_node, add_edge,
                                                  ctx_stack, depth)
                        if pos is not None:
                            return pos
                elif hasattr(prop, "type"):
                    self._walk_node(prop, add_node, add_edge, ctx_stack,
                                   file_path, 0)
            return None

        if node_type == "ArrayPattern":
            elements = getattr(node, "elements", []) or []
            for elem in elements:
                if elem is not None:
                    self._walk_pattern(elem, add_node, add_edge, ctx_stack,
                                        file_path, depth)
            return None

        # Fallback: try walking as a regular node
        return self._walk_node(node, add_node, add_edge, ctx_stack,
                               file_path, depth)

    # ===================================================================
    # Fallback: walk child fields
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        """Walk child fields of unknown node types."""
        if node is None:
            return None

        # Child fields to walk (esprima-specific)
        child_fields = [
            "body", "declarations", "properties", "elements",
            "arguments", "params", "expressions", "alternatives",
            "consequent", "alternate", "test", "left", "right",
            "argument", "object", "property", "callee", "init",
            "update", "discriminant", "cases", "block", "handler",
            "finalizer", "id", "key", "value", "source", "specifiers",
            "declaration", "quasis",
        ]

        last_pos = None
        for field_name in child_fields:
            child = getattr(node, field_name, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if item is not None:
                        pos = self._walk_node(
                            item, add_node, add_edge, ctx_stack, file_path, 0,
                        )
                        if pos is not None:
                            last_pos = pos
            elif hasattr(child, "type"):
                pos = self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, 0,
                )
                if pos is not None:
                    last_pos = pos

        return last_pos

    # ===================================================================
    # Utility: text representation of an esprima expression
    # ===================================================================

    def _expr_text(self, node) -> str:
        """Best-effort text representation of an esprima AST node."""
        if node is None:
            return ""
        if isinstance(node, str):
            return node
        if not hasattr(node, "type"):
            return str(node)

        ntype = node.type

        if ntype == "Identifier":
            return getattr(node, "name", "")
        if ntype == "ThisExpression":
            return "this"
        if ntype == "Super":
            return "super"
        if ntype == "PrivateIdentifier":
            return "#" + getattr(node, "name", "")
        if ntype in ("StringLiteral", "NumericLiteral", "BooleanLiteral",
                     "NullLiteral", "RegExpLiteral"):
            raw = getattr(node, "raw", None)
            if raw is not None:
                return str(raw)
            val = getattr(node, "value", "")
            return str(val) if not isinstance(val, str) else val
        if ntype == "TemplateLiteral":
            quasis = getattr(node, "quasis", []) or []
            parts = []
            for q in quasis:
                val = getattr(q, "value", None)
                if val and hasattr(val, "cooked"):
                    parts.append(str(val.cooked))
            return "`" + "".join(parts) + "`"
        if ntype in ("MemberExpression", "StaticMemberExpression"):
            obj = self._expr_text(getattr(node, "object", None))
            prop = self._expr_text(getattr(node, "property", None))
            return f"{obj}.{prop}" if obj and prop else ""
        if ntype == "ComputedMemberExpression":
            obj = self._expr_text(getattr(node, "object", None))
            prop = self._expr_text(getattr(node, "property", None))
            return f"{obj}[{prop}]" if obj else f"[{prop}]"
        if ntype == "CallExpression":
            callee = self._expr_text(getattr(node, "callee", None))
            return f"{callee}()"
        if ntype == "NewExpression":
            callee = self._expr_text(getattr(node, "callee", None))
            return f"new {callee}()"
        if ntype in ("BinaryExpression", "LogicalExpression"):
            left = self._expr_text(getattr(node, "left", None))
            right = self._expr_text(getattr(node, "right", None))
            op = getattr(node, "operator", "?")
            return f"{left} {op} {right}"
        if ntype == "UnaryExpression":
            operand = self._expr_text(getattr(node, "argument", None))
            op = getattr(node, "operator", "?")
            prefix = getattr(node, "prefix", True)
            return f"{op}{operand}" if prefix else f"{operand}{op}"
        if ntype == "UpdateExpression":
            operand = self._expr_text(getattr(node, "argument", None))
            op = getattr(node, "operator", "++")
            prefix = getattr(node, "prefix", True)
            return f"{op}{operand}" if prefix else f"{operand}{op}"
        if ntype == "AssignmentExpression":
            left = self._expr_text(getattr(node, "left", None))
            right = self._expr_text(getattr(node, "right", None))
            op = getattr(node, "operator", "=")
            return f"{left} {op} {right}"
        if ntype == "ConditionalExpression":
            test = self._expr_text(getattr(node, "test", None))
            cons = self._expr_text(getattr(node, "consequent", None))
            alt = self._expr_text(getattr(node, "alternate", None))
            return f"{cons} if {test} else {alt}"
        if ntype == "SequenceExpression":
            exprs = getattr(node, "expressions", []) or []
            return ", ".join(self._expr_text(e) for e in exprs)
        if ntype == "ArrayExpression":
            return "[...]"
        if ntype == "ObjectExpression":
            return "{...}"
        if ntype == "ArrowFunctionExpression":
            params = getattr(node, "params", []) or []
            param_strs = [self._expr_text(p) for p in params]
            return f"({', '.join(param_strs)}) => ..."
        if ntype in _FUNCTION_TYPES:
            name = ""
            func_id = getattr(node, "id", None)
            if func_id and hasattr(func_id, "name"):
                name = func_id.name
            return name or "<anonymous>"
        if ntype == "ClassDeclaration" or ntype == "ClassExpression":
            class_id = getattr(node, "id", None)
            return class_id.name if class_id and hasattr(class_id, "name") else "<class>"
        if ntype == "SpreadElement":
            inner = self._expr_text(getattr(node, "argument", None))
            return f"...{inner}"
        if ntype == "RestElement":
            inner = self._expr_text(getattr(node, "argument", None))
            return f"...{inner}"
        if ntype == "MetaProperty":
            meta = self._expr_text(getattr(node, "meta", None))
            prop = self._expr_text(getattr(node, "property", None))
            return f"{meta}.{prop}"
        if ntype == "ObjectPattern":
            return "{...pattern}"
        if ntype == "ArrayPattern":
            return "[...pattern]"
        if ntype == "AssignmentPattern":
            left = self._expr_text(getattr(node, "left", None))
            return left or "<pattern>"
        if ntype == "VariableDeclarator":
            return self._expr_text(getattr(node, "id", None))
        if ntype == "ImportDeclaration":
            src = getattr(node, "source", None)
            return self._expr_text(src)
        if ntype == "ExportDeclaration":
            return "<export>"
        # Fallback
        return getattr(node, "name", "") or type(node).__name__
