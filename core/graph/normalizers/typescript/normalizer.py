"""TypeScript AST Normalizer — maps tree-sitter TypeScript AST to UnifiedNode / UnifiedEdge.

Converts TypeScript source parsed by ``tree-sitter-typescript`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter node model:
  - ``node.type`` → str (e.g. ``"function_declaration"``)
  - ``node.text`` → bytes (UTF-8 source text)
  - ``node.children`` → list of child nodes
  - ``node.start_point`` → (row, col), row is 0-indexed
  - ``node.end_point`` → (row, col)
  - Keywords/punctuation are leaf nodes (e.g. ``"if"``, ``"{"``)
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
    FrgType,
)

__all__ = ["Normalizer"]

# ---------------------------------------------------------------------------
# tree-sitter TypeScript node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||", "??",
    "+", "-", "*", "/", "%", "=", "!", "~",
    "=>", "->", "...", "?", "#", "@", "$",
    "<", ">",
    "if", "else", "for", "in", "of", "while", "do", "switch",
    "let", "const", "var",
    "function", "return", "break", "continue",
    "class", "new", "this", "super",
    "import", "export", "from", "as", "type",
    "async", "await", "yield",
    "true", "false", "null", "undefined",
    "interface", "enum", "extends", "implements",
    "abstract", "declare", "readonly", "static", "public", "private",
    "protected", "get", "set",
    "keyof", "infer", "is",
    "void", "delete", "typeof", "instanceof",
    "throw", "try", "catch", "finally",
    "case", "default", "with",
    "debugger", "constructor",
    # TypeScript-specific type syntax nodes to skip
    "type_annotation",
    "type_parameter_declaration",
    "type_arguments",
    "type_parameter",
    "type_identifier",
    "nested_type_identifier",
    "generic_type",
    "qualified_type_identifier",
    "type",
    "predefined_type",
    "union_type",
    "intersection_type",
    "literal_type",
    "conditional_type",
    "mapped_type",
    "indexed_access_type",
    "tuple_type",
    "array_type",
    "parenthesized_type",
    "type_predicate",
    "asserts",
    "implements_clause",
    "abstract_modifier",
    "readonly_modifier",
    "static_modifier",
    "accessibility_modifier",
    "override_modifier",
    "export_statement",  # handled specially by _walk_export
})

_LITERAL_TYPES = frozenset({
    "number", "string", "true", "false", "null", "undefined",
    "template_string", "regex",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier", "property_identifier", "private_property_identifier",
    "shorthand_property_identifier",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter TypeScript AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser

        lang = Language(tsts.language_typescript())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.ts",
            source_content=source,
        )
    """

    language = "typescript"

    def normalize(
        self,
        ast_nodes: Any,
        file_path: str,
        source_content: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        content_hash = ""
        if source_content:
            raw = source_content if isinstance(source_content, str) else source_content.decode("utf-8", errors="ignore")
            content_hash = hashlib.md5(
                raw.encode("utf-8", errors="ignore")
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

        root = getattr(ast_nodes, "root_node", ast_nodes)
        if root is not None:
            for idx, child in enumerate(root.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, _add_node, _add_edge, ctx_stack,
                                file_path, idx)

        assert nodes[0] is file_node
        return file_node, nodes[1:], edges

    # ===================================================================
    # Helpers
    # ===================================================================

    @staticmethod
    def _text(node) -> str:
        if node is None:
            return ""
        raw = node.text
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="ignore")
        return str(raw)

    @staticmethod
    def _lineno(node) -> int:
        if node is None:
            return 0
        try:
            return node.start_point[0] + 1
        except (AttributeError, IndexError):
            return 0

    def _end_lineno(self, node) -> int:
        if node is None:
            return 0
        try:
            return node.end_point[0] + 1
        except (AttributeError, IndexError):
            return 0

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

    def _frg_edge(self, add_edge, source, target, frg_type: str):
        add_edge({
            "label": EdgeLabel.FRG.value,
            "source": source,
            "target": target,
            "attrs": {"type": frg_type},
        })

    def _find_child_by_type(self, node, *types):
        """Return first child whose type is in *types*, or None."""
        for child in node.children:
            if child.type in types:
                return child
        return None

    def _find_children_by_type(self, node, *types):
        """Return all children whose type is in *types*."""
        return [c for c in node.children if c.type in types]

    # ===================================================================
    # Main dispatch
    # ===================================================================

    def _walk_node(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int | None:
        """Dispatch to the appropriate handler based on node type."""
        if node is None:
            return None
        ntype = node.type

        # Skip type-only nodes
        if ntype in _SKIP_TYPES:
            return None

        # Literals
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # Identifiers (leaf-level, not inside special constructs)
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, add_edge,
                                         ctx_stack, file_path, depth)

        # ---- Top-level / declaration nodes ----
        if ntype == "import_statement":
            return self._walk_import(node, add_node, add_edge,
                                    ctx_stack, file_path, depth)
        if ntype in ("function_declaration", "generator_function_declaration",
                     "async_function_declaration"):
            return self._walk_function(node, add_node, add_edge,
                                      ctx_stack, file_path, depth)
        if ntype == "arrow_function":
            return self._walk_arrow_function(node, add_node, add_edge,
                                              ctx_stack, file_path, depth)
        if ntype in ("class_declaration", "abstract_class_declaration"):
            return self._walk_class(node, add_node, add_edge,
                                   ctx_stack, file_path, depth)
        if ntype == "interface_declaration":
            return self._walk_interface(node, add_node, add_edge,
                                       ctx_stack, file_path, depth)
        if ntype == "enum_declaration":
            return self._walk_enum(node, add_node, add_edge,
                                   ctx_stack, file_path, depth)
        if ntype == "type_alias_declaration":
            return self._walk_type_alias(node, add_node, add_edge,
                                         ctx_stack, file_path, depth)

        # ---- Statement nodes ----
        if ntype == "if_statement":
            return self._walk_if(node, add_node, add_edge,
                                 ctx_stack, file_path, depth)
        if ntype in ("for_statement", "for_in_statement"):
            return self._walk_for(node, add_node, add_edge,
                                  ctx_stack, file_path, depth)
        if ntype in ("while_statement", "do_statement"):
            return self._walk_loop(node, add_node, add_edge,
                                   ctx_stack, file_path, depth)
        if ntype == "switch_statement":
            return self._walk_switch(node, add_node, add_edge,
                                      ctx_stack, file_path, depth)
        if ntype == "try_statement":
            return self._walk_try(node, add_node, add_edge,
                                  ctx_stack, file_path, depth)
        if ntype == "return_statement":
            return self._walk_return(node, add_node, add_edge,
                                     ctx_stack, file_path, depth)
        if ntype in ("break_statement", "continue_statement"):
            return self._walk_control(node, add_node, add_edge,
                                      ctx_stack, file_path, depth)
        if ntype == "throw_statement":
            return self._walk_throw(node, add_node, add_edge,
                                     ctx_stack, file_path, depth)

        # ---- Expression nodes ----
        if ntype in ("lexical_declaration", "variable_declaration"):
            return self._walk_var_decl(node, add_node, add_edge,
                                       ctx_stack, file_path, depth)
        if ntype == "expression_statement":
            return self._walk_expr_stmt(node, add_node, add_edge,
                                         ctx_stack, file_path, depth)
        if ntype == "assignment_expression":
            return self._walk_assignment(node, add_node, add_edge,
                                          ctx_stack, file_path, depth)
        if ntype == "augmented_assignment_expression":
            return self._walk_aug_assignment(node, add_node, add_edge,
                                              ctx_stack, file_path, depth)
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge,
                                     ctx_stack, file_path, depth)
        if ntype == "unary_expression":
            return self._walk_unary(node, add_node, add_edge,
                                     ctx_stack, file_path, depth)
        if ntype in ("call_expression",):
            return self._walk_call(node, add_node, add_edge,
                                   ctx_stack, file_path, depth)
        if ntype in ("call_member_expression",):
            return self._walk_method_call(node, add_node, add_edge,
                                          ctx_stack, file_path, depth)
        if ntype == "new_expression":
            return self._walk_new(node, add_node, add_edge,
                                  ctx_stack, file_path, depth)
        if ntype == "member_expression":
            return self._walk_member_expr(node, add_node, add_edge,
                                          ctx_stack, file_path, depth)
        if ntype == "subscript_expression":
            return self._walk_subscript(node, add_node, add_edge,
                                        ctx_stack, file_path, depth)

        # ---- TypeScript-specific expression nodes ----
        if ntype == "as_expression":
            return self._walk_as_expression(node, add_node, add_edge,
                                           ctx_stack, file_path, depth)
        if ntype == "non_null_expression":
            return self._walk_non_null(node, add_node, add_edge,
                                      ctx_stack, file_path, depth)
        if ntype in ("await_expression", "yield_expression"):
            return self._walk_await(node, add_node, add_edge,
                                     ctx_stack, file_path, depth)
        if ntype == "ternary_expression":
            return self._walk_ternary(node, add_node, add_edge,
                                      ctx_stack, file_path, depth)

        # ---- Container / fallback ----
        if ntype == "statement_block":
            return self._walk_block(node, add_node, add_edge,
                                    ctx_stack, file_path, depth)
        if ntype in ("object", "object_pattern", "array", "array_pattern",
                     "parenthesized_expression", "arguments",
                     "formal_parameters", "object_type", "enum_body",
                     "switch_body", "catch_clause", "finally_clause",
                     "else_clause", "condition", "update",
                     "initializer_clause", "increment", "decrement",
                     "computed_property_name", "spread_element",
                     "rest_pattern", "assignment_pattern",
                     "decorator"):
            return self._walk_children(node, add_node, add_edge,
                                       ctx_stack, file_path, depth)

        # Fallback: walk children
        return self._walk_children(node, add_node, add_edge,
                                  ctx_stack, file_path, depth)

    # ===================================================================
    # Import
    # ===================================================================

    def _walk_import(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        # Extract import source string
        source_str = ""
        for child in node.children:
            if child.type == "string":
                source_str = self._text(child).strip("\"'")

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": source_str or text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.IMPORT.value,
                "raw_type": "import_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Create DEPENDENCY node linked via FRG USE edge
        dep_pos = add_node({
            "label": NodeLabel.DEPENDENCY.value,
            "name": source_str,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "raw_type": "import_source",
            },
        })
        self._frg_edge(add_edge, pos, dep_pos, FrgType.USE.value)

        # Walk import clauses for named imports
        for child in node.children:
            if child.type in ("import_specifier", "namespace_import",
                              "named_imports", "import_clause"):
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, 0)
            elif child.type == "identifier":
                # Default import: import X from "module"
                name = self._text(child)
                if name:
                    id_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": name,
                        "lineno": self._lineno(child),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.GLOBAL.value,
                            "raw_type": "default_import",
                        },
                    })
                    self._own_edge(add_edge, ctx_stack, id_pos, 0)

        return pos

    # ===================================================================
    # Function
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name = ""

        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name or "<anonymous>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": FunctionType.FUNCTION.value,
                "raw_type": "function_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk parameters
        param_list = self._find_child_by_type(node, "formal_parameters")
        if param_list:
            for idx, child in enumerate(param_list.children):
                if child.type in ("required_parameter", "optional_parameter",
                                  "rest_parameter", "parameter"):
                    pname = ""
                    for c in child.children:
                        if c.type == "identifier":
                            pname = self._text(c)
                            break
                    if pname:
                        p_pos = add_node({
                            "label": NodeLabel.PARAMETER.value,
                            "name": pname,
                            "lineno": self._lineno(child),
                            "language": self.language,
                            "attrs": {
                                "type": IdentifierType.VARIABLE.value,
                                "raw_type": "parameter",
                            },
                        })
                        self._own_edge(add_edge, [(pos, NodeLabel.FUNCTION.value)], p_pos, idx)
                        self._ast_edge(add_edge, pos, p_pos, AstRole.ARG.value,
                                       extra={"index": idx})

        # Walk function body
        body = self._find_child_by_type(node, "statement_block")
        if body:
            ctx_stack.append((pos, NodeLabel.FUNCTION.value))
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Arrow function
    # ===================================================================

    def _walk_arrow_function(self, node, add_node, add_edge,
                             ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": "<arrow>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": FunctionType.FUNCTION.value,
                "raw_type": "arrow_function",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk parameters
        for child in node.children:
            if child.type in ("identifier", "formal_parameters"):
                if child.type == "identifier":
                    p_pos = add_node({
                        "label": NodeLabel.PARAMETER.value,
                        "name": self._text(child),
                        "lineno": self._lineno(child),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.VARIABLE.value,
                            "raw_type": "arrow_param",
                        },
                    })
                    self._own_edge(add_edge, [(pos, NodeLabel.FUNCTION.value)], p_pos, 0)
                    self._ast_edge(add_edge, pos, p_pos, AstRole.ARG.value,
                                   extra={"index": 0})
                elif child.type == "formal_parameters":
                    for idx, pchild in enumerate(child.children):
                        if pchild.type in ("required_parameter", "optional_parameter",
                                           "rest_parameter", "parameter"):
                            pname = ""
                            for c in pchild.children:
                                if c.type == "identifier":
                                    pname = self._text(c)
                                    break
                            if pname:
                                p_pos = add_node({
                                    "label": NodeLabel.PARAMETER.value,
                                    "name": pname,
                                    "lineno": self._lineno(pchild),
                                    "language": self.language,
                                    "attrs": {
                                        "type": IdentifierType.VARIABLE.value,
                                        "raw_type": "arrow_param",
                                    },
                                })
                                self._own_edge(add_edge, [(pos, NodeLabel.FUNCTION.value)], p_pos, idx)
                                self._ast_edge(add_edge, pos, p_pos, AstRole.ARG.value,
                                               extra={"index": idx})

        # Walk body (either statement_block or single expression)
        for child in node.children:
            if child.type == "statement_block":
                ctx_stack.append((pos, NodeLabel.FUNCTION.value))
                for idx, c in enumerate(child.children):
                    if c.type in _SKIP_TYPES:
                        continue
                    self._walk_node(c, add_node, add_edge, ctx_stack,
                                   file_path, idx)
                ctx_stack.pop()
                break

        return pos

    # ===================================================================
    # Class
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name = ""
        class_type = ClassType.CLASS.value

        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name or "<anonymous_class>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": class_type,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk class body
        body = self._find_child_by_type(node, "class_body")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Interface
    # ===================================================================

    def _walk_interface(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name = ""
        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name or "<anonymous_interface>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ClassType.INTERFACE.value,
                "raw_type": "interface_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk interface body for members
        body = self._find_child_by_type(node, "object_type",
                                         "interface_body",
                                         "statement_block")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Enum
    # ===================================================================

    def _walk_enum(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name = ""
        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name or "<anonymous_enum>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ClassType.ENUM.value,
                "raw_type": "enum_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk enum body for members
        body = self._find_child_by_type(node, "enum_body")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                if child.type == "enum_assignment":
                    member_name = ""
                    for c in child.children:
                        if c.type == "identifier":
                            member_name = self._text(c)
                            break
                    if member_name:
                        m_pos = add_node({
                            "label": NodeLabel.IDENTIFIER.value,
                            "name": member_name,
                            "lineno": self._lineno(child),
                            "language": self.language,
                            "attrs": {
                                "type": IdentifierType.FIELD.value,
                                "raw_type": "enum_member",
                            },
                        })
                        self._own_edge(add_edge, [(pos, NodeLabel.CLASS.value)], m_pos, idx)
                elif child.type == "identifier":
                    member_name = self._text(child)
                    m_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": member_name,
                        "lineno": self._lineno(child),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.FIELD.value,
                            "raw_type": "enum_member",
                        },
                    })
                    self._own_edge(add_edge, [(pos, NodeLabel.CLASS.value)], m_pos, idx)

        return pos

    # ===================================================================
    # Type alias
    # ===================================================================

    def _walk_type_alias(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name = ""
        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name or "<type_alias>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ClassType.CLASS.value,
                "raw_type": "type_alias_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # If
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "if",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "raw_type": "if_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        for child in node.children:
            if child.type not in _SKIP_TYPES and child.type not in (
                "statement_block", "else_clause"
            ):
                cond_pos = self._walk_node(child, add_node, add_edge,
                                           ctx_stack, file_path, 0)
                if cond_pos is not None:
                    self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)
                break

        # Walk consequent body
        for child in node.children:
            if child.type == "statement_block":
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                for idx, c in enumerate(child.children):
                    if c.type in _SKIP_TYPES:
                        continue
                    self._walk_node(c, add_node, add_edge, ctx_stack,
                                   file_path, idx)
                ctx_stack.pop()
                break

        # Walk else clause
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause:
            for child in else_clause.children:
                if child.type == "statement_block":
                    ctx_stack.append((pos, NodeLabel.BRANCH.value))
                    for idx, c in enumerate(child.children):
                        if c.type in _SKIP_TYPES:
                            continue
                        self._walk_node(c, add_node, add_edge, ctx_stack,
                                       file_path, idx)
                    ctx_stack.pop()
                    break
                elif child.type == "if_statement":
                    else_pos = self._walk_if(child, add_node, add_edge,
                                             [(pos, NodeLabel.BRANCH.value)], file_path, 0)
                    if else_pos is not None:
                        self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

        return pos

    # ===================================================================
    # For
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "for",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk non-body children (condition, initializer, etc.)
        body_node = None
        for child in node.children:
            if child.type == "statement_block":
                body_node = child
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                           file_path, 0)

        # Walk body
        if body_node:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            for idx, c in enumerate(body_node.children):
                if c.type in _SKIP_TYPES:
                    continue
                self._walk_node(c, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # While / Do-While
    # ===================================================================

    def _walk_loop(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "while",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body_node = None
        for child in node.children:
            if child.type == "statement_block":
                body_node = child
                continue
            if child.type in _SKIP_TYPES:
                continue
            cond_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        if body_node:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            for idx, c in enumerate(body_node.children):
                if c.type in _SKIP_TYPES:
                    continue
                self._walk_node(c, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Switch
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "switch",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "raw_type": "switch_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "switch_body")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Try
    # ===================================================================

    def _walk_try(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "try",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TRY.value,
                "raw_type": "try_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "statement_block":
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                for idx, c in enumerate(child.children):
                    if c.type in _SKIP_TYPES:
                        continue
                    self._walk_node(c, add_node, add_edge, ctx_stack,
                                   file_path, idx)
                ctx_stack.pop()
            elif child.type in ("catch_clause", "finally_clause"):
                # Walk catch/finally body
                for c in child.children:
                    if c.type in _SKIP_TYPES:
                        continue
                    if c.type == "identifier":
                        # Extract error variable
                        err_name = self._text(c)
                        err_pos = add_node({
                            "label": NodeLabel.IDENTIFIER.value,
                            "name": err_name,
                            "lineno": self._lineno(c),
                            "language": self.language,
                            "attrs": {
                                "type": IdentifierType.VARIABLE.value,
                                "raw_type": "catch_variable",
                            },
                        })
                        self._own_edge(add_edge, [(pos, NodeLabel.BRANCH.value)], err_pos, 0)
                    elif c.type == "statement_block":
                        ctx_stack.append((pos, NodeLabel.BRANCH.value))
                        for idx, sc in enumerate(c.children):
                            if sc.type in _SKIP_TYPES:
                                continue
                            self._walk_node(sc, add_node, add_edge, ctx_stack,
                                           file_path, idx)
                        ctx_stack.pop()

        return pos

    # ===================================================================
    # Return
    # ===================================================================

    def _walk_return(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "return",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "raw_type": "return_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk return value expression
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            ret_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if ret_pos is not None:
                self._ast_edge(add_edge, pos, ret_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Break / Continue
    # ===================================================================

    def _walk_control(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        ctrl_type = (OperatorType.BREAK.value
                     if node.type == "break_statement"
                     else OperatorType.CONTINUE.value)
        name = "break" if node.type == "break_statement" else "continue"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ctrl_type,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            lbl_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if lbl_pos is not None:
                self._ast_edge(add_edge, pos, lbl_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Throw
    # ===================================================================

    def _walk_throw(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "throw",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.THROW.value,
                "raw_type": "throw_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Variable declaration (let / const / var)
    # ===================================================================

    def _walk_var_decl(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        kind = ""
        for child in node.children:
            if child.type in ("let", "const", "var"):
                kind = child.type
                break

        # Walk each declarator
        last_pos = None
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "variable_declarator":
                pos = self._walk_declarator(child, add_node, add_edge,
                                            ctx_stack, file_path,
                                            depth + idx, kind)
                if pos is not None:
                    last_pos = pos

        return last_pos if last_pos is not None else self._lineno(node)

    def _walk_declarator(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth, kind="let") -> int:
        lineno = self._lineno(node)
        name = ""

        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name or "<var>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "raw_type": "variable_declarator",
                "kind": kind,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk initializer — create assignment operator node for DFG builder
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "identifier":
                continue
            init_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if init_pos is not None:
                eq_pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": "=",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "variable_declarator",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + 1)
                self._ast_edge(add_edge, eq_pos, pos, AstRole.LHS.value)
                self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)
            break

        return pos

    # ===================================================================
    # Expression statement
    # ===================================================================

    def _walk_expr_stmt(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int | None:
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            return self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, depth)
        return None

    # ===================================================================
    # Assignment
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text if len(text) < 80 else "assign",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "raw_type": "assignment_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        left_node = None
        right_node = None
        found_op = False
        for child in node.children:
            if child.type == "=":
                found_op = True
                continue
            if child.type in _SKIP_TYPES:
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        if left_node is not None:
            lhs_pos = self._walk_node(left_node, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if lhs_pos is not None:
                self._ast_edge(add_edge, pos, lhs_pos, AstRole.LHS.value)

        if right_node is not None:
            rhs_pos = self._walk_node(right_node, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if rhs_pos is not None:
                self._ast_edge(add_edge, pos, rhs_pos, AstRole.RHS.value)

        return pos

    def _walk_aug_assignment(self, node, add_node, add_edge,
                             ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text if len(text) < 80 else "aug_assign",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AUG_ASSIGN.value,
                "raw_type": "augmented_assignment_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Binary expression
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Find operator node
        op_node = None
        for child in node.children:
            if child.type in ("==", "!=", "===", "!==", ">=", "<=", ">", "<",
                              "&&", "||", "??", "+", "-", "*", "/", "%",
                              "**", "&", "|", "^", "<<", ">>", ">>>",
                              "in", "instanceof"):
                op_node = child
                break

        op_text = self._text(op_node) if op_node else "<binary>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "binary_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk left and right operands
        found_op = False
        for child in node.children:
            if child == op_node:
                found_op = True
                continue
            if child.type in _SKIP_TYPES:
                continue
            side = AstRole.RHS.value if found_op else AstRole.LHS.value
            child_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, side)

        return pos

    # ===================================================================
    # Unary expression
    # ===================================================================

    def _walk_unary(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        op_text = ""
        for child in node.children:
            if child.type in ("-", "!", "~", "typeof", "void", "delete"):
                op_text = self._text(child)
                break

        if not op_text:
            op_text = "<unary>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "raw_type": "unary_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk operand (skip the operator token)
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Call expression (func(args))
    # ===================================================================

    def _extract_member_name(self, member_node) -> str:
        """Extract dotted name from a member_expression node.

        Handles nested member expressions like ``a.b.c`` by recursion.
        Returns the full dotted name string, e.g. ``'console.log'``.
        """
        parts = []
        self._collect_member_parts(member_node, parts)
        return ".".join(parts)

    def _collect_member_parts(self, node, parts):
        """Recursively collect identifier/property_identifier names from member_expression."""
        if node.type == "identifier":
            parts.append(self._text(node))
        elif node.type == "property_identifier":
            parts.append(self._text(node))
        elif node.type == "this":
            parts.append("this")
        elif node.type == "member_expression":
            for child in node.children:
                if child.type not in (".", "?."):
                    self._collect_member_parts(child, parts)

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        callee = None
        member_expr = None  # for a.b() style calls
        for child in node.children:
            if child.type == "identifier":
                callee = child
                break
            elif child.type == "member_expression":
                member_expr = child
                break

        if callee is not None:
            callee_name = self._text(callee)
        elif member_expr is not None:
            # Extract full name from member_expression (e.g. "console.log")
            callee_name = self._extract_member_name(member_expr)
            callee = member_expr  # walk the whole member_expression as callee
        else:
            callee_name = "<call>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CALL.value,
                "raw_type": "call_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk callee
        if callee is not None:
            callee_pos = self._walk_node(callee, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if callee_pos is not None:
                self._ast_edge(add_edge, pos, callee_pos, AstRole.CALLEE.value)

        # Walk arguments
        arg_list = self._find_child_by_type(node, "arguments")
        if arg_list:
            for idx, arg in enumerate(arg_list.children):
                if arg.type in ("(", ")", ","):
                    continue
                arg_pos = self._walk_node(arg, add_node, add_edge,
                                          ctx_stack, file_path, 0)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"index": idx})

        # use edge to function (callee target, may be external)
        if callee_name and isinstance(callee_name, str) and callee_name != "<call>":
            func_name = callee_name.rsplit(".", 1)[-1]
            if "::" in func_name:
                func_name = func_name.rsplit("::", 1)[-1]
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": func_name,
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
                           "call_type": CgCallType.DIRECT.value,
                           "lineno": lineno,
                       }})

        return pos

    # ===================================================================
    # Method call (obj.method(args))
    # ===================================================================

    def _walk_method_call(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        method_name_node = self._find_child_by_type(node, "property_identifier")
        method_name = self._text(method_name_node) if method_name_node else "<method>"

        # Get the object (everything before the method name)
        obj_node = None
        for child in node.children:
            if child.type in ("property_identifier", ".", "(", ")", ","):
                continue
            if child.type == "arguments":
                continue
            obj_node = child
            break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": method_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.METHOD_CALL.value,
                "raw_type": "call_member_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk object
        if obj_node is not None:
            obj_pos = self._walk_node(obj_node, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.OPERAND.value)

        # Walk arguments
        arg_list = self._find_child_by_type(node, "arguments")
        if arg_list:
            for idx, arg in enumerate(arg_list.children):
                if arg.type in ("(", ")", ","):
                    continue
                arg_pos = self._walk_node(arg, add_node, add_edge,
                                          ctx_stack, file_path, 0)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"index": idx})

        # use edge to function (callee target, may be external)
        if method_name and isinstance(method_name, str) and method_name != "<method>":
            func_name = method_name.rsplit(".", 1)[-1]
            if "::" in func_name:
                func_name = func_name.rsplit("::", 1)[-1]
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": func_name,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": method_name,
                    "type": FunctionType.FUNCTION.value,
                    "is_external": True,
                },
            })
            add_edge({"label": EdgeLabel.USE.value, "source": pos, "target": target_pos,
                       "attrs": {
                           "call_type": CgCallType.METHOD.value,
                           "lineno": lineno,
                       }})

        return pos

    # ===================================================================
    # New expression (new Class())
    # ===================================================================

    def _walk_new(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        type_name = ""
        for child in node.children:
            if child.type == "identifier":
                type_name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": type_name or "new",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.NEW.value,
                "raw_type": "new_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk arguments
        arg_list = self._find_child_by_type(node, "arguments")
        if arg_list:
            for idx, arg in enumerate(arg_list.children):
                if arg.type in ("(", ")", ","):
                    continue
                arg_pos = self._walk_node(arg, add_node, add_edge,
                                          ctx_stack, file_path, 0)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"index": idx})

        return pos

    # ===================================================================
    # Member expression (obj.prop)
    # ===================================================================

    def _walk_member_expr(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        prop_node = self._find_child_by_type(node, "property_identifier",
                                               "private_property_identifier")
        prop_name = self._text(prop_node) if prop_node else ""

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": prop_name or text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.FIELD.value,
                "raw_type": "member_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk object
        for child in node.children:
            if child.type in ("property_identifier", "private_property_identifier",
                              "."):
                continue
            obj_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Subscript expression (arr[i])
    # ===================================================================

    def _walk_subscript(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "[]",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "subscript_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # TypeScript-specific: as expression (type cast)
    # ===================================================================

    def _walk_as_expression(self, node, add_node, add_edge,
                           ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "as",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.TYPE_CAST.value,
                "raw_type": "as_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk the value expression (skip the 'as' keyword and type)
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "as":
                continue
            # Skip type annotation nodes
            if child.type in ("type_annotation", "type_identifier",
                              "predefined_type", "generic_type",
                              "qualified_type_identifier",
                              "union_type", "intersection_type",
                              "literal_type", "conditional_type",
                              "nested_type_identifier"):
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # TypeScript-specific: non-null expression (expr!)
    # ===================================================================

    def _walk_non_null(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "!",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "raw_type": "non_null_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk the inner expression
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "!":
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Await / Yield
    # ===================================================================

    def _walk_await(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        op_name = "await" if node.type == "await_expression" else "yield"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AWAIT.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Ternary expression
    # ===================================================================

    def _walk_ternary(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "?:",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "raw_type": "ternary_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition, then consequent, then alternate
        phase = 0  # 0=condition, 1=consequent, 2=alternate
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                role = [AstRole.CONDITION.value, AstRole.IFTRUE.value,
                        AstRole.IFFALSE.value][min(phase, 2)]
                self._ast_edge(add_edge, pos, child_pos, role)
            phase += 1

        return pos

    # ===================================================================
    # Block (walk children only)
    # ===================================================================

    def _walk_block(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int | None:
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                           file_path, depth + idx)
        return None

    # ===================================================================
    # Children walker (fallback)
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        last_pos = None
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                  file_path, depth + idx)
            if pos is not None:
                last_pos = pos
        return last_pos

    # ===================================================================
    # Literal
    # ===================================================================

    def _walk_literal(self, node, add_node, file_path) -> int:
        ntype = node.type
        text = self._text(node)
        lineno = self._lineno(node)

        if ntype in ("number",):
            return self._emit_const(add_node, text, lineno, ConstType.NUMBER)
        if ntype in ("string",):
            return self._emit_const(add_node, text, lineno, ConstType.STRING)
        if ntype in ("true", "false"):
            return self._emit_const(add_node, text, lineno, ConstType.BOOLEAN)
        if ntype in ("null", "undefined"):
            return self._emit_const(add_node, text, lineno, ConstType.NULL)
        if ntype == "regex":
            return self._emit_const(add_node, text, lineno, ConstType.CONSTANT)
        if ntype == "template_string":
            return self._emit_const(add_node, text, lineno, ConstType.STRING)
        return self._emit_const(add_node, text, lineno, ConstType.CONSTANT)

    # ===================================================================
    # Identifier
    # ===================================================================

    def _walk_identifier(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        name = self._text(node)
        lineno = self._lineno(node)
        return self._emit_identifier(add_node, name, lineno,
                                      IdentifierType.VARIABLE)

    # ===================================================================
    # Emit helpers
    # ===================================================================

    def _emit_const(self, add_node, name, lineno, const_type) -> int:
        return add_node({
            "label": NodeLabel.CONST.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": const_type.value,
                "raw_type": "literal",
            },
        })

    def _emit_identifier(self, add_node, name, lineno, id_type) -> int:
        return add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": id_type.value,
                "raw_type": "identifier",
            },
        })
