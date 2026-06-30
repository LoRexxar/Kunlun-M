"""C# AST Normalizer — maps tree-sitter C# AST to UnifiedNode / UnifiedEdge.

Converts C# source parsed by ``tree-sitter-c-sharp`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter node model:
  - ``node.type`` → str (e.g. ``"class_declaration"``)
  - ``node.text`` → bytes (UTF-8 source text)
  - ``node.children`` → list of child nodes
  - ``node.start_point`` → (row, col), row is 0-indexed
  - ``node.end_point`` → (row, col)
  - Keywords/punctuation are leaf nodes (e.g. ``"class"``, ``"{"``)
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
# tree-sitter C# node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||", "??",
    "+", "-", "*", "/", "%", "=", "!", "~",
    ".", "->", "?.", "..", "=>",
    "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "^=", "<<=", ">>=",
    "<", ">",
    "if", "else", "for", "foreach", "while", "do",
    "switch", "case", "default", "break", "continue", "goto",
    "try", "catch", "finally", "throw", "return",
    "in", "out", "ref", "params", "is", "as",
    "using", "namespace", "class", "struct", "interface", "enum",
    "public", "private", "protected", "static", "virtual",
    "override", "abstract", "sealed", "readonly", "const", "async",
    "partial", "new", "this", "base",
    "get", "set", "value", "var",
    "true", "false", "null", "typeof", "nameof",
    "where", "select", "from", "orderby", "group", "by",
    "ascending", "descending", "join", "on", "equals",
    "into", "let", "await", "yield",
    "void", "int", "string", "bool", "double", "float",
    "decimal", "long", "short", "byte", "char", "object",
    # C# specific punctuation
    "accessor_declaration", "accessor_list",
    "attribute", "attribute_list", "attribute_argument",
    "attribute_argument_list", "attribute_arguments",
    "constraint", "type_parameter", "type_parameter_list",
    "type_argument", "type_argument_list",
    "separator",
    "declaration_list", "enum_member_declaration_list",
    "parameter", "variable_declarator",
    "nullable_type", "array_type", "pointer_type",
    "tuple_type", "tuple_element",
    "predefined_type", "interpolated_string_text",
    "global_attribute_list", "global_using_directive",
    "alias_qualifier",
    "when_clause",
    # bracket/brace tokens
    "open_brace", "close_brace", "open_paren", "close_paren",
    "open_bracket", "close_bracket",
    # semicolon tokens
    "semicolon",
})

_LITERAL_TYPES = frozenset({
    "integer_literal", "real_literal",
    "string_literal", "character_literal",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier", "generic_name",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter C# AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_c_sharp as tscs

        lang = Language(tscs.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/Program.cs",
            source_content=source,
        )
    """

    language = "csharp"

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

    def _find_child_by_type(self, node, *types):
        """Return first child matching one of the given types."""
        if node is None:
            return None
        for c in node.children:
            if c.type in types:
                return c
        return None

    def _find_children_by_type(self, node, *types):
        """Return all children matching one of the given types."""
        if node is None:
            return []
        return [c for c in node.children if c.type in types]

    def _is_skip(self, node):
        return node.type in _SKIP_TYPES

    def _has_modifier(self, node, mod_name):
        """Check if a declaration node has a specific modifier."""
        for child in node.children:
            if child.type == mod_name:
                return True
        return False

    # ===================================================================
    # Walk dispatch
    # ===================================================================

    def _walk_node(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int | None:
        if node is None:
            return None
        if self._is_skip(node):
            return None

        ntype = node.type

        # ---- Using directive (import) ---------------------------------
        if ntype == "using_directive":
            return self._walk_using(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Namespace declaration (container) -----------------------
        if ntype == "namespace_declaration":
            return self._walk_namespace(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Class declaration ----------------------------------------
        if ntype == "class_declaration":
            return self._walk_class(node, add_node, add_edge, ctx_stack,
                                    file_path, depth, ClassType.CLASS)

        # ---- Interface declaration -------------------------------------
        if ntype == "interface_declaration":
            return self._walk_class(node, add_node, add_edge, ctx_stack,
                                    file_path, depth, ClassType.INTERFACE)

        # ---- Struct declaration ---------------------------------------
        if ntype == "struct_declaration":
            return self._walk_class(node, add_node, add_edge, ctx_stack,
                                    file_path, depth, ClassType.STRUCT)

        # ---- Enum declaration ------------------------------------------
        if ntype == "enum_declaration":
            return self._walk_enum(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Delegate declaration (container) --------------------------
        if ntype == "delegate_declaration":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Constructor -----------------------------------------------
        if ntype == "constructor_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, FunctionType.CONSTRUCTOR)

        # ---- Destructor ------------------------------------------------
        if ntype == "destructor_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, FunctionType.DESTRUCTOR)

        # ---- Method declaration ----------------------------------------
        if ntype == "method_declaration":
            is_static = self._has_modifier(node, "static")
            func_type = FunctionType.FUNCTION if is_static else FunctionType.METHOD
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, func_type)

        # ---- Property declaration ---------------------------------------
        if ntype == "property_declaration":
            return self._walk_property(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Field declaration -----------------------------------------
        if ntype == "field_declaration":
            return self._walk_field(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Local variable declaration --------------------------------
        if ntype == "local_variable_declaration" or ntype == "variable_declaration":
            return self._walk_local_var(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Lambda expression -----------------------------------------
        if ntype == "lambda_expression":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, FunctionType.LAMBDA)

        # ---- Local function statement ----------------------------------
        if ntype == "local_function_statement":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, FunctionType.FUNCTION)

        # ---- Expression statement --------------------------------------
        if ntype == "expression_statement":
            inner = self._find_child_by_type(
                node, "invocation_expression", "assignment_expression",
                "object_creation_expression", "binary_expression",
                "unary_expression", "return_statement", "throw_statement",
                "throw_expression", "await_expression", "yield_statement",
                "break_statement", "continue_statement", "goto_statement",
                "member_access_expression", "conditional_expression",
                "is_expression", "as_expression", "cast_expression",
                "postfix_unary_expression", "prefix_unary_expression",
                "checked_expression", "unchecked_expression",
                "default_expression", "sizeof_expression",
                "typeof_expression", "nameof_expression",
            )
            if inner is not None:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                       file_path, depth)
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Invocation expression (call) ------------------------------
        if ntype == "invocation_expression":
            return self._walk_invocation(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Object creation expression (new) -------------------------
        if ntype == "object_creation_expression":
            return self._walk_object_creation(node, add_node, add_edge,
                                               ctx_stack, file_path, depth)

        # ---- Assignment expression -------------------------------------
        if ntype == "assignment_expression":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Binary expression -----------------------------------------
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Unary expression ------------------------------------------
        if ntype in ("prefix_unary_expression", "postfix_unary_expression"):
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Cast expression -------------------------------------------
        if ntype == "cast_expression":
            return self._walk_cast(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Member access expression (a.b) ---------------------------
        if ntype == "member_access_expression":
            return self._walk_member_access(node, add_node, add_edge,
                                              ctx_stack, file_path, depth)

        # ---- Element access expression (a[key]) ------------------------
        if ntype == "element_access_expression":
            return self._walk_element_access(node, add_node, add_edge,
                                             ctx_stack, file_path, depth)

        # ---- Conditional expression (ternary) --------------------------
        if ntype == "conditional_expression":
            return self._walk_conditional(node, add_node, add_edge,
                                           ctx_stack, file_path, depth)

        # ---- Branch: if statement --------------------------------------
        if ntype == "if_statement":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: switch statement ---------------------------------
        if ntype == "switch_statement":
            return self._walk_switch(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Branch: for statement -------------------------------------
        if ntype == "for_statement":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Branch: foreach statement ---------------------------------
        if ntype == "foreach_statement":
            return self._walk_foreach(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Branch: while statement -----------------------------------
        if ntype == "while_statement":
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Branch: do statement --------------------------------------
        if ntype == "do_statement":
            return self._walk_do(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: try statement -------------------------------------
        if ntype == "try_statement":
            return self._walk_try(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Return statement ------------------------------------------
        if ntype == "return_statement":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Throw statement / expression -------------------------------
        if ntype in ("throw_statement", "throw_expression"):
            return self._walk_throw(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Await expression ------------------------------------------
        if ntype == "await_expression":
            return self._walk_await(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Yield statement -------------------------------------------
        if ntype == "yield_statement":
            return self._walk_yield(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Break / Continue / Goto ----------------------------------
        if ntype in ("break_statement", "continue_statement", "goto_statement"):
            return self._walk_control(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Block (statement list) ------------------------------------
        if ntype == "block":
            return self._walk_block(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Statement list (in try/for etc.) ---------------------------
        if ntype == "statement_list":
            return self._walk_block(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Literals --------------------------------------------------
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # ---- True / False (boolean) -------------------------------------
        if ntype in ("true", "false"):
            return self._emit_const(add_node, self._text(node),
                                     self._lineno(node), ConstType.BOOLEAN)

        # ---- Null literal ---------------------------------------------
        if ntype == "null_literal":
            return self._emit_const(add_node, "null",
                                     self._lineno(node), ConstType.NULL)

        # ---- Identifiers ----------------------------------------------
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, file_path)

        # ---- Qualified name (namespace.member) -------------------------
        if ntype == "qualified_name":
            return self._walk_qualified_name(node, add_node, add_edge,
                                               ctx_stack, file_path, depth)

        # ---- this / base keywords --------------------------------------
        if ntype == "this":
            return self._emit_identifier(add_node, "this", self._lineno(node),
                                         IdentifierType.THIS)

        if ntype == "base":
            return self._emit_identifier(add_node, "base", self._lineno(node),
                                         IdentifierType.SUPER)

        # ---- Argument list (walk args) ---------------------------------
        if ntype == "argument_list":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Parameter list (walk params) ------------------------------
        if ntype == "parameter_list":
            return self._walk_parameter_list(node, add_node, add_edge,
                                              ctx_stack, file_path, depth)

        # ---- Parenthesized expression ----------------------------------
        if ntype == "parenthesized_expression":
            inner = self._find_child_by_type(node,
                "binary_expression", "unary_expression", "invocation_expression",
                "member_access_expression", "object_creation_expression",
                "assignment_expression", "identifier", "generic_name",
                "qualified_name", "conditional_expression", "cast_expression",
                "is_expression", "as_expression", "await_expression",
                "lambda_expression", "default_expression", "throw_expression",
                "prefix_unary_expression", "postfix_unary_expression")
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Interpolated string expression ----------------------------
        if ntype == "interpolated_string_expression":
            str_pos = self._emit_const(add_node, self._text(node),
                                       self._lineno(node), ConstType.STRING)
            # Walk interpolation children for DFG tracking
            for child in node.children:
                if child.type == "interpolation":
                    self._walk_interpolation(child, add_node, add_edge,
                                             str_pos, ctx_stack,
                                             file_path, depth)
            return str_pos

        # ---- Default expression ----------------------------------------
        if ntype == "default_expression":
            return self._emit_const(add_node, "default",
                                     self._lineno(node), ConstType.CONSTANT)

        # ---- Fallback --------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Import: using directive
    # ===================================================================

    def _walk_interpolation(self, node, add_node, add_edge, str_pos,
                            ctx_stack, file_path, depth) -> None:
        """Walk expression children inside an interpolation node.

        For each expression (identifier, call, etc.), emit a DFG edge from
        the expression to the string constant so taint can propagate.
        """
        if not node.children:
            return
        for child in node.children:
            ctype = child.type
            # Skip punctuation markers
            if ctype in ("interpolation_brace", ",", ";"):
                continue
            expr_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, depth)
            if expr_pos is not None:
                add_edge({"label": "dfg", "source": expr_pos, "target": str_pos})
                if ctx_stack:
                    self._own_edge(add_edge, ctx_stack, expr_pos, depth)

    # ===================================================================
    # Import: using directive
    # ===================================================================

    def _walk_using(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # using System.IO; → qualified_name or alias
        qname = self._find_child_by_type(node, "qualified_name", "identifier",
                                         "generic_name", "alias_qualifier")
        name = self._text(qname).strip().rstrip(";") if qname else "<using>"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.USE.value,
                "raw_type": "using_directive",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # DEPENDENCY edge
        file_pos = ctx_stack[0][0]
        add_edge({
            "label": EdgeLabel.FRG.value,
            "source": file_pos,
            "target": pos,
            "attrs": {"type": FrgType.USE.value},
        })

        return pos

    # ===================================================================
    # Namespace declaration (container, no node generated)
    # ===================================================================

    def _walk_namespace(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int | None:
        # Walk the declaration_list (body)
        body = self._find_child_by_type(node, "declaration_list")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, depth + idx)
        return None

    # ===================================================================
    # Class / Interface / Struct
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth, class_type) -> int:
        lineno = self._lineno(node)
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<class>"

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": class_type.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk body (declaration_list)
        ctx_stack.append((pos, NodeLabel.CLASS.value))
        body = self._find_child_by_type(node, "declaration_list")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, depth + idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Enum
    # ===================================================================

    def _walk_enum(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<enum>"

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ClassType.ENUM.value,
                "raw_type": "enum_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk enum members
        ctx_stack.append((pos, NodeLabel.CLASS.value))
        members = self._find_child_by_type(node, "enum_member_declaration_list")
        if members:
            for idx, child in enumerate(members.children):
                if child.type in _SKIP_TYPES:
                    continue
                if child.type == "enum_member_declaration":
                    member_name = self._find_child_by_type(child, "identifier")
                    m_name = self._text(member_name) if member_name else "<member>"
                    m_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": m_name,
                        "lineno": self._lineno(child),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.FIELD.value,
                            "raw_type": "enum_member_declaration",
                        },
                    })
                    self._own_edge(add_edge, ctx_stack, m_pos, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Function (method / constructor / destructor / lambda / local_function)
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth, func_type) -> int:
        lineno = self._lineno(node)

        # Extract function name
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<function>"

        # For constructor, name comes from identifier
        if func_type == FunctionType.CONSTRUCTOR:
            name_node = self._find_child_by_type(node, "identifier")
            name = self._text(name_node) if name_node else "<constructor>"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": func_type.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk parameters
        param_list = self._find_child_by_type(node, "parameter_list")
        if param_list:
            self._walk_parameter_list(param_list, add_node, add_edge, ctx_stack,
                                       file_path, 0)

        # Walk body
        body = self._find_child_by_type(node, "block", "arrow_expression_clause")
        if body:
            ctx_stack.append((pos, NodeLabel.FUNCTION.value))
            if body.type == "block":
                self._walk_block(body, add_node, add_edge, ctx_stack, file_path, 0)
            else:
                # Arrow expression body: => expression
                for child in body.children:
                    if child.type in _SKIP_TYPES:
                        continue
                    child_pos = self._walk_node(child, add_node, add_edge,
                                                  ctx_stack, file_path, 0)
                    if child_pos is not None:
                        self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Property declaration
    # ===================================================================

    def _walk_parameter_list(self, node, add_node, add_edge,
                              ctx_stack, file_path, depth) -> int | None:
        last_pos = None
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "parameter":
                p_name = self._find_child_by_type(child, "identifier")
                name = self._text(p_name) if p_name else "<param>"
                p_pos = add_node({
                    "label": NodeLabel.PARAMETER.value,
                    "name": name,
                    "lineno": self._lineno(child),
                    "language": self.language,
                    "attrs": {
                        "type": IdentifierType.VARIABLE.value,
                        "raw_type": "parameter",
                    },
                })
                self._own_edge(add_edge, ctx_stack, p_pos, idx)
                last_pos = p_pos
        return last_pos

    # ===================================================================
    # Property declaration
    # ===================================================================

    def _walk_property(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<property>"

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.PROPERTY.value,
                "raw_type": "property_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk accessor body (get/set)
        accessor_list = self._find_child_by_type(node, "accessor_list")
        if accessor_list:
            ctx_stack.append((pos, NodeLabel.IDENTIFIER.value))
            self._walk_children(accessor_list, add_node, add_edge,
                               ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Field declaration
    # ===================================================================

    def _walk_field(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # A field_declaration can have multiple declarators
        decls = self._find_children_by_type(node, "variable_declarator")
        last_pos = None
        for d_idx, decl in enumerate(decls):
            name_node = self._find_child_by_type(decl, "identifier")
            name = self._text(name_node) if name_node else "<field>"

            d_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.FIELD.value,
                    "raw_type": "field_declaration",
                },
            })
            self._own_edge(add_edge, ctx_stack, d_pos, depth + d_idx)

            # Walk initializer
            eq_clause = self._find_child_by_type(decl, "equals_value_clause")
            found_eq = False
            init_children = []
            if eq_clause:
                init_children = [c for c in eq_clause.children if c.type not in _SKIP_TYPES]
            else:
                for child in decl.children:
                    if found_eq and child.type not in _SKIP_TYPES:
                        init_children = [child]
                        break
                    if child.type == "=":
                        found_eq = True

            if init_children:
                # Create assignment operator node for DFG builder
                eq_pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": "=",
                    "lineno": self._lineno(decl),
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "field_declaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + d_idx)
                self._ast_edge(add_edge, eq_pos, d_pos, AstRole.LHS.value)

                for child in init_children:
                    init_pos = self._walk_node(child, add_node, add_edge,
                                                ctx_stack, file_path, 0)
                    if init_pos is not None:
                        self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)
                    break

            last_pos = d_pos

        return last_pos if last_pos is not None else add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": "<field>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.FIELD.value,
                "raw_type": "field_declaration",
            },
        })

    # ===================================================================
    # Local variable declaration
    # ===================================================================

    def _walk_local_var(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int | None:
        # Walk each variable_declarator
        decls = self._find_children_by_type(node, "variable_declarator")
        last_pos = None
        for d_idx, decl in enumerate(decls):
            name_node = self._find_child_by_type(decl, "identifier")
            name = self._text(name_node) if name_node else "<var>"

            d_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": name,
                "lineno": self._lineno(decl),
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "raw_type": "local_variable_declaration",
                },
            })
            self._own_edge(add_edge, ctx_stack, d_pos, depth + d_idx)

            # Find initializer: first child after identifier and "=" token
            eq_clause = self._find_child_by_type(decl, "equals_value_clause")
            found_eq = False
            init_children = []
            if eq_clause:
                init_children = [c for c in eq_clause.children if c.type not in _SKIP_TYPES]
            else:
                # C# tree-sitter: variable_declarator children are [identifier, =, expr, ...]
                found_eq = False
                for child in decl.children:
                    if found_eq and child.type not in _SKIP_TYPES:
                        init_children = [child]
                        break
                    if child.type == "=":
                        found_eq = True

            if init_children:
                # Create assignment operator node for DFG builder
                eq_pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": "=",
                    "lineno": self._lineno(decl),
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "local_variable_declaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + d_idx)
                self._ast_edge(add_edge, eq_pos, d_pos, AstRole.LHS.value)

                for child in init_children:
                    init_pos = self._walk_node(child, add_node, add_edge,
                                                ctx_stack, file_path, 0)
                    if init_pos is not None:
                        self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)
                    break

            last_pos = d_pos
        return last_pos

    # ===================================================================
    # Branch: if statement
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Extract condition
        cond_node = None
        for child in node.children:
            if child.type not in ("if", "(", ")", "block", "else_clause"):
                cond_node = child
                break

        cond_text = self._text(cond_node).strip() if cond_node else "<if>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": cond_text,
                "raw_type": "if_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Walk if-body
        if_body = self._find_child_by_type(node, "block")
        if if_body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(if_body, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        # Walk else clause
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause:
            # Check for else-if
            inner_if = self._find_child_by_type(else_clause, "if_statement")
            if inner_if:
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                self._walk_if(inner_if, add_node, add_edge, ctx_stack,
                               file_path, 0)
                ctx_stack.pop()
            else:
                # else block
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "else",
                    "lineno": self._lineno(else_clause),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "raw_type": "else_clause",
                    },
                })
                add_edge({
                    "label": EdgeLabel.AST.value,
                    "source": pos,
                    "target": else_pos,
                    "attrs": {"role": AstRole.IFFALSE.value},
                })
                else_block = self._find_child_by_type(else_clause, "block")
                if else_block:
                    ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                    self._walk_block(else_block, add_node, add_edge,
                                     ctx_stack, file_path, 0)
                    ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: switch statement
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Extract switch expression
        switch_expr = None
        for child in node.children:
            if child.type not in ("switch", "(", ")", "{", "}"):
                switch_expr = child
                break

        expr_text = self._text(switch_expr).strip() if switch_expr else "<switch>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": expr_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": expr_text,
                "raw_type": "switch_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk switch expression
        if switch_expr is not None:
            expr_pos = self._walk_node(switch_expr, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.CONDITION.value)

        # Walk switch sections (case/default)
        sections = self._find_children_by_type(node, "switch_section")
        for s_idx, section in enumerate(sections):
            # Check for default pattern
            labels = self._find_children_by_type(section, "case_pattern_clause",
                                                    "case_expression_list")
            is_default = False
            label_text = ""
            for label in labels:
                lt = self._text(label).strip()
                if "default" in lt:
                    is_default = True
                label_text = lt

            case_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": label_text or ("<case {}>".format(s_idx)),
                "lineno": self._lineno(section),
                "language": self.language,
                "attrs": {
                    "type": BranchType.DEFAULT.value if is_default else BranchType.CASE.value,
                    "condition": label_text,
                    "raw_type": "switch_section",
                },
            })
            add_edge({
                "label": EdgeLabel.AST.value,
                "source": pos,
                "target": case_pos,
                "attrs": {"role": AstRole.IFTRUE.value, "index": s_idx},
            })

            # Walk section statements
            ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
            self._walk_children(section, add_node, add_edge,
                                ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: for statement
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # C# for: for (init; cond; update) { body }
        # Extract condition
        cond_text = "<for>"
        # Look for the for body block and condition
        children_list = node.children
        cond_node = None
        state = "init"
        for child in children_list:
            if child.type == "for":
                continue
            if child.type == ";":
                state = "cond" if state == "init" else "update"
                continue
            if child.type == "block":
                continue
            if state == "cond":
                cond_node = child
                break

        if cond_node:
            cond_text = self._text(cond_node).strip()

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": cond_text,
                "raw_type": "for_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Walk body
        body = self._find_child_by_type(node, "block")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(body, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: foreach statement
    # ===================================================================

    def _walk_foreach(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # foreach (var item in collection) { body }
        iter_text = "<foreach>"
        iter_node = None
        for child in node.children:
            if child.type in ("foreach", "(", ")", "block", "var",
                              "identifier", "type", "in"):
                continue
            if child.type not in _SKIP_TYPES:
                iter_node = child
                break

        if iter_node:
            iter_text = self._text(iter_node).strip()

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": iter_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": iter_text,
                "raw_type": "foreach_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk iterable
        if iter_node is not None:
            iter_pos = self._walk_node(iter_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if iter_pos is not None:
                self._ast_edge(add_edge, pos, iter_pos, AstRole.CONDITION.value)

        # Walk body
        body = self._find_child_by_type(node, "block")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(body, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: while statement
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        cond_node = None
        for child in node.children:
            if child.type in ("while", "(", ")", "block"):
                continue
            cond_node = child
            break

        cond_text = self._text(cond_node).strip() if cond_node else "<while>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": cond_text,
                "raw_type": "while_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        body = self._find_child_by_type(node, "block")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(body, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: do statement
    # ===================================================================

    def _walk_do(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        cond_node = None
        for child in node.children:
            if child.type in ("do", "while", "(", ")", "block", ";"):
                continue
            cond_node = child
            break

        cond_text = self._text(cond_node).strip() if cond_node else "<do>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": cond_text,
                "raw_type": "do_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "block")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(body, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        return pos

    # ===================================================================
    # Branch: try statement
    # ===================================================================

    def _walk_try(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<try>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TRY.value,
                "raw_type": "try_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk try block
        try_block = self._find_child_by_type(node, "block")
        if try_block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(try_block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        # Walk catch clauses
        catches = self._find_children_by_type(node, "catch_clause")
        for c_idx, catch in enumerate(catches):
            catch_type = ""
            catch_decl = self._find_child_by_type(catch, "catch_declaration")
            if catch_decl:
                catch_type = self._text(catch_decl).strip()

            catch_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": catch_type or "<catch>",
                "lineno": self._lineno(catch),
                "language": self.language,
                "attrs": {
                    "type": BranchType.CATCH.value,
                    "condition": catch_type,
                    "raw_type": "catch_clause",
                },
            })
            add_edge({
                "label": EdgeLabel.AST.value,
                "source": pos,
                "target": catch_pos,
                "attrs": {"role": AstRole.IFFALSE.value, "index": c_idx},
            })

            catch_block = self._find_child_by_type(catch, "block")
            if catch_block:
                ctx_stack.append((catch_pos, NodeLabel.BRANCH.value))
                self._walk_block(catch_block, add_node, add_edge,
                                 ctx_stack, file_path, 0)
                ctx_stack.pop()

        # Walk finally clause
        finally_clause = self._find_child_by_type(node, "finally_clause")
        if finally_clause:
            finally_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": "<finally>",
                "lineno": self._lineno(finally_clause),
                "language": self.language,
                "attrs": {
                    "type": BranchType.FINALLY.value,
                    "raw_type": "finally_clause",
                },
            })
            add_edge({
                "label": EdgeLabel.AST.value,
                "source": pos,
                "target": finally_pos,
                "attrs": {"role": AstRole.IFFALSE.value},
            })

            finally_block = self._find_child_by_type(finally_clause, "block")
            if finally_block:
                ctx_stack.append((finally_pos, NodeLabel.BRANCH.value))
                self._walk_block(finally_block, add_node, add_edge,
                                 ctx_stack, file_path, 0)
                ctx_stack.pop()

        return pos

    # ===================================================================
    # Return statement
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

        # Walk return value
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            ret_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if ret_pos is not None:
                self._ast_edge(add_edge, pos, ret_pos, AstRole.VALUE.value)
            break

        return pos

    # ===================================================================
    # Throw
    # ===================================================================

    def _walk_throw(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text if len(text) < 80 else "throw",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.THROW.value,
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
                self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)
            break

        return pos

    # ===================================================================
    # Await
    # ===================================================================

    def _walk_await(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "await",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AWAIT.value,
                "raw_type": "await_expression",
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
    # Yield
    # ===================================================================

    def _walk_yield(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text if len(text) < 80 else "yield",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "raw_type": "yield_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)
            break

        return pos

    # ===================================================================
    # Break / Continue / Goto
    # ===================================================================

    def _walk_control(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        ctrl_map = {
            "break_statement": ("break", OperatorType.BREAK),
            "continue_statement": ("continue", OperatorType.CONTINUE),
            "goto_statement": ("goto", OperatorType.GOTO),
        }
        name, op_type = ctrl_map.get(node.type, ("control", OperatorType.BREAK))

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk target (for goto, it might have an identifier target)
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "identifier":
                id_pos = self._walk_node(child, add_node, add_edge,
                                           ctx_stack, file_path, 0)
                if id_pos is not None:
                    self._ast_edge(add_edge, pos, id_pos, AstRole.VALUE.value)
                break

        return pos

    # ===================================================================
    # Invocation expression (call)
    # ===================================================================

    def _walk_invocation(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # callee can be: identifier, member_access_expression, generic_name
        callee = self._find_child_by_type(node, "identifier",
                                            "member_access_expression",
                                            "generic_name",
                                            "qualified_name",
                                            "conditional_expression")
        callee_name = self._text(callee).strip() if callee else "<call>"

        # Check if callee is a member_access_expression (method call)
        is_method_call = callee is not None and callee.type == "member_access_expression"

        op_type = OperatorType.METHOD_CALL if is_method_call else OperatorType.CALL

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
                "raw_type": "invocation_expression",
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
        arg_list = self._find_child_by_type(node, "argument_list")
        if arg_list:
            for idx, arg in enumerate(arg_list.children):
                if arg.type in _SKIP_TYPES:
                    continue
                arg_pos = self._walk_node(arg, add_node, add_edge,
                                            ctx_stack, file_path, 0)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"index": idx})

        # NOTE: use edge generation moved to UseEdgeBuilder (phase 2).

        return pos

    # ===================================================================
    # Object creation expression (new)
    # ===================================================================

    def _walk_object_creation(self, node, add_node, add_edge,
                               ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Extract type name
        type_node = self._find_child_by_type(node, "identifier",
                                               "generic_name", "qualified_name",
                                               "member_access_expression")
        type_name = self._text(type_node).strip() if type_node else "<new>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": type_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.NEW.value,
                "raw_type": "object_creation_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk type node
        if type_node is not None:
            type_pos = self._walk_node(type_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if type_pos is not None:
                self._ast_edge(add_edge, pos, type_pos, AstRole.CALLEE.value)

        # Walk arguments
        arg_list = self._find_child_by_type(node, "argument_list")
        if arg_list:
            for idx, arg in enumerate(arg_list.children):
                if arg.type in _SKIP_TYPES:
                    continue
                arg_pos = self._walk_node(arg, add_node, add_edge,
                                            ctx_stack, file_path, 0)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"index": idx})

        return pos

    # ===================================================================
    # Assignment expression
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        left_node = None
        right_node = None
        op_node = None
        found_op = False
        for child in node.children:
            if child.type in ("=", "+=", "-=", "*=", "/=", "%=",
                              "&=", "|=", "^=", "<<=", ">>="):
                op_node = child
                found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        # Determine if augmented assignment
        is_aug = op_node is not None and op_node.type != "="
        op_type = OperatorType.AUG_ASSIGN if is_aug else OperatorType.ASSIGN
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text if len(text) < 80 else "assign",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
                "raw_type": "assignment_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

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

    # ===================================================================
    # Binary expression
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Find operator node
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in node.children:
            if child.type in ("==", "!=", ">=", "<=", ">", "<",
                              "&&", "||", "??", "?." , "+", "-", "*", "/",
                              "%", "&", "|", "^", "<<", ">>"):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

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

        # Walk left and right
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
            if child.type in ("-", "!", "~", "++", "--", "*"):
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
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == op_text:
                continue
            op_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if op_pos is not None:
                self._ast_edge(add_edge, pos, op_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Cast expression
    # ===================================================================

    def _walk_cast(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "cast",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.TYPE_CAST.value,
                "raw_type": "cast_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Element access expression (obj[key])
    # ===================================================================

    def _walk_element_access(self, node, add_node, add_edge,
                             ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        # Build name: for member[key] combine member_name + "[key]"
        name = text
        for child in node.children:
            if child.type == "member_access_expression":
                member_name = ""
                for mc in child.children:
                    if mc.type in ("identifier", "generic_name"):
                        member_name = self._text(mc)
                if member_name and "[" in text:
                    idx = text.index("[")
                    name = member_name + text[idx:]
                break

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.PROPERTY.value,
                "raw_type": "element_access_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Member access expression (a.b)
    # ===================================================================

    def _walk_member_access(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        # Extract the member name (right side)
        member_name = ""
        for child in node.children:
            if child.type in ("identifier", "generic_name"):
                member_name = self._text(child)
            elif child.type == ".":
                continue

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": member_name or text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.PROPERTY.value,
                "raw_type": "member_access_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk object (left side, skip the member identifier)
        first_obj = True
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if first_obj and child.type in ("identifier", "generic_name"):
                # This might be the member name (right side), skip it
                # But actually for member_access, the first child before '.' is the object
                # and after '.' is the member. Let me reconsider.
                # In C# tree-sitter: member_access_expression has children like
                # expression . identifier_name or expression . generic_name
                # The first non-punctuation child is usually the object if it comes before '.'
                pass
            first_obj = False
            if child.type == ".":
                continue
            if child.type in ("identifier", "generic_name"):
                continue
            obj_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Conditional expression (ternary)
    # ===================================================================

    def _walk_conditional(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<ternary>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TERNARY.value,
                "raw_type": "conditional_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition, true branch, false branch
        found_question = False
        found_colon = False
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == "?":
                found_question = True
                continue
            if child.type == ":":
                found_colon = True
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if child_pos is not None:
                if not found_question:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.CONDITION.value)
                elif not found_colon:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.IFTRUE.value)
                else:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.IFFALSE.value)

        return pos

    # ===================================================================
    # Qualified name (namespace.member)
    # ===================================================================

    def _walk_qualified_name(self, node, add_node, add_edge,
                              ctx_stack, file_path, depth) -> int:
        text = self._text(node)
        lineno = self._lineno(node)

        # If contains dots, treat as static reference
        if "." in text:
            pos = add_node({
                "label": NodeLabel.OPERATOR.value,
                "name": text,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": OperatorType.STATIC_CALL.value,
                    "raw_type": "qualified_name",
                },
            })
            self._own_edge(add_edge, ctx_stack, pos, depth)
            return pos

        # Simple: treat as identifier
        return self._emit_identifier(add_node, text, lineno,
                                        IdentifierType.STATIC)

    # ===================================================================
    # Block (walk children)
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

        if ntype in ("integer_literal", "real_literal"):
            return self._emit_const(add_node, text, lineno, ConstType.NUMBER)
        if ntype in ("string_literal", "character_literal"):
            return self._emit_const(add_node, text, lineno, ConstType.STRING)
        return self._emit_const(add_node, text, lineno, ConstType.CONSTANT)

    # ===================================================================
    # Identifier
    # ===================================================================

    def _walk_identifier(self, node, add_node, file_path) -> int:
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
