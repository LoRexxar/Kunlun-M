"""Rust AST Normalizer — maps tree-sitter Rust AST to UnifiedNode / UnifiedEdge.

Converts Rust source parsed by ``tree-sitter-rust`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter node model:
  - ``node.type`` → str (e.g. ``"function_item"``)
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
# tree-sitter Rust node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||",
    "+", "-", "*", "/", "%", "=", "!", "~",
    "->", "::", "&", "^", "|", "#", "..", "...",
    "@", "$",
    "<", ">",
    "if", "else", "for", "in", "while", "loop", "match",
    "let", "mut", "ref", "fn", "pub", "crate", "super",
    "struct", "enum", "trait", "impl", "use", "mod",
    "return", "break", "continue", "where", "as", "type",
    "unsafe", "async", "await", "move", "dyn", "static",
    "const", "true", "false",
})

_LITERAL_TYPES = frozenset({
    "integer_literal", "float_literal",
    "string_literal", "char_literal",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier", "type_identifier", "field_identifier",
})

# Macro calls that look like function calls (treated as OPERATOR call)
_MACRO_CALL_PATTERNS = frozenset({
    "println", "eprintln", "print", "eprint",
    "format", "vec", "dbg", "todo", "unimplemented",
    "panic", "assert", "assert_eq", "assert_ne",
    "log", "info", "warn", "error", "debug", "trace",
    "cfg", "cfg_attr", "test", "bench", "should_panic",
    "derive", "derive_debug",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter Rust AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_rust as tsrust

        lang = Language(tsrust.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.rs",
            source_content=source,
        )
    """

    language = "rust"

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

        # ---- Attribute (annotation) -----------------------------------
        if ntype == "attribute_item":
            return self._walk_attribute(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Use declaration (import) ----------------------------------
        if ntype == "use_declaration":
            return self._walk_use(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Struct ----------------------------------------------------
        if ntype == "struct_item":
            return self._walk_struct(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Enum ------------------------------------------------------
        if ntype == "enum_item":
            return self._walk_enum(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Trait (interface) -----------------------------------------
        if ntype == "trait_item":
            return self._walk_trait(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Impl (container, walk children) -----------------------------
        if ntype == "impl_item":
            return self._walk_impl(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Function -------------------------------------------------
        if ntype == "function_item":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Closure (lambda) ------------------------------------------
        if ntype == "closure_expression":
            return self._walk_closure(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Branch: if ------------------------------------------------
        if ntype == "if_expression":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                 file_path, depth)

        # ---- Branch: match ---------------------------------------------
        if ntype == "match_expression":
            return self._walk_match(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Branch: for -----------------------------------------------
        if ntype == "for_expression":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: while ---------------------------------------------
        if ntype == "while_expression":
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Branch: loop (infinite loop) -------------------------------
        if ntype == "loop_expression":
            return self._walk_loop(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Return ---------------------------------------------------
        if ntype == "return_expression":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Break / Continue ------------------------------------------
        if ntype in ("break_expression", "continue_expression"):
            return self._walk_control(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Let declaration -------------------------------------------
        if ntype == "let_declaration":
            return self._walk_let(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Expression statement --------------------------------------
        if ntype == "expression_statement":
            inner = self._find_child_by_type(
                node, "call_expression", "method_call_expression",
                "macro_invocation", "assignment_expression",
                "binary_expression", "unary_expression",
                "return_expression", "break_expression", "continue_expression",
                "for_expression", "while_expression", "loop_expression",
                "if_expression", "match_expression", "let_declaration",
                "unsafe_block", "await_expression",
            )
            if inner is not None:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Call expression -------------------------------------------
        if ntype == "call_expression":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Method call expression -------------------------------------
        if ntype == "method_call_expression":
            return self._walk_method_call(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Macro invocation -----------------------------------------
        if ntype == "macro_invocation":
            return self._walk_macro(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Assignment expression -------------------------------------
        if ntype == "assignment_expression":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Binary / Unary expression --------------------------------
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        if ntype == "unary_expression":
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Compound assignment (+=, -=, etc.) ----------------------
        if ntype == "compound_assignment_expression":
            return self._walk_compound_assignment(node, add_node, add_edge,
                                                   ctx_stack, file_path, depth)

        # ---- Ternary-like (Rust has no ternary, but conditionals) -----
        # (no-op)

        # ---- Field expression (a.b) -----------------------------------
        if ntype == "field_expression":
            return self._walk_field_expr(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Index expression (a[i]) ----------------------------------
        if ntype == "index_expression":
            return self._walk_index(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Type cast expression (as) --------------------------------
        if ntype == "type_cast_expression":
            return self._walk_cast(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Tuple expression ------------------------------------------
        if ntype == "tuple_expression":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Struct expression ------------------------------------------
        if ntype == "struct_expression":
            return self._walk_struct_expr(node, add_node, add_edge, ctx_stack,
                                           file_path, depth)

        # ---- Array expression ------------------------------------------
        if ntype == "array_expression":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Await expression ------------------------------------------
        if ntype == "await_expression":
            return self._walk_await(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Try expression (?, .await) --------------------------------
        if ntype == "try_expression":
            return self._walk_try(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Block (statement list) ------------------------------------
        if ntype == "block":
            return self._walk_block(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Unsafe block ----------------------------------------------
        if ntype == "unsafe_block":
            return self._walk_block(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Literals -------------------------------------------------
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # ---- True / False (boolean) -----------------------------------
        if ntype in ("true", "false"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.BOOLEAN)

        # ---- Identifiers ----------------------------------------------
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, file_path)

        # ---- Scoped identifier (path like std::io) --------------------
        if ntype == "scoped_identifier":
            return self._walk_scoped_identifier(node, add_node, add_edge,
                                                  ctx_stack, file_path, depth)

        # ---- self ------------------------------------------------------
        if ntype == "self":
            return self._emit_identifier(add_node, "self", self._lineno(node),
                                         IdentifierType.THIS)

        # ---- Parenthesized expression ----------------------------------
        if ntype == "parenthesized_expression":
            inner = self._find_child_by_type(node,
                "binary_expression", "unary_expression", "call_expression",
                "method_call_expression", "identifier", "scoped_identifier",
                "field_expression", "if_expression", "match_expression",
                "macro_invocation", "assignment_expression",
                "type_cast_expression")
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Fallback -------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Attribute (Annotation)
    # ===================================================================

    def _walk_attribute(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        # Extract the attribute name (e.g., "derive" from #[derive(Debug)])
        attr_name = ""
        attr_node = self._find_child_by_type(node, "attribute")
        if attr_node:
            # attribute > [ + identifier + ( ... )
            for c in attr_node.children:
                if c.type == "identifier":
                    attr_name = self._text(c)
                    break
            if not attr_name:
                attr_name = self._text(attr_node)

        pos = add_node({
            "label": NodeLabel.ANNOTATION.value,
            "name": attr_name or "<annotation>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "raw_type": "attribute_item",
                "text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Use declaration (Import)
    # ===================================================================

    def _walk_use(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # use path::{module} or use path::item
        scoped = self._find_child_by_type(node, "scoped_identifier",
                                            "use_list", "scoped_use_list")
        path = self._text(scoped).strip(";").strip() if scoped else ""

        import_name = path or "<use>"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": import_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.USE.value,
                "source": path,
                "raw_type": "UseDeclaration",
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
                "attrs": {"type": FrgType.USE.value},
            })

        return pos

    # ===================================================================
    # Struct (Class - struct)
    # ===================================================================

    def _walk_struct(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        type_id = self._find_child_by_type(node, "type_identifier")
        name = self._text(type_id) if type_id else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.STRUCT.value,
                "raw_type": "struct_item",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk fields
        field_list = self._find_child_by_type(node, "field_declaration_list")
        if field_list:
            fields = self._find_children_by_type(field_list, "field_declaration")
            for f_idx, field in enumerate(fields):
                fname = self._find_child_by_type(field, "field_identifier")
                if fname is not None:
                    f_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": self._text(fname),
                        "lineno": self._lineno(field),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.FIELD.value,
                            "raw_type": "FieldDeclaration",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.OWN.value,
                        "source": pos,
                        "target": f_pos,
                        "attrs": {"index": f_idx},
                    })

        return pos

    # ===================================================================
    # Enum (Class - enum)
    # ===================================================================

    def _walk_enum(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        type_id = self._find_child_by_type(node, "type_identifier")
        name = self._text(type_id) if type_id else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.ENUM.value,
                "raw_type": "enum_item",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk enum variants
        variant_list = self._find_child_by_type(node, "enum_variant_list")
        if variant_list:
            variants = self._find_children_by_type(variant_list, "enum_variant")
            for v_idx, variant in enumerate(variants):
                vname = self._find_child_by_type(variant, "identifier")
                if vname is not None:
                    v_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": self._text(vname),
                        "lineno": self._lineno(variant),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.FIELD.value,
                            "raw_type": "EnumVariant",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.OWN.value,
                        "source": pos,
                        "target": v_pos,
                        "attrs": {"index": v_idx},
                    })

        return pos

    # ===================================================================
    # Trait (Class - interface)
    # ===================================================================

    def _walk_trait(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        type_id = self._find_child_by_type(node, "type_identifier")
        name = self._text(type_id) if type_id else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.INTERFACE.value,
                "raw_type": "trait_item",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk trait method signatures
        decl_list = self._find_child_by_type(node, "declaration_list")
        if decl_list:
            # Trait body contains trait items (function signatures / default impls)
            for child in decl_list.children:
                if child.type == "function_item":
                    self._walk_function(child, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        return pos

    # ===================================================================
    # Impl (container — walk children, set context)
    # ===================================================================

    def _walk_impl(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        # impl is a container, not a node itself
        type_id = self._find_child_by_type(node, "type_identifier")
        impl_name = self._text(type_id) if type_id else "<impl>"

        # Functions are inside declaration_list in tree-sitter Rust
        decl_list = self._find_child_by_type(node, "declaration_list")
        if decl_list:
            for idx, child in enumerate(decl_list.children):
                if child.type == "function_item":
                    self._walk_function(child, add_node, add_edge, ctx_stack,
                                        file_path, idx, in_impl=True,
                                        impl_type=impl_name)
        else:
            # Fallback: check direct children
            for idx, child in enumerate(node.children):
                if child.type == "function_item":
                    self._walk_function(child, add_node, add_edge, ctx_stack,
                                        file_path, idx, in_impl=True,
                                        impl_type=impl_name)

        return None

    # ===================================================================
    # Function / Method / Constructor
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth,
                       in_impl=False, impl_type="") -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"

        # Determine function type
        has_self = self._find_child_by_type(node, "self_parameter") is not None
        if name == "new" or name == "default":
            func_type = FunctionType.CONSTRUCTOR.value
        elif has_self or in_impl:
            func_type = FunctionType.METHOD.value
        else:
            func_type = FunctionType.FUNCTION.value

        # Parameters
        param_list = self._find_child_by_type(node, "parameters")
        params = self._find_children_by_type(param_list, "parameter") if param_list else []

        param_strs = []
        for p in params:
            pname_node = self._find_child_by_type(p, "parameter")
            # In tree-sitter-rust, parameter contains pattern, type
            # pattern can be: identifier, ref, mut, tuple_pattern, etc.
            pname = ""
            ptype_node = self._find_child_by_type(p, "type_identifier")
            ptype = self._text(ptype_node) if ptype_node else ""
            if not ptype:
                # Try to get type from 'abstract_type' or other type nodes
                type_node = self._find_child_by_type(
                    p, "abstract_type", "generic_type", "reference_type",
                    "slice_type", "array_type", "tuple_type", "scoped_type_identifier",
                    "pointer_type", "unit_type", "never_type", "dynamic_type",
                    "closure_type")
                if type_node:
                    ptype = self._text(type_node)

            for c in p.children:
                if c.type == "identifier":
                    pname = self._text(c)
                    break
            if pname:
                param_strs.append(f"{ptype} {pname}" if ptype else pname)

        # Return type
        ret_type = ""
        ret_type_node = self._find_child_by_type(node, "return_type")
        if ret_type_node:
            ret_type = self._text(ret_type_node)

        # Build fullname
        fullname = name
        if in_impl and impl_type:
            fullname = f"{impl_type}::{name}"

        signature = f"{ret_type} {name}({', '.join(param_strs)})" if ret_type else f"{name}({', '.join(param_strs)})"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": fullname,
                "type": func_type,
                "signature": signature,
                "file_path": file_path,
                "raw_type": "function_item",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

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
        block = self._find_child_by_type(node, "block")
        if block is not None:
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        if param_node is None:
            return None

        # Extract name from pattern (the first identifier child)
        name = ""
        for c in param_node.children:
            if c.type == "identifier":
                name = self._text(c)
                break
        if not name:
            return None

        lineno = self._lineno(param_node)

        # Type
        ptype = ""
        type_node = self._find_child_by_type(
            param_node, "type_identifier", "abstract_type", "generic_type",
            "reference_type", "slice_type", "array_type", "tuple_type",
            "scoped_type_identifier", "pointer_type", "unit_type",
            "never_type", "dynamic_type", "closure_type")
        if type_node:
            ptype = self._text(type_node)

        return add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "rust_type": ptype,
                "file_path": file_path,
            },
        })

    # ===================================================================
    # Closure (Lambda)
    # ===================================================================

    def _walk_closure(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": "<lambda>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": "<lambda>",
                "type": FunctionType.LAMBDA.value,
                "raw_type": "closure_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk closure parameters
        params_node = self._find_child_by_type(node, "closure_parameters")
        if params_node:
            for c in params_node.children:
                if c.type == "parameter":
                    p_pos = self._walk_parameter(c, add_node, file_path)
                    if p_pos is not None:
                        add_edge({
                            "label": EdgeLabel.OWN.value,
                            "source": pos,
                            "target": p_pos,
                            "attrs": {"index": 0},
                        })

        # Walk body
        body_node = self._find_child_by_type(node, "block")
        if body_node:
            ctx_stack.append((pos, NodeLabel.FUNCTION.value))
            self._walk_block(body_node, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()
        else:
            # Expression body
            for child in node.children:
                if child.type in _SKIP_TYPES:
                    continue
                if child.type not in ("closure_parameters", "return_type"):
                    ctx_stack.append((pos, NodeLabel.FUNCTION.value))
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, 0)
                    ctx_stack.pop()
                    break

        return pos

    # ===================================================================
    # Branch: If Expression
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Rust if: condition (block) (else_clause)?
        # Find condition: first non-keyword, non-block child
        cond_node = None
        cond_text = "<if>"
        for child in node.children:
            if child.type in ("if", "let", "{", "}", "block", "else_clause"):
                continue
            cond_node = child
            break

        if cond_node:
            cond_text = self._text(cond_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": cond_text,
                "raw_type": "IfExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Then block
        ctx_stack.append((pos, NodeLabel.BRANCH.value))

        # The blocks are direct children in Rust if-expression
        # Find first block (then body)
        blocks = self._find_children_by_type(node, "block")
        if blocks:
            then_block = blocks[0]
            self._walk_block(then_block, add_node, add_edge, ctx_stack,
                             file_path, 0)

        # Else clause
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause is not None:
            # Check for else if
            elif_if = self._find_child_by_type(else_clause, "if_expression")
            if elif_if is not None:
                self._walk_if(elif_if, add_node, add_edge, ctx_stack,
                              file_path, depth + 1)
            else:
                else_block = self._find_child_by_type(else_clause, "block")
                if else_block is not None:
                    else_pos = add_node({
                        "label": NodeLabel.BRANCH.value,
                        "name": "<else>",
                        "lineno": self._lineno(else_clause),
                        "language": self.language,
                        "attrs": {
                            "type": BranchType.ELSE.value,
                            "condition": "",
                            "raw_type": "Else",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.AST.value,
                        "source": pos,
                        "target": else_pos,
                        "attrs": {"role": AstRole.IFFALSE.value},
                    })
                    ctx_stack.pop()
                    ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                    self._walk_block(else_block, add_node, add_edge,
                                     ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: Match Expression
    # ===================================================================

    def _walk_match(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Match value (scrutinee)
        value_node = None
        value_text = "<match>"
        for child in node.children:
            if child.type in ("match", "{", "}", "match_arm"):
                continue
            if child.type == "match_block":
                continue
            value_node = child
            break

        if value_node:
            value_text = self._text(value_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": value_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.MATCH.value,
                "condition": value_text,
                "raw_type": "MatchExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk value
        if value_node is not None:
            val_pos = self._walk_node(value_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.CONDITION.value)

        # Walk match arms
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        match_block = self._find_child_by_type(node, "match_block")
        if match_block:
            arms = self._find_children_by_type(match_block, "match_arm")
            for a_idx, arm in enumerate(arms):
                # Check if pattern is _ (wildcard/default)
                pattern_node = self._find_child_by_type(arm, "match_pattern",
                    "tuple_pattern", "identifier", "constant_identifier",
                    "scoped_identifier", "struct_pattern", "tuple_struct_pattern",
                    "ref_pattern", "mut_pattern", "wildcard_pattern")
                is_default = False
                if pattern_node and self._text(pattern_node).strip() == "_":
                    is_default = True
                # Also check for a direct wildcard_pattern child
                wildcard = self._find_child_by_type(arm, "wildcard_pattern")
                if wildcard:
                    is_default = True

                pattern_text = self._text(pattern_node) if pattern_node else "_"
                arm_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": pattern_text.strip(),
                    "lineno": self._lineno(arm),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.DEFAULT.value if is_default else BranchType.CASE.value,
                        "condition": pattern_text.strip(),
                        "raw_type": "MatchArm",
                    },
                })
                add_edge({
                    "label": EdgeLabel.AST.value,
                    "source": pos,
                    "target": arm_pos,
                    "attrs": {"role": AstRole.IFTRUE.value, "index": a_idx},
                })

                # Walk arm body
                arm_body = self._find_child_by_type(arm, "expression", "block")
                if arm_body:
                    ctx_stack.append((arm_pos, NodeLabel.BRANCH.value))
                    if arm_body.type == "block":
                        self._walk_block(arm_body, add_node, add_edge,
                                         ctx_stack, file_path, 0)
                    else:
                        self._walk_node(arm_body, add_node, add_edge,
                                        ctx_stack, file_path, 0)
                    ctx_stack.pop()

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: For Expression
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Rust for: for pattern in iterable { body }
        pattern = self._find_child_by_type(node, "identifier", "tuple_pattern",
                                            "ref_pattern", "mut_pattern",
                                            "_")
        iterable = None
        iter_text = "<for>"
        for child in node.children:
            if child.type == "in":
                continue
            if child.type == "block":
                continue
            if child.type == "for":
                continue
            if child.type in ("identifier", "ref_pattern", "mut_pattern",
                              "tuple_pattern"):
                continue
            iterable = child
            break

        if iterable:
            iter_text = self._text(iterable)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": iter_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": iter_text,
                "raw_type": "ForExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk iterable
        if iterable is not None:
            iter_pos = self._walk_node(iterable, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if iter_pos is not None:
                self._ast_edge(add_edge, pos, iter_pos, AstRole.CONDITION.value)

        # Body
        block = self._find_child_by_type(node, "block")
        if block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: While Expression
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        cond_node = None
        cond_text = "<while>"
        for child in node.children:
            if child.type in ("while", "block"):
                continue
            cond_node = child
            break

        if cond_node:
            cond_text = self._text(cond_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": cond_text,
                "raw_type": "WhileExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        block = self._find_child_by_type(node, "block")
        if block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: Loop Expression (infinite loop → while)
    # ===================================================================

    def _walk_loop(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<loop>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": "true",
                "raw_type": "LoopExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        block = self._find_child_by_type(node, "block")
        if block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
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
                "raw_type": "return_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk return value expression
        for child in node.children:
            if child.type == "return":
                continue
            ret_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if ret_pos is not None:
                self._ast_edge(add_edge, pos, ret_pos, AstRole.VALUE.value)
            break

        return pos

    # ===================================================================
    # Break / Continue
    # ===================================================================

    def _walk_control(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        ctrl_type = OperatorType.BREAK.value if node.type == "break_expression" else OperatorType.CONTINUE.value
        name = "break" if node.type == "break_expression" else "continue"

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

        # Break/continue may have a label: break 'label
        for child in node.children:
            if child.type in ("break", "continue"):
                continue
            lbl_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if lbl_pos is not None:
                self._ast_edge(add_edge, pos, lbl_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Let declaration
    # ===================================================================

    def _walk_let(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Extract variable name from pattern
        name = ""
        for child in node.children:
            if child.type == "identifier":
                name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name or "<let>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "raw_type": "let_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk initializer expression — skip variable name identifier
        found_name = False
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type in ("let", "mut", "ref", ";", ":", "=", "_"):
                continue
            if child.type == "type_identifier" or "type" in child.type.lower():
                if child.type not in ("identifier", "scoped_identifier"):
                    continue
            # Skip the variable name identifier (first identifier is LHS)
            if not found_name and child.type == "identifier":
                found_name = True
                continue
            init_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if init_pos is not None:
                # Create assignment operator node for DFG builder
                eq_pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": "=",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "let_declaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + 1)
                self._ast_edge(add_edge, eq_pos, pos, AstRole.LHS.value)
                self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)
            break

        return pos

    # ===================================================================
    # Call expression
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # callee + arguments
        callee = self._find_child_by_type(node, "identifier", "scoped_identifier",
                                           "field_expression", "parenthesized_expression")
        callee_name = self._text(callee) if callee else "<call>"

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
        func_name = callee_name.rsplit("::", 1)[-1] if callee_name else ""
        func_fullname = callee_name
        cg_call_type = CgCallType.DIRECT
        if func_name and isinstance(func_name, str) and func_name != "<call>":
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
    # Method call expression
    # ===================================================================

    def _walk_method_call(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # In tree-sitter-rust: method_call_expression
        # Children: object, ::, identifier, (, arguments, )
        # The object can be a field_expression, identifier, etc.
        method_name_node = self._find_child_by_type(node, "identifier")
        method_name = self._text(method_name_node) if method_name_node else "<method>"

        # Get the object
        obj_node = None
        for child in node.children:
            if child.type in ("identifier", "::", "(", ")", ","):
                continue
            if "argument" in child.type:
                continue
            if child.type == "identifier":
                # This is the method name, skip
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
                "raw_type": "method_call_expression",
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
    # Macro invocation (treated as call)
    # ===================================================================

    # Known format-string macros: first arg is a format string literal,
    # subsequent args are interpolated values.
    _FORMAT_MACROS = frozenset({
        "format", "print", "println", "eprint", "eprintln",
        "write", "writeln", "format_args", "format_args_nl",
        "dbg", "println", "log", "info", "warn", "error", "debug", "trace",
    })

    def _walk_macro(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # macro_invocation: identifier ! token_tree
        # e.g., println!("hello"), format!("{}", x), vec![1,2,3]
        macro_name = ""
        for child in node.children:
            if child.type == "identifier" and not macro_name:
                macro_name = self._text(child)
                break
            if child.type == "scoped_identifier":
                # e.g., std::println!
                macro_name = self._text(child)
                break

        if not macro_name:
            macro_name = "<macro>"

        # Strip trailing "!" if present (tree-sitter may or may not include it)
        macro_name_clean = macro_name.rstrip("!")

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": macro_name_clean + "!",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CALL.value,
                "raw_type": "macro_invocation",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk macro body (token_tree) for any expressions
        token_tree = self._find_child_by_type(node, "token_tree")
        if token_tree:
            # For format-string macros, create DFG edges from arguments to
            # the format string const node (mirrors Ruby interpolation DFG).
            # e.g., format!("Hello {}", name) → dfg(name → format_string)
            if macro_name_clean in self._FORMAT_MACROS:
                self._walk_format_macro_args(
                    token_tree, pos, add_node, add_edge,
                    ctx_stack, file_path, depth)
            else:
                for child in token_tree.children:
                    if child.type in _SKIP_TYPES:
                        continue
                    self._walk_node(child, add_node, add_edge,
                                    ctx_stack, file_path, 0)

        return pos

    def _walk_format_macro_args(self, token_tree, macro_pos, add_node, add_edge,
                                ctx_stack, file_path, depth):
        """Walk format macro token_tree, creating DFG edges from args to
        the format string const.

        For format!("Hello {}", name):
          1. Walk string_literal → emits CONST node (fmt_str_pos)
          2. Walk subsequent expression nodes (identifier, call, etc.)
          3. DFG edge: arg_expr → fmt_str_pos  (data flows into string)
          4. DFG edge: arg_expr → macro_pos     (data flows to macro result)
          5. own edge for each arg so same-variable linking works
        """
        children = token_tree.children
        fmt_str_pos = None
        seen_fmt_str = False

        for child in children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type == ",":
                continue

            if not seen_fmt_str:
                # First non-punctuation, non-comma child should be the
                # format string literal (or first arg for write! which has
                # a destination before the format string).
                seen_fmt_str = True
                fmt_str_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
            else:
                # Subsequent children are format arguments
                arg_pos = self._walk_node(child, add_node, add_edge,
                                          ctx_stack, file_path, 0)
                if arg_pos is not None:
                    # DFG: argument → format string (taint flows into string)
                    if fmt_str_pos is not None:
                        add_edge({
                            "label": "dfg",
                            "source": arg_pos,
                            "target": fmt_str_pos,
                        })
                    # DFG: argument → macro operator (taint flows to result)
                    add_edge({
                        "label": "dfg",
                        "source": arg_pos,
                        "target": macro_pos,
                    })
                    # own edge so same-variable linking works
                    self._own_edge(add_edge, ctx_stack, arg_pos, depth)

    # ===================================================================
    # Assignment expression
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # assignment_expression: left = right
        left_node = None
        right_node = None
        found_op = False
        for child in node.children:
            if child.type == "=":
                found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

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
    # Compound assignment (+=, -=, etc.)
    # ===================================================================

    def _walk_compound_assignment(self, node, add_node, add_edge,
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
                "raw_type": "compound_assignment_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk children
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

        op_node = None
        for child in node.children:
            if child.type in ("==", "!=", ">=", "<=", ">", "<",
                              "&&", "||", "+", "-", "*", "/", "%",
                              "&", "|", "^", "<<", ">>"):
                op_node = child
                break
            if child.type not in ("identifier", "integer_literal",
                                  "float_literal", "string_literal",
                                  "char_literal", "true", "false",
                                  "call_expression", "method_call_expression",
                                  "field_expression", "index_expression",
                                  "scoped_identifier", "parenthesized_expression",
                                  "unary_expression", "binary_expression",
                                  "if_expression", "match_expression",
                                  "block", "macro_invocation",
                                  "self", "array_expression", "tuple_expression",
                                  "struct_expression", "type_cast_expression",
                                  "reference_expression", "dereference_expression",
                                  "try_expression", "await_expression",
                                  "as_expression", "tuple_expression"):
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
            if child.type in ("-", "!", "*", "&", "~"):
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

        # Walk operand
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type in _SKIP_TYPES or child.type == op_text:
                continue
            op_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if op_pos is not None:
                self._ast_edge(add_edge, pos, op_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Field expression (a.b)
    # ===================================================================

    def _walk_field_expr(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        field_node = self._find_child_by_type(node, "field_identifier")
        field_name = self._text(field_node) if field_node else ""

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": field_name or text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.FIELD.value,
                "raw_type": "field_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk object
        for child in node.children:
            if child.type in ("field_identifier", "."):
                continue
            obj_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Index expression (a[i])
    # ===================================================================

    def _walk_index(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "[]",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "index_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk children (object + index)
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Type cast expression (as)
    # ===================================================================

    def _walk_cast(self, node, add_node, add_edge,
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
                "raw_type": "type_cast_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk children
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Struct expression (StructInit { field: value })
    # ===================================================================

    def _walk_struct_expr(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Get struct type
        type_node = self._find_child_by_type(
            node, "type_identifier", "scoped_type_identifier", "generic_type")
        type_name = self._text(type_node) if type_node else "<struct>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": type_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.NEW.value,
                "raw_type": "struct_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk children
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type in ("type_identifier", "scoped_type_identifier",
                              "generic_type"):
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Await expression
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
    # Try expression (? operator)
    # ===================================================================

    def _walk_try(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "?",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "raw_type": "try_expression",
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
    # Scoped identifier (path like std::io or Type::method)
    # ===================================================================

    def _walk_scoped_identifier(self, node, add_node, add_edge,
                                 ctx_stack, file_path, depth) -> int | None:
        text = self._text(node)
        lineno = self._lineno(node)

        # Check if it's a type path with :: (like User::new, std::io::Result)
        if "::" in text:
            # Split into parts
            parts = text.split("::")
            if len(parts) >= 2:
                # Could be a static call: Type::method()
                # Or a module path: std::io
                # Emit as static_call operator
                pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": text,
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.STATIC_CALL.value,
                        "raw_type": "scoped_identifier",
                    },
                })
                self._own_edge(add_edge, ctx_stack, pos, depth)
                return pos

        # Simple identifier-like scoped: just emit as identifier
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

        if ntype in ("integer_literal", "float_literal"):
            return self._emit_const(add_node, text, lineno, ConstType.NUMBER)
        if ntype in ("string_literal", "char_literal"):
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
