"""Kotlin AST Normalizer — maps tree-sitter Kotlin AST to UnifiedNode / UnifiedEdge.

Converts Kotlin source parsed by ``tree-sitter-kotlin`` (via ``tree_sitter.Parser``)
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
# tree-sitter Kotlin node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||",
    "+", "-", "*", "/", "%", "=", "!",
    "->", "::", ".", "..", "?:", "!!", "?",
    "@", "$",
    "if", "else", "for", "in", "while", "do", "when",
    "val", "var", "fun", "class", "object", "interface", "enum",
    "package", "as", "is", "typealias",
    "return", "break", "continue", "throw", "try", "catch", "finally",
    "super", "this", "override", "open", "abstract", "sealed",
    "private", "protected", "public", "internal",
    "data", "inner", "companion", "annotation",
    "suspend", "inline", "noinline", "crossinline", "reified",
    "tailrec", "operator", "infix",
    "const", "true", "false", "null",
    "init", "constructor",
    "modifiers", "class_modifier",
    "\"",
    # NOTE: "import" is NOT in skip — it is both a keyword leaf and a parent
    # node type in tree-sitter-kotlin.  We handle it explicitly in _walk_node
    # before the skip check so the parent ``import`` node becomes an IMPORT.
})

_LITERAL_TYPES = frozenset({
    "number_literal",
    "string_literal",
    "string_content",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter Kotlin AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_kotlin as tsk

        lang = Language(tsk.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/Main.kt",
            source_content=source,
        )
    """

    language = "kotlin"

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
                if child.type in _SKIP_TYPES or child.type == "package_header":
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

        # ---- Import (parent node) --------------------------------------
        if ntype == "import":
            # tree-sitter-kotlin uses ``import`` as both keyword leaf and
            # parent node type.  A parent ``import`` has children that are
            # ``qualified_identifier`` (or other sub-nodes).  Detect by
            # checking whether this node has children beyond the keyword.
            if node.children and len(node.children) > 1:
                return self._walk_import_direct(node, add_node, add_edge,
                                                ctx_stack, file_path, depth)
            else:
                # Leaf keyword — skip
                return None

        # ---- Import (navigation_expression with import keyword) ------
        if ntype == "navigation_expression":
            return self._walk_maybe_import(node, add_node, add_edge, ctx_stack,
                                           file_path, depth)

        # ---- Class declaration ----------------------------------------
        if ntype == "class_declaration":
            return self._walk_class(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Object declaration (singleton) ---------------------------
        if ntype == "object_declaration":
            return self._walk_object(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Interface declaration -------------------------------------
        if ntype == "interface_declaration":
            return self._walk_interface(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Enum declaration -----------------------------------------
        if ntype == "enum_declaration":
            return self._walk_enum(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Function declaration (top-level or in class) --------------
        if ntype == "function_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Secondary constructor ------------------------------------
        if ntype == "secondary_constructor":
            return self._walk_secondary_constructor(node, add_node, add_edge,
                                                     ctx_stack, file_path, depth)

        # ---- Lambda / Anonymous function ------------------------------
        if ntype in ("lambda_expression", "anonymous_function"):
            return self._walk_lambda(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- If expression --------------------------------------------
        if ntype == "if_expression":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                 file_path, depth)

        # ---- When expression ------------------------------------------
        if ntype == "when_expression":
            return self._walk_when(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- For statement --------------------------------------------
        if ntype == "for_statement":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- While / Do-While statement -------------------------------
        if ntype in ("while_statement", "do_while_statement"):
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Try expression -------------------------------------------
        if ntype == "try_expression":
            return self._walk_try(node, add_node, add_edge, ctx_stack,
                                 file_path, depth)

        # ---- Call expression ------------------------------------------
        if ntype == "call_expression":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Binary expression (includes >=, .., +, -, etc.) ----------
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Prefix expression ----------------------------------------
        if ntype == "prefix_expression":
            return self._walk_prefix(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Postfix expression ---------------------------------------
        if ntype == "postfix_expression":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Assignment ----------------------------------------------
        if ntype == "assignment":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Throw expression -----------------------------------------
        if ntype == "throw_expression":
            return self._walk_throw(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Return expression ----------------------------------------
        if ntype == "return_expression":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Break / Continue -----------------------------------------
        if ntype in ("break_expression", "continue_expression"):
            return self._walk_control(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Property declaration --------------------------------------
        if ntype == "property_declaration":
            return self._walk_property(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- this / super keywords ------------------------------------
        if ntype == "this":
            return self._emit_identifier(add_node, "this", self._lineno(node),
                                         IdentifierType.THIS)
        if ntype == "super":
            return self._emit_identifier(add_node, "super", self._lineno(node),
                                         IdentifierType.SUPER)

        # ---- Literals ------------------------------------------------
        if ntype == "number_literal":
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.NUMBER)
        if ntype == "string_literal":
            str_pos = self._emit_const(add_node, self._text(node),
                                        self._lineno(node), ConstType.STRING)
            has_interp = any(c.type == "interpolation" for c in node.children)
            if has_interp:
                for child in node.children:
                    if child.type == "interpolation":
                        self._walk_interpolation(child, add_node, add_edge,
                                                 str_pos, ctx_stack,
                                                 file_path, depth)
            else:
                # Kotlin simple string interpolation: $identifier (without braces)
                # tree-sitter parses this as consecutive string_content nodes:
                #   string_content("$") + string_content("identifier")
                # We detect this pattern and create DFG edges for the referenced vars.
                import re
                children = list(node.children)
                for i, child in enumerate(children):
                    if child.type != "string_content":
                        continue
                    text = self._text(child)
                    if text == "$" and i + 1 < len(children):
                        next_child = children[i + 1]
                        if next_child.type == "string_content":
                            raw = self._text(next_child).strip()
                            # Extract leading identifier portion (may be followed
                            # by non-identifier chars like ')', '"', etc.)
                            var_name = re.match(r'^[a-zA-Z_]\w*', raw)
                            if var_name:
                                var_name = var_name.group(0)
                                var_pos = add_node({
                                    "label": NodeLabel.IDENTIFIER.value,
                                    "name": var_name,
                                    "lineno": self._lineno(node),
                                    "language": self.language,
                                    "attrs": {
                                        "type": IdentifierType.VARIABLE.value,
                                        "raw_type": "string_template_var",
                                    },
                                })
                                add_edge({
                                    "label": "dfg",
                                    "source": var_pos,
                                    "target": str_pos,
                                })
                                if ctx_stack:
                                    self._own_edge(add_edge, ctx_stack, var_pos, depth)
            return str_pos

        # ---- True / False (boolean) -----------------------------------
        if ntype in ("true", "false"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.BOOLEAN)

        # ---- null -----------------------------------------------------
        if ntype == "null":
            return self._emit_const(add_node, "null",
                                    self._lineno(node), ConstType.NULL)

        # ---- Identifiers ----------------------------------------------
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, file_path)

        # ---- Parenthesized expression ---------------------------------
        if ntype == "parenthesized_expression":
            for child in node.children:
                if child.type in _SKIP_TYPES:
                    continue
                return self._walk_node(child, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Class body (container) -----------------------------------
        if ntype == "class_body":
            return self._walk_class_body(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Fallback -------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Import (parent node — import_statement equivalent)
    # ===================================================================

    def _walk_import_direct(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        """Handle a top-level ``import`` parent node.

        In tree-sitter-kotlin the import statement is modelled as::

            import:                  # parent
                import: "import"    # keyword leaf
                qualified_identifier: "kotlin.io.IO"
                    identifier: "kotlin"
                    .
                    identifier: "io"
                    .
                    identifier: "IO"
        """
        lineno = self._lineno(node)
        text = self._text(node)

        # Extract path — everything after the "import" keyword
        path = text.replace("import", "", 1).strip().strip(";").strip()

        import_name = path or "<import>"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": import_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.IMPORT.value,
                "source": path,
                "raw_type": "ImportStatement",
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
    # Import (navigation_expression starting with 'import' keyword)
    # ===================================================================

    def _walk_maybe_import(self, node, add_node, add_edge,
                           ctx_stack, file_path, depth) -> int | None:
        """Check if a navigation_expression is an import statement."""
        # Check first child for 'import' keyword
        first = node.children[0] if node.children else None
        if first and first.type == "identifier" and self._text(first) == "import":
            lineno = self._lineno(node)
            path = self._text(node).strip().lstrip("import").strip().strip()

            import_name = path or "<import>"

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": import_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.IMPORT.value,
                    "source": path,
                    "raw_type": "ImportStatement",
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

        # Not an import — walk as children
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

    # ===================================================================
    # Class declaration
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.CLASS.value,
                "raw_type": "class_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk class body
        body = self._find_child_by_type(node, "class_body")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            self._walk_class_body(body, add_node, add_edge, ctx_stack,
                                 file_path, 0)
            ctx_stack.pop()

        # Walk secondary constructors
        for child in node.children:
            if child.type == "secondary_constructor":
                self._walk_secondary_constructor(child, add_node, add_edge,
                                                 ctx_stack, file_path, 0)

        return pos

    # ===================================================================
    # Object declaration (Kotlin singleton)
    # ===================================================================

    def _walk_object(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.CLASS.value,
                "raw_type": "object_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "class_body")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            self._walk_class_body(body, add_node, add_edge, ctx_stack,
                                 file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Interface declaration
    # ===================================================================

    def _walk_interface(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.INTERFACE.value,
                "raw_type": "interface_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "class_body")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            self._walk_class_body(body, add_node, add_edge, ctx_stack,
                                 file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Enum declaration
    # ===================================================================

    def _walk_enum(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.ENUM.value,
                "raw_type": "enum_declaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "class_body", "enum_class_body")
        if body:
            ctx_stack.append((pos, NodeLabel.CLASS.value))
            self._walk_class_body(body, add_node, add_edge, ctx_stack,
                                 file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Class body (container)
    # ===================================================================

    def _walk_class_body(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int | None:
        for idx, child in enumerate(node.children):
            if child is None or not hasattr(child, 'type'):
                continue
            if self._is_skip(child):
                continue
            # companion_object — walk its body but don't create a separate node
            if child.type == "companion_object":
                comp_body = self._find_child_by_type(child, "class_body")
                if comp_body:
                    self._walk_class_body(comp_body, add_node, add_edge,
                                         ctx_stack, file_path, depth)
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, depth + idx)
        return None

    # ===================================================================
    # Function / Method
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"

        # Determine function type: method if inside a class context
        in_class = any(ctx[1] == NodeLabel.CLASS.value for ctx in ctx_stack)
        if in_class:
            func_type = FunctionType.METHOD.value
        else:
            func_type = FunctionType.FUNCTION.value

        fullname = name

        # Parameters
        param_node = self._find_child_by_type(node, "function_value_parameters", "parameter")
        param_names = self._extract_param_names(param_node)

        param_strs = []
        for pname in param_names:
            param_strs.append(pname)

        # Return type
        ret_type = ""
        type_node = self._find_child_by_type(node, "user_type")
        if type_node:
            ret_type = self._text(type_node)

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
                "raw_type": "function_declaration",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, pname in enumerate(param_names):
            p_pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": pname,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "file_path": file_path,
                },
            })
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": p_pos,
                "attrs": {"index": idx},
            })

        # Body: could be block or function_body (= expr)
        block = self._find_child_by_type(node, "block")
        if block is not None:
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
        else:
            # Expression body (function_body = expr)
            func_body = self._find_child_by_type(node, "function_body")
            if func_body:
                for child in func_body.children:
                    if child.type in _SKIP_TYPES or child.type == "=":
                        continue
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                    file_path, 0)
                    break

        ctx_stack.pop()
        return pos

    def _extract_param_names(self, param_node) -> list[str]:
        """Extract parameter names from a parameter node."""
        names = []
        if param_node is None:
            return names
        for child in param_node.children:
            if child.type == "parameter":
                for sub in child.children:
                    if sub.type == "simple_identifier":
                        names.append(self._text(sub))
                        break
                    elif sub.type == "identifier":
                        names.append(self._text(sub))
                        break
        return names

    # ===================================================================
    # Secondary constructor
    # ===================================================================

    def _walk_secondary_constructor(self, node, add_node, add_edge,
                                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        param_node = self._find_child_by_type(node, "parameter")
        param_names = self._extract_param_names(param_node)
        param_strs = ", ".join(param_names)

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": "<constructor>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": "<constructor>",
                "type": FunctionType.CONSTRUCTOR.value,
                "signature": f"constructor({param_strs})",
                "file_path": file_path,
                "raw_type": "secondary_constructor",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, pname in enumerate(param_names):
            p_pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": pname,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "file_path": file_path,
                },
            })
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": p_pos,
                "attrs": {"index": idx},
            })

        # Body
        block = self._find_child_by_type(node, "block")
        if block:
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Lambda / Anonymous function
    # ===================================================================

    def _walk_lambda(self, node, add_node, add_edge,
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
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk lambda body
        for child in node.children:
            if self._is_skip(child):
                continue
            ctx_stack.append((pos, NodeLabel.FUNCTION.value))
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, 0)
            ctx_stack.pop()
            break  # Only walk first non-skip child as body

        return pos

    # ===================================================================
    # Branch: If expression
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Kotlin if: condition { then } else { ... }
        cond_node = None
        cond_text = "<if>"
        for child in node.children:
            if child.type in ("if", "else", "{", "}", "block"):
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

        # Then block(s)
        blocks = self._find_children_by_type(node, "block")
        ctx_stack.append((pos, NodeLabel.BRANCH.value))

        if blocks:
            then_block = blocks[0]
            self._walk_block(then_block, add_node, add_edge, ctx_stack,
                             file_path, 0)

        # Else clause
        else_node = None
        for child in node.children:
            if child.type == "else":
                else_node = child
                break

        if else_node is not None:
            # Check for else if
            elif_node = self._find_child_by_type(else_node, "if_expression")
            if elif_node is not None:
                self._walk_if(elif_node, add_node, add_edge, ctx_stack,
                              file_path, depth + 1)
            else:
                else_block = self._find_child_by_type(else_node, "block")
                if else_block is not None:
                    else_pos = add_node({
                        "label": NodeLabel.BRANCH.value,
                        "name": "<else>",
                        "lineno": self._lineno(else_node),
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
    # Branch: When expression (switch)
    # ===================================================================

    def _walk_when(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # when_subject
        value_node = self._find_child_by_type(node, "when_subject")
        value_text = "<when>"
        if value_node:
            inner = self._find_child_by_type(value_node, "range_expression",
                                              "binary_expression", "identifier",
                                              "call_expression")
            if inner:
                value_text = self._text(inner)
            else:
                value_text = self._text(value_node).strip("()")

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": value_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": value_text,
                "raw_type": "WhenExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk subject
        if value_node:
            inner = self._find_child_by_type(value_node, "range_expression",
                                              "binary_expression", "identifier",
                                              "call_expression")
            if inner:
                val_pos = self._walk_node(inner, add_node, add_edge,
                                           ctx_stack, file_path, 0)
                if val_pos is not None:
                    self._ast_edge(add_edge, pos, val_pos, AstRole.CONDITION.value)

        # Walk when entries (cases)
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        entry_idx = 0
        for child in node.children:
            if child.type == "when_entry":
                self._walk_when_entry(child, add_node, add_edge, ctx_stack,
                                      file_path, entry_idx, pos)
                entry_idx += 1

        ctx_stack.pop()
        return pos

    def _walk_when_entry(self, node, add_node, add_edge,
                         ctx_stack, file_path, idx, parent_pos) -> int:
        lineno = self._lineno(node)

        # Determine if this is a default (else) case
        is_default = False
        condition_text = ""
        for child in node.children:
            if child.type == "else":
                is_default = True
                condition_text = "else"
                break
            if child.type == "when_condition":
                condition_text = self._text(child).strip()

        branch_type = BranchType.DEFAULT.value if is_default else BranchType.CASE.value

        entry_pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition_text or f"case_{idx}",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": branch_type,
                "condition": condition_text,
                "raw_type": "WhenEntry",
            },
        })
        add_edge({
            "label": EdgeLabel.AST.value,
            "source": parent_pos,
            "target": entry_pos,
            "attrs": {"role": AstRole.IFTRUE.value, "index": idx},
        })

        # Walk entry body
        ctx_stack.append((entry_pos, NodeLabel.BRANCH.value))
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type in ("when_condition", "->", "guard"):
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, 0)
            break  # Only first body child

        ctx_stack.pop()
        return entry_pos

    # ===================================================================
    # Branch: For statement (foreach)
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Kotlin for: for (x in iterable) { body }
        iterable = None
        iter_text = "<for>"
        for child in node.children:
            if child.type in ("for", "block", "(", ")"):
                continue
            if child.type in ("variable_declaration", "identifier", "_"):
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
                "raw_type": "ForStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if iterable is not None:
            iter_pos = self._walk_node(iterable, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if iter_pos is not None:
                self._ast_edge(add_edge, pos, iter_pos, AstRole.CONDITION.value)

        block = self._find_child_by_type(node, "block")
        if block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: While / Do-While statement
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        cond_node = None
        cond_text = "<while>"
        for child in node.children:
            if child.type in ("while", "do", "block"):
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
                "raw_type": node.type,
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
    # Branch: Try expression
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
                "condition": "",
                "raw_type": "TryExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))

        # Try block
        try_block = self._find_child_by_type(node, "block")
        if try_block:
            self._walk_block(try_block, add_node, add_edge, ctx_stack,
                             file_path, 0)

        # Catch blocks
        for child in node.children:
            if child.type == "catch_block":
                catch_lineno = self._lineno(child)
                catch_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<catch>",
                    "lineno": catch_lineno,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.CATCH.value,
                        "condition": "",
                        "raw_type": "CatchBlock",
                    },
                })
                add_edge({
                    "label": EdgeLabel.AST.value,
                    "source": pos,
                    "target": catch_pos,
                    "attrs": {"role": AstRole.IFFALSE.value},
                })
                catch_block = self._find_child_by_type(child, "block")
                if catch_block:
                    ctx_stack.pop()
                    ctx_stack.append((catch_pos, NodeLabel.BRANCH.value))
                    self._walk_block(catch_block, add_node, add_edge,
                                     ctx_stack, file_path, 0)

            if child.type == "finally_block":
                finally_lineno = self._lineno(child)
                finally_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<finally>",
                    "lineno": finally_lineno,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.FINALLY.value,
                        "condition": "",
                        "raw_type": "FinallyBlock",
                    },
                })
                add_edge({
                    "label": EdgeLabel.AST.value,
                    "source": pos,
                    "target": finally_pos,
                    "attrs": {"role": AstRole.IFFALSE.value},
                })
                finally_block = self._find_child_by_type(child, "block")
                if finally_block:
                    ctx_stack.pop()
                    ctx_stack.append((finally_pos, NodeLabel.BRANCH.value))
                    self._walk_block(finally_block, add_node, add_edge,
                                     ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Call expression
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # callee + arguments
        callee = None
        for child in node.children:
            if child.type in ("(", ")", "value_arguments"):
                continue
            callee = child
            break
        callee_name = self._text(callee) if callee else "<call>"

        # Determine call type: method call when callee is a navigation/postfix
        # expression (obj.method()), otherwise direct call
        if callee is not None and callee.type in (
            "navigation_expression", "postfix_expression",
            "callable_reference", "safe_navigation_expression",
        ):
            call_type = OperatorType.METHOD_CALL.value
            cg_call_type = CgCallType.METHOD
        else:
            call_type = OperatorType.CALL.value
            cg_call_type = CgCallType.DIRECT

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": call_type,
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
        arg_list = self._find_child_by_type(node, "value_arguments")
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
                           "call_type": cg_call_type.value,
                           "lineno": lineno,
                       }})

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
                              "===","!==", "plus", "minus", "times", "div",
                              "mod", "rangeTo", "and", "or", "xor",
                              "shl", "shr", "ushr"):
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
    # Prefix expression (unary)
    # ===================================================================

    def _walk_prefix(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        op_text = ""
        for child in node.children:
            if child.type in ("-", "!", "++", "--", "+", "~"):
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
                "raw_type": "prefix_expression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk operand
        for child in node.children:
            if child.type in _SKIP_TYPES or self._text(child) == op_text:
                continue
            op_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if op_pos is not None:
                self._ast_edge(add_edge, pos, op_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Assignment
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

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
                "raw_type": "assignment",
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
    # Throw expression
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
                "raw_type": "throw_expression",
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
            break

        return pos

    # ===================================================================
    # Return expression
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
        return pos

    # ===================================================================
    # Property declaration
    # ===================================================================

    def _walk_property(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Kotlin property: val/var name: Type = expr
        # Name might be in variable_declaration > identifier
        name = ""
        var_decl = self._find_child_by_type(node, "variable_declaration")
        if var_decl:
            name_node = self._find_child_by_type(var_decl, "identifier")
            name = self._text(name_node) if name_node else "<property>"
        else:
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

        # Walk initializer expression — create assignment operator for DFG
        found_init = False
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child.type in ("val", "var", ":", "=", "type_identifier",
                              "variable_declaration"):
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
                        "raw_type": "property_declaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + 1)
                self._ast_edge(add_edge, eq_pos, pos, AstRole.LHS.value)
                self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)
                found_init = True
            break

        return pos

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
    # Kotlin string interpolation DFG
    # ===================================================================

    def _walk_interpolation(self, node, add_node, add_edge, str_pos,
                            ctx_stack, file_path, depth):
        """Walk ${expr} interpolation nodes and create DFG edges."""
        if not node.children:
            return
        for child in node.children:
            ctype = child.type
            if ctype in ("${", "}", "string_content"):
                continue
            expr_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, depth)
            if expr_pos is not None:
                add_edge({
                    "label": "dfg",
                    "source": expr_pos,
                    "target": str_pos,
                })
                if ctx_stack:
                    self._own_edge(add_edge, ctx_stack, expr_pos, depth)

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
