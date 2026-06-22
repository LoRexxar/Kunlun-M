"""Lua AST Normalizer — maps tree-sitter Lua AST to UnifiedNode / UnifiedEdge.

Converts Lua source parsed by ``tree-sitter-lua`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter node model:
  - ``node.type`` → str (e.g. ``"function_declaration"``)
  - ``node.text`` → bytes (UTF-8 source text)
  - ``node.children`` → list of child nodes
  - ``node.start_point`` → (row, col), row is 0-indexed
  - ``node.end_point`` → (row, col)
  - Keywords/punctuation are leaf nodes (e.g. ``"if"``, ``"then"``, ``"end"``)
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
# tree-sitter Lua node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",",
    "==", "~=", ">=", "<=", ">", "<", "and", "or", "not",
    "+", "-", "*", "/", "%", "^", "..", "#", "=",
    "if", "then", "else", "elseif", "end",
    "for", "in", "while", "do", "repeat", "until",
    "local", "function", "return", "break", "goto",
    "true", "false", "nil",
    ".", ":", "::",
})

_LITERAL_TYPES = frozenset({
    "number", "string",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter Lua AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_lua as tslua

        lang = Language(tslua.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.lua",
            source_content=source,
        )
    """

    language = "lua"

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

        # ---- Import (require) ------------------------------------------
        if ntype == "require_call":
            return self._walk_require(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Function declaration (named) ------------------------------
        if ntype == "function_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Function definition (anonymous) --------------------------
        if ntype == "function_definition":
            return self._walk_anonymous_function(node, add_node, add_edge,
                                                 ctx_stack, file_path, depth)

        # ---- Branch: if ------------------------------------------------
        if ntype == "if_statement":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                 file_path, depth)

        # ---- Branch: while ---------------------------------------------
        if ntype == "while_statement":
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Branch: for (numeric) ------------------------------------
        if ntype == "for_statement":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: for_in (generic) ---------------------------------
        if ntype == "for_in_statement":
            return self._walk_for_in(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Branch: repeat-until -------------------------------------
        if ntype == "repeat_statement":
            return self._walk_repeat(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Return ----------------------------------------------------
        if ntype == "return_statement":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Break -----------------------------------------------------
        if ntype == "break_statement":
            return self._walk_break(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Goto -----------------------------------------------------
        if ntype == "goto_statement":
            return self._walk_goto(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Label -----------------------------------------------------
        if ntype == "label_statement":
            return self._walk_label(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Function call ---------------------------------------------
        if ntype == "function_call":
            # Check if it's a require() call
            callee = self._find_child_by_type(node, "identifier")
            if callee and self._text(callee) == "require":
                return self._walk_require_from_call(node, add_node, add_edge,
                                                     ctx_stack, file_path, depth)
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Method call (obj:method) ----------------------------------
        if ntype == "method_call":
            return self._walk_method_call(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Assignment -----------------------------------------------
        if ntype in ("assignment", "assignment_statement"):
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Local declaration ----------------------------------------
        if ntype in ("local_declaration", "variable_declaration"):
            return self._walk_local_declaration(node, add_node, add_edge,
                                                ctx_stack, file_path, depth)

        # ---- Binary operation ------------------------------------------
        if ntype in ("binary_operation", "binary_expression"):
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Unary operation -------------------------------------------
        if ntype in ("unary_operation", "unary_expression"):
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Literals -------------------------------------------------
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # ---- true / false (boolean) ------------------------------------
        if ntype in ("true", "false"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.BOOLEAN)

        # ---- nil -------------------------------------------------------
        if ntype == "nil":
            return self._emit_const(add_node, "nil",
                                    self._lineno(node), ConstType.NULL)

        # ---- Identifier ------------------------------------------------
        if ntype == "identifier":
            return self._walk_identifier(node, add_node, file_path)

        # ---- name (table field) ----------------------------------------
        if ntype == "name":
            return self._emit_identifier(add_node, self._text(node),
                                         self._lineno(node),
                                         IdentifierType.FIELD)

        # ---- dot_index_expression (a.b) --------------------------------
        if ntype == "dot_index_expression":
            return self._walk_dot_index(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- bracket_index_expression (a[b]) ---------------------------
        if ntype == "bracket_index_expression":
            return self._walk_bracket_index(node, add_node, add_edge, ctx_stack,
                                            file_path, depth)

        # ---- parenthesized expression ----------------------------------
        if ntype == "parenthesized_expression":
            inner = self._find_child_by_type(node,
                "binary_operation", "unary_operation", "function_call",
                "method_call", "identifier", "dot_index_expression",
                "bracket_index_expression", "if_statement")
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Fallback -------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Import (require_call)
    # ===================================================================

    def _walk_require(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        # Extract module name from require("module") or require 'module'
        # In tree-sitter-lua, require_call has function_call as child
        # The argument is typically a string literal
        module_name = ""
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type in ("(", ")", ","):
                        continue
                    module_name = self._text(arg).strip("'\"")
                    break
                break

        if not module_name:
            module_name = text

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": module_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.REQUIRE.value,
                "source": module_name,
                "raw_type": "require_call",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if module_name:
            dep_pos = add_node({
                "label": NodeLabel.DEPENDENCY.value,
                "name": module_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {"source": module_name},
            })
            add_edge({
                "label": EdgeLabel.FRG.value,
                "source": pos,
                "target": dep_pos,
                "attrs": {"type": FrgType.IMPORT.value},
            })

        return pos

    # ===================================================================
    # Import from function_call (require() pattern)
    # ===================================================================

    def _walk_require_from_call(self, node, add_node, add_edge,
                                ctx_stack, file_path, depth) -> int:
        """Handle require("module") which is a function_call in tree-sitter-lua."""
        lineno = self._lineno(node)

        # Extract module name from arguments
        module_name = ""
        arg_list = self._find_child_by_type(node, "arguments")
        if arg_list:
            for arg in arg_list.children:
                if arg.type in ("(", ")", ","):
                    continue
                module_name = self._text(arg).strip("'\"")
                break

        if not module_name:
            module_name = "require"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": module_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.REQUIRE.value,
                "source": module_name,
                "raw_type": "function_call(require)",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if module_name:
            dep_pos = add_node({
                "label": NodeLabel.DEPENDENCY.value,
                "name": module_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {"source": module_name},
            })
            add_edge({
                "label": EdgeLabel.FRG.value,
                "source": pos,
                "target": dep_pos,
                "attrs": {"type": FrgType.IMPORT.value},
            })

        return pos

    # ===================================================================
    # Function declaration (named)
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"

        # Parameters
        param_list = self._find_child_by_type(node, "parameters")
        params = []
        if param_list:
            params = [c for c in param_list.children if c.type == "identifier"]

        param_strs = [self._text(p) for p in params]

        signature = f"function {name}({', '.join(param_strs)})"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": FunctionType.FUNCTION.value,
                "signature": signature,
                "file_path": file_path,
                "raw_type": "function_declaration",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, param in enumerate(params):
            p_pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": self._text(param),
                "lineno": self._lineno(param),
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

        # Body (block)
        block = self._find_child_by_type(node, "block")
        if block is not None:
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Function definition (anonymous / lambda)
    # ===================================================================

    def _walk_anonymous_function(self, node, add_node, add_edge,
                                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        # Parameters
        param_list = self._find_child_by_type(node, "parameters")
        params = []
        if param_list:
            params = [c for c in param_list.children if c.type == "identifier"]

        param_strs = [self._text(p) for p in params]

        signature = f"function({', '.join(param_strs)})"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": "<lambda>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": "<lambda>",
                "type": FunctionType.LAMBDA.value,
                "signature": signature,
                "raw_type": "function_definition",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        for idx, param in enumerate(params):
            p_pos = add_node({
                "label": NodeLabel.PARAMETER.value,
                "name": self._text(param),
                "lineno": self._lineno(param),
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
        if block is not None:
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: If Statement
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Lua if: if condition then block {elseif condition then block} [else block] end
        # Find condition: first non-keyword child
        cond_node = None
        cond_text = "<if>"
        for child in node.children:
            if child.type in ("if", "then", "block", "elseif_clause",
                               "else_clause", "end"):
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

        # Then block
        block = self._find_child_by_type(node, "block")
        if block is not None:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        # elseif clauses
        elseif_clauses = self._find_children_by_type(node, "elseif_clause")
        for ei, elif_clause in enumerate(elseif_clauses):
            elif_cond = None
            elif_cond_text = "<elseif>"
            for child in elif_clause.children:
                if child.type in ("elseif", "then", "block"):
                    continue
                elif_cond = child
                break
            if elif_cond:
                elif_cond_text = self._text(elif_cond)

            elif_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": elif_cond_text,
                "lineno": self._lineno(elif_clause),
                "language": self.language,
                "attrs": {
                    "type": BranchType.ELIF.value,
                    "condition": elif_cond_text,
                    "raw_type": "elseif_clause",
                },
            })
            add_edge({
                "label": EdgeLabel.AST.value,
                "source": pos,
                "target": elif_pos,
                "attrs": {"role": AstRole.IFFALSE.value, "index": ei},
            })

            # Walk elseif condition
            if elif_cond is not None:
                c_pos = self._walk_node(elif_cond, add_node, add_edge,
                                        ctx_stack, file_path, 0)
                if c_pos is not None:
                    self._ast_edge(add_edge, elif_pos, c_pos,
                                   AstRole.CONDITION.value)

            # Walk elseif block
            elif_block = self._find_child_by_type(elif_clause, "block")
            if elif_block is not None:
                ctx_stack.append((elif_pos, NodeLabel.BRANCH.value))
                self._walk_block(elif_block, add_node, add_edge,
                                 ctx_stack, file_path, 0)
                ctx_stack.pop()

        # else clause
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause is not None:
            else_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": "<else>",
                "lineno": self._lineno(else_clause),
                "language": self.language,
                "attrs": {
                    "type": BranchType.ELSE.value,
                    "condition": "",
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
            if else_block is not None:
                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                self._walk_block(else_block, add_node, add_edge,
                                 ctx_stack, file_path, 0)
                ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: While Statement
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
                "raw_type": "while_statement",
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
    # Branch: For Statement (numeric)
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Lua numeric for: for i = start, end, step do block end
        var_name = ""
        for child in node.children:
            if child.type == "identifier":
                var_name = self._text(child)
                break

        iter_text = var_name or "<for>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": iter_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": iter_text,
                "raw_type": "for_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk start/end/step expressions (skip identifier and = and , and do)
        found_id = False
        for child in node.children:
            if child.type == "identifier" and not found_id:
                found_id = True
                continue
            if child.type in ("=", ",", "do", "block"):
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.CONDITION.value)

        block = self._find_child_by_type(node, "block")
        if block:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            self._walk_block(block, add_node, add_edge, ctx_stack, file_path, 0)
            ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: For-In Statement (generic / foreach)
    # ===================================================================

    def _walk_for_in(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Lua generic for: for k, v in iter do block end
        var_names = []
        iter_text = "<foreach>"
        for child in node.children:
            if child.type in ("for", "in", "do", "block"):
                continue
            if child.type == "identifier":
                var_names.append(self._text(child))

        # Find the iterator expression (after "in" keyword)
        iter_node = None
        found_in = False
        for child in node.children:
            if child.type == "in":
                found_in = True
                continue
            if found_in:
                if child.type == "block" or child.type == "do":
                    break
                iter_node = child
                break

        if iter_node:
            iter_text = self._text(iter_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": iter_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": iter_text,
                "raw_type": "for_in_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk iterator expression
        if iter_node is not None:
            iter_pos = self._walk_node(iter_node, add_node, add_edge,
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
    # Branch: Repeat-Until Statement
    # ===================================================================

    def _walk_repeat(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<repeat>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": "<repeat_until>",
                "raw_type": "repeat_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk body (block) and condition
        for child in node.children:
            if child.type in ("repeat", "until"):
                continue
            if child.type == "block":
                ctx_stack.append((pos, NodeLabel.BRANCH.value))
                self._walk_block(child, add_node, add_edge, ctx_stack,
                                 file_path, 0)
                ctx_stack.pop()
            else:
                cond_pos = self._walk_node(child, add_node, add_edge,
                                           ctx_stack, file_path, 0)
                if cond_pos is not None:
                    self._ast_edge(add_edge, pos, cond_pos,
                                   AstRole.CONDITION.value)

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

        # Walk return value expressions
        for child in node.children:
            if child.type == "return":
                continue
            ret_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if ret_pos is not None:
                self._ast_edge(add_edge, pos, ret_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Break
    # ===================================================================

    def _walk_break(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "break",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BREAK.value,
                "raw_type": "break_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Goto
    # ===================================================================

    def _walk_goto(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        label_name = ""
        for child in node.children:
            if child.type == "identifier":
                label_name = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": label_name or "<goto>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.GOTO.value,
                "raw_type": "goto_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Label
    # ===================================================================

    def _walk_label(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        label_name = self._text(node).strip(":")

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": label_name or "<label>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "raw_type": "label_statement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Function call
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # function_call: identifier (args)
        callee = self._find_child_by_type(node, "identifier",
                                           "dot_index_expression",
                                           "parenthesized_expression",
                                           "bracket_index_expression")
        callee_name = self._text(callee) if callee else "<call>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CALL.value,
                "raw_type": "function_call",
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
    # Method call (obj:method)
    # ===================================================================

    def _walk_method_call(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # method_call: object : identifier (args)
        method_name_node = self._find_child_by_type(node, "identifier")
        method_name = self._text(method_name_node) if method_name_node else "<method>"

        # Get the object (first child before the ':')
        obj_node = None
        for child in node.children:
            if child.type in (":", "identifier", "(", ")", ","):
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
                "raw_type": "method_call",
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
    # Assignment
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # assignment: left = right
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
    # Local declaration
    # ===================================================================

    def _walk_local_declaration(self, node, add_node, add_edge,
                                ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Handle two formats:
        # 1. local_declaration: [local, identifier, =, expr, ...]
        # 2. variable_declaration (tree-sitter-lua): [local, assignment_statement > [variable_list > identifier, =, expression_list > expr]]
        asmt = self._find_child_by_type(node, "assignment_statement")
        if asmt:
            # Format 2: delegate to _walk_assignment which already creates operator + LHS/RHS
            return self._walk_assignment(asmt, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # Format 1: Extract variable names (identifiers before '=')
        names = []
        init_exprs = []
        found_eq = False
        for child in node.children:
            if child.type == "=":
                found_eq = True
                continue
            if child.type == "local":
                continue
            if not found_eq:
                if child.type == "identifier":
                    names.append(self._text(child))
                elif child.type == "function_call":
                    # local call = func() — unusual but valid
                    names.append("<call_assign>")
                elif child.type == "function_definition":
                    # local f = function(...) end
                    names.append("<lambda>")
                elif child.type == "table_constructor":
                    names.append("<table>")
            else:
                init_exprs.append(child)

        # Emit each variable as an identifier
        last_var_pos = None
        for idx, name in enumerate(names):
            var_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.VARIABLE.value,
                    "raw_type": "local_declaration",
                },
            })
            self._own_edge(add_edge, ctx_stack, var_pos, depth + idx)
            last_var_pos = var_pos

        # Walk initializer expressions
        for idx, init_expr in enumerate(init_exprs):
            # Check for function_definition in local declaration
            if init_expr.type == "function_definition":
                func_pos = self._walk_anonymous_function(
                    init_expr, add_node, add_edge, ctx_stack, file_path, depth)
                continue

            init_pos = self._walk_node(init_expr, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if init_pos is not None and last_var_pos is not None:
                # Create assignment operator node for DFG builder
                eq_pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": "=",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "local_declaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, eq_pos, depth + 1)
                self._ast_edge(add_edge, eq_pos, last_var_pos, AstRole.LHS.value)
                self._ast_edge(add_edge, eq_pos, init_pos, AstRole.RHS.value)

        return last_var_pos

    # ===================================================================
    # Binary operation
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        op_node = None
        for child in node.children:
            if child.type in ("+", "-", "*", "/", "%", "^", "..",
                              "==", "~=", "<=", ">=", "<", ">",
                              "and", "or"):
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
                "raw_type": "binary_operation",
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
    # Unary operation
    # ===================================================================

    def _walk_unary(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        op_text = ""
        for child in node.children:
            if child.type in ("-", "not", "#"):
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
                "raw_type": "unary_operation",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk operand
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if self._text(child) == op_text:
                continue
            op_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if op_pos is not None:
                self._ast_edge(add_edge, pos, op_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Dot index expression (a.b)
    # ===================================================================

    def _walk_dot_index(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node)

        field_node = self._find_child_by_type(node, "name", "identifier")
        field_name = self._text(field_node) if field_node else ""

        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": field_name or text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.FIELD.value,
                "raw_type": "dot_index_expression",
                "full_text": text,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk object
        for child in node.children:
            if child.type in ("name", "identifier", "."):
                continue
            obj_pos = self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.OPERAND.value)
            break

        return pos

    # ===================================================================
    # Bracket index expression (a[b])
    # ===================================================================

    def _walk_bracket_index(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "[]",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "bracket_index_expression",
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

        if ntype == "number":
            return self._emit_const(add_node, text, lineno, ConstType.NUMBER)
        if ntype == "string":
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
