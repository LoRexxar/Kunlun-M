"""Ruby AST Normalizer — maps tree-sitter Ruby AST to UnifiedNode / UnifiedEdge.

Converts Ruby source parsed by ``tree-sitter-ruby`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter node model:
  - ``node.type`` → str (e.g. ``"method"``)
  - ``node.text`` → bytes (UTF-8 source text)
  - ``node.children`` → list of child nodes
  - ``node.start_point`` → (row, col), row is 0-indexed
  - ``node.end_point`` → (row, col)
  - Keywords/punctuation are leaf nodes (e.g. ``"if"``, ``"end"``)
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
    AstRole,
    FrgType,
)

__all__ = ["Normalizer"]

# ---------------------------------------------------------------------------
# tree-sitter Ruby node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||", "and", "or", "not",
    "+", "-", "*", "/", "%", "=", "!", "~", "&", "|", "^",
    "->", "::", ".", "..", "...",
    "=>",
    "<", ">",
    "then", "end",
    "do",
    "attr_accessor", "attr_reader", "attr_writer",
    "begin",  # keyword leaf — container is handled separately
    "elsif",
    "when",
    "rescue",
    "ensure",
    "in",
    "super",
    "redo",
    "proc",
})

_LITERAL_TYPES = frozenset({
    "integer", "float",
    "string", "string_content", "heredoc",
    "character",
    "simple_symbol", "complex_symbol", "hash_key_symbol", "symbol",
})

_IMPORT_CALLS = frozenset({
    "require", "require_relative", "load",
})

_MIXIN_CALLS = frozenset({
    "include", "extend", "prepend",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter Ruby AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_ruby as tsruby

        lang = Language(tsruby.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.rb",
            source_content=source,
        )
    """

    language = "ruby"

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

        # ---- Class / Module ------------------------------------------
        if ntype in ("class", "module"):
            return self._walk_class(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Singleton class ------------------------------------------
        if ntype == "singleton_class":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Method (def) ----------------------------------------------
        if ntype == "method":
            return self._walk_method(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Alias ----------------------------------------------------
        if ntype == "alias":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Block / do...end / lambda ---------------------------------
        if ntype in ("block", "lambda"):
            return self._walk_block_func(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- If / Unless -----------------------------------------------
        if ntype in ("if", "unless"):
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                 file_path, depth)

        # ---- Case / When -----------------------------------------------
        if ntype in ("case", "case_match"):
            return self._walk_case(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- While / Until ---------------------------------------------
        if ntype in ("while", "until"):
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- For -------------------------------------------------------
        if ntype == "for":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Begin / Rescue / Ensure -----------------------------------
        if ntype == "begin":
            return self._walk_begin(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Return ----------------------------------------------------
        if ntype == "return":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Call expression -------------------------------------------
        if ntype == "call":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Assignment -----------------------------------------------
        if ntype == "assignment":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Binary expression -----------------------------------------
        if ntype == "binary":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Yield -----------------------------------------------------
        if ntype == "yield":
            return self._emit_operator(add_node, "yield", self._lineno(node),
                                       OperatorType.YIELD)

        # ---- Raise -----------------------------------------------------
        if ntype == "raise":
            return self._emit_operator(add_node, "raise", self._lineno(node),
                                       OperatorType.THROW)

        # ---- Break / Next / Redo ---------------------------------------
        if ntype in ("break", "next", "redo"):
            op_type = (OperatorType.CONTINUE if ntype == "next"
                       else OperatorType.BREAK)
            return self._emit_operator(add_node, ntype, self._lineno(node),
                                       op_type)

        # ---- Identifier ------------------------------------------------
        if ntype == "identifier":
            return self._walk_identifier(node, add_node, file_path)

        # ---- Constant --------------------------------------------------
        if ntype == "constant":
            return self._emit_identifier(add_node, self._text(node),
                                        self._lineno(node),
                                        IdentifierType.STATIC)

        # ---- Instance variable (@var) ----------------------------------
        if ntype == "instance_variable":
            return self._emit_identifier(add_node, self._text(node),
                                        self._lineno(node),
                                        IdentifierType.FIELD)

        # ---- Global variable ($var) ------------------------------------
        if ntype == "global_variable":
            return self._emit_identifier(add_node, self._text(node),
                                        self._lineno(node),
                                        IdentifierType.GLOBAL)

        # ---- Class variable (@@var) ------------------------------------
        if ntype == "class_variable":
            return self._emit_identifier(add_node, self._text(node),
                                        self._lineno(node),
                                        IdentifierType.STATIC)

        # ---- self keyword ----------------------------------------------
        if ntype == "self":
            return self._emit_identifier(add_node, "self", self._lineno(node),
                                         IdentifierType.THIS)

        # ---- Literals -------------------------------------------------
        if ntype in ("integer", "float"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.NUMBER)

        if ntype in ("string", "string_content", "heredoc"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.STRING)

        if ntype == "character":
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.STRING)

        if ntype in ("simple_symbol", "complex_symbol",
                     "hash_key_symbol", "symbol"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.CONSTANT)

        if ntype in ("true", "false"):
            return self._emit_const(add_node, self._text(node),
                                    self._lineno(node), ConstType.BOOLEAN)

        if ntype == "nil":
            return self._emit_const(add_node, "nil",
                                    self._lineno(node), ConstType.NULL)

        # ---- Array / Hash / Pair --------------------------------------
        if ntype in ("array", "hash", "pair", "hash_pattern", "array_pattern"):
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Parenthesized expression ----------------------------------
        if ntype == "parenthesized_statements":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Splat / Arguments / etc. ----------------------------------
        if ntype in ("argument_list", "arguments",
                     "method_parameters", "parameter",
                     "block_parameter", "hash_splat",
                     "splat", "range", "scope",
                     "else", "then", "end",
                     "do_block", "body_statement",
                     "elsif", "when", "rescue",
                     "ensure", "begin", "match_pattern",
                     "in_pattern", "pattern", "destructured_parameter",
                     "if_guard", "unless_guard",
                     "operator", "field", "call_operator"):
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Fallback -------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Class / Module
    # ===================================================================

    def _walk_class(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # In tree-sitter-ruby, class/module has:
        # class: "class" constant superclass? body_statement "end"
        # module: "module" constant body_statement "end"
        name_node = self._find_child_by_type(node, "constant")
        name = self._text(name_node) if name_node else "<anonymous>"
        class_type = ClassType.CLASS if node.type == "class" else ClassType.MODULE

        # Superclass
        superclass = ""
        sc_node = self._find_child_by_type(node, "superclass")
        if sc_node:
            superclass = self._text(sc_node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": class_type.value,
                "superclass": superclass,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context and walk body
        ctx_stack.append((pos, NodeLabel.CLASS.value))

        body = self._find_child_by_type(node, "body_statement")
        if body is None:
            body = self._find_child_by_type(node, "method")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, idx)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Method (def)
    # ===================================================================

    def _walk_method(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        # tree-sitter-ruby method node:
        # method: "def" [receiver "."] identifier "(" parameters? ")" body_statement "end"
        name_node = self._find_child_by_type(node, "identifier")
        name = self._text(name_node) if name_node else "<anonymous>"

        # Determine function type
        if name == "initialize":
            func_type = FunctionType.CONSTRUCTOR
        elif self._find_child_by_type(node, "receiver"):
            func_type = FunctionType.METHOD
        else:
            func_type = FunctionType.FUNCTION

        # Parameters
        params_node = self._find_child_by_type(node, "method_parameters")
        param_strs = []
        if params_node:
            for c in params_node.children:
                if c.type == "parameter":
                    pname = ""
                    for sub in c.children:
                        if sub.type in ("identifier", "instance_variable"):
                            pname = self._text(sub)
                            break
                    if pname:
                        param_strs.append(pname)

        # Build fullname (receiver.method)
        receiver = self._find_child_by_type(node, "receiver")
        fullname = name
        if receiver:
            recv_text = self._text(receiver)
            fullname = f"{recv_text}.{name}"

        signature = f"def {name}({', '.join(param_strs)})"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": fullname,
                "type": func_type.value,
                "signature": signature,
                "file_path": file_path,
                "raw_type": "method",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Push context
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        if params_node:
            param_idx = 0
            for c in params_node.children:
                if c.type == "parameter":
                    p_pos = self._walk_param(c, add_node, file_path)
                    if p_pos is not None:
                        add_edge({
                            "label": EdgeLabel.OWN.value,
                            "source": pos,
                            "target": p_pos,
                            "attrs": {"index": param_idx},
                        })
                        param_idx += 1

        # Body
        body = self._find_child_by_type(node, "body_statement")
        if body is None:
            body = self._find_child_by_type(node, "begin")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, idx)

        ctx_stack.pop()
        return pos

    def _walk_param(self, param_node, add_node, file_path) -> int | None:
        if param_node is None:
            return None

        name = ""
        for c in param_node.children:
            if c.type in ("identifier", "instance_variable", "global_variable"):
                name = self._text(c)
                break
        if not name:
            return None

        lineno = self._lineno(param_node)
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

    # ===================================================================
    # Block / Lambda
    # ===================================================================

    def _walk_block_func(self, node, add_node, add_edge,
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

        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Walk block parameters
        block_params = self._find_child_by_type(node, "block_parameters")
        if block_params:
            param_idx = 0
            for c in block_params.children:
                if c.type == "parameter":
                    p_pos = self._walk_param(c, add_node, file_path)
                    if p_pos is not None:
                        add_edge({
                            "label": EdgeLabel.OWN.value,
                            "source": pos,
                            "target": p_pos,
                            "attrs": {"index": param_idx},
                        })
                        param_idx += 1

        # Walk body
        body = self._find_child_by_type(node, "body_statement")
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, idx)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # If / Unless
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        ntype = node.type

        # Ruby if: "if" condition body elsif* else? "end"
        # Ruby unless: "unless" condition body else? "end"
        cond_node = None
        cond_text = "<if>"
        for child in node.children:
            if child.type in ("if", "unless", "then", "end"):
                continue
            if child.type == "body_statement" and cond_node is None:
                continue
            if child.type in ("elsif", "else"):
                continue
            cond_node = child
            break

        if cond_node:
            cond_text = self._text(cond_node)

        branch_type = BranchType.IF if ntype == "if" else BranchType.IF

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": branch_type.value,
                "condition": cond_text,
                "raw_type": ntype,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Then body
        then_body = self._find_child_by_type(node, "body_statement")
        if then_body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(then_body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, idx)
            ctx_stack.pop()

        # Elsif / else
        for child in node.children:
            if child.type == "elsif":
                self._walk_elsif(child, add_node, add_edge, ctx_stack,
                                  file_path, pos, depth)
            elif child.type == "else":
                self._walk_else(child, add_node, add_edge, ctx_stack,
                                file_path, pos)

        return pos

    def _walk_elsif(self, node, add_node, add_edge,
                    ctx_stack, file_path, parent_pos, depth) -> None:
        lineno = self._lineno(node)

        # elsif: "elsif" condition body_statement
        cond_node = None
        cond_text = "<elsif>"
        for child in node.children:
            if child.type in ("elsif", "then"):
                continue
            if child.type == "body_statement":
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
                "type": BranchType.ELIF.value,
                "condition": cond_text,
                "raw_type": "elsif",
            },
        })
        self._ast_edge(add_edge, parent_pos, pos, AstRole.IFFALSE.value)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Walk body
        body = self._find_child_by_type(node, "body_statement")
        if body:
            ctx_stack.append((pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                                file_path, idx)
            ctx_stack.pop()

    def _walk_else(self, node, add_node, add_edge,
                   ctx_stack, file_path, parent_pos) -> None:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<else>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.ELSE.value,
                "condition": "",
                "raw_type": "else",
            },
        })
        self._ast_edge(add_edge, parent_pos, pos, AstRole.IFFALSE.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)
        ctx_stack.pop()

    # ===================================================================
    # Case / When
    # ===================================================================

    def _walk_case(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # case: "case" value? case_body "end"
        value_node = None
        value_text = "<case>"
        for child in node.children:
            if child.type in ("case", "end", "when", "in"):
                continue
            if child.type == "case_body":
                continue
            if child.type == "case_match":
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
                "type": BranchType.SWITCH.value,
                "condition": value_text,
                "raw_type": "case",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk value
        if value_node is not None:
            val_pos = self._walk_node(value_node, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.CONDITION.value)

        # Walk when clauses
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type == "when":
                self._walk_when(child, add_node, add_edge, ctx_stack,
                                file_path, pos)
            elif child.type == "else":
                self._walk_else(child, add_node, add_edge, ctx_stack,
                                file_path, pos)
        ctx_stack.pop()

        return pos

    def _walk_when(self, node, add_node, add_edge,
                   ctx_stack, file_path, parent_pos) -> None:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<case>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CASE.value,
                "condition": "",
                "raw_type": "when",
            },
        })
        self._ast_edge(add_edge, parent_pos, pos, "case")

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type in ("when", "then", "end"):
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)
        ctx_stack.pop()

    # ===================================================================
    # While / Until
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        cond_node = None
        cond_text = "<while>"
        for child in node.children:
            if child.type in ("while", "until", "do", "end"):
                continue
            if child.type == "body_statement":
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

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Body
        body = self._find_child_by_type(node, "body_statement")
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
    # For
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<for>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOREACH.value,
                "condition": "",
                "raw_type": "for",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk iterator and body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type in ("for", "in", "do", "end"):
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Begin / Rescue / Ensure (exception handling)
    # ===================================================================

    def _walk_begin(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<begin>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TRY.value,
                "condition": "",
                "raw_type": "begin",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))

        has_rescue = False
        has_ensure = False

        for idx, child in enumerate(node.children):
            if child.type in ("begin", "end"):
                continue
            if child.type == "rescue":
                has_rescue = True
                self._walk_rescue(child, add_node, add_edge, ctx_stack,
                                  file_path, pos)
                continue
            if child.type == "ensure":
                has_ensure = True
                self._walk_ensure(child, add_node, add_edge, ctx_stack,
                                  file_path, pos)
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)

        ctx_stack.pop()
        return pos

    def _walk_rescue(self, node, add_node, add_edge,
                     ctx_stack, file_path, parent_pos) -> None:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<rescue>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CATCH.value,
                "condition": "",
                "raw_type": "rescue",
            },
        })
        self._ast_edge(add_edge, parent_pos, pos, AstRole.IFTRUE.value)

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type in ("rescue", "then"):
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)
        ctx_stack.pop()

    def _walk_ensure(self, node, add_node, add_edge,
                     ctx_stack, file_path, parent_pos) -> None:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<ensure>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FINALLY.value,
                "condition": "",
                "raw_type": "ensure",
            },
        })
        self._ast_edge(add_edge, parent_pos, pos, "finally")

        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.children):
            if child.type in ("ensure", "end"):
                continue
            if child.type in _SKIP_TYPES:
                continue
            self._walk_node(child, add_node, add_edge, ctx_stack,
                            file_path, idx)
        ctx_stack.pop()

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
                "type": "return",
                "raw_type": "return",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk return value
        for child in node.children:
            if child.type in ("return", ";"):
                continue
            if child.type in _SKIP_TYPES:
                continue
            val_pos = self._walk_node(child, add_node, add_edge,
                                      ctx_stack, file_path, 0)
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.VALUE.value)
            break

        return pos

    # ===================================================================
    # Call expression (function call / method call)
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int | None:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        # tree-sitter-ruby call: receiver? call_operator identifier argument_list?
        # Determine if it's a method call (with .) or function call
        method_node = self._find_child_by_type(node, "identifier")
        receiver = self._find_child_by_type(node, "receiver")
        call_op = self._find_child_by_type(node, "call_operator")

        method_name = self._text(method_node) if method_node else ""

        # Check for import/mixin calls
        if not receiver and method_name in _IMPORT_CALLS:
            return self._walk_import_call(node, add_node, add_edge,
                                           ctx_stack, file_path, depth)
        if not receiver and method_name in _MIXIN_CALLS:
            return self._walk_mixin_call(node, add_node, add_edge,
                                         ctx_stack, file_path, depth)

        is_method_call = call_op is not None and self._text(call_op).strip() == "."
        op_type = (OperatorType.METHOD_CALL if is_method_call
                   else OperatorType.CALL)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": method_name or "<call>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
                "text": text,
                "raw_type": "call",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk receiver
        if receiver:
            recv_pos = self._walk_node(receiver, add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if recv_pos is not None:
                self._ast_edge(add_edge, pos, recv_pos, AstRole.OPERAND.value)

        # Walk arguments
        args = self._find_child_by_type(node, "argument_list", "arguments")
        if args:
            for a_idx, a in enumerate(args.children):
                if a.type in _SKIP_TYPES or a.type in ("(", ")", ",", "|"):
                    continue
                a_pos = self._walk_node(a, add_node, add_edge,
                                         ctx_stack, file_path, a_idx)
                if a_pos is not None:
                    self._ast_edge(add_edge, pos, a_pos, AstRole.ARG.value)

        # Walk block (do...end / {})
        block = self._find_child_by_type(node, "block", "do_block")
        if block:
            self._walk_node(block, add_node, add_edge, ctx_stack,
                            file_path, depth)

        return pos

    # ===================================================================
    # Import (require/load)
    # ===================================================================

    def _walk_import_call(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        # Extract the import path (first string argument)
        import_path = ""
        args = self._find_child_by_type(node, "argument_list", "arguments")
        if args:
            for child in args.children:
                if child.type in ("string", "string_content", "heredoc"):
                    import_path = self._text(child).strip('"').strip("'")
                    break
                if child.type in ("simple_symbol", "complex_symbol", "symbol"):
                    import_path = self._text(child)
                    break

        method_node = self._find_child_by_type(node, "identifier")
        method_name = self._text(method_node) if method_node else "require"

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": import_path or method_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.REQUIRE.value,
                "source": import_path,
                "raw_type": "require",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if import_path:
            dep_pos = add_node({
                "label": NodeLabel.DEPENDENCY.value,
                "name": import_path,
                "lineno": lineno,
                "language": self.language,
                "attrs": {"source": import_path},
            })
            add_edge({
                "label": EdgeLabel.FRG.value,
                "source": pos,
                "target": dep_pos,
                "attrs": {"type": FrgType.USE.value},
            })

        return pos

    # ===================================================================
    # Mixin (include/extend/prepend)
    # ===================================================================

    def _walk_mixin_call(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        method_node = self._find_child_by_type(node, "identifier")
        method_name = self._text(method_node) if method_node else "include"

        # Extract the module name
        mixin_name = ""
        args = self._find_child_by_type(node, "argument_list", "arguments")
        if args:
            for child in args.children:
                if child.type in ("constant", "identifier"):
                    mixin_name = self._text(child)
                    break

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": mixin_name or method_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.INCLUDE.value,
                "source": mixin_name,
                "raw_type": "mixin",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        return pos

    # ===================================================================
    # Assignment
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # tree-sitter-ruby assignment: left "=" right
        # left can be: identifier, instance_variable, etc.
        left = None
        right = None
        for child in node.children:
            if child.type == "=":
                continue
            if left is None:
                left = child
            elif right is None:
                right = child
                break

        left_text = self._text(left) if left else ""
        text = f"{left_text} = ..."

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "=",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "text": text,
                "raw_type": "assignment",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk left and right
        if left:
            left_pos = self._walk_node(left, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)
        if right:
            right_pos = self._walk_node(right, add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Binary expression
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        text = self._text(node).strip()

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "text": text,
                "raw_type": "binary",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk operands (skip operator nodes)
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            child_pos = self._walk_node(child, add_node, add_edge,
                                          ctx_stack, file_path, idx)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Identifier
    # ===================================================================

    def _walk_identifier(self, node, add_node, file_path) -> int:
        name = self._text(node)
        lineno = self._lineno(node)
        return self._emit_identifier(add_node, name, lineno,
                                     IdentifierType.VARIABLE)

    # ===================================================================
    # Generic emit helpers
    # ===================================================================

    def _emit_const(self, add_node, name, lineno, const_type) -> int:
        return add_node({
            "label": NodeLabel.CONST.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": const_type.value,
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
            },
        })

    def _emit_operator(self, add_node, name, lineno, op_type) -> int:
        return add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type.value,
            },
        })

    # ===================================================================
    # Walk children (generic fallback)
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        any_pos = None
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                  file_path, idx)
            if pos is not None:
                any_pos = pos
        return any_pos
