"""C/C++ AST Normalizer — maps tree-sitter C AST to UnifiedNode / UnifiedEdge.

Converts C/C++ source parsed by ``tree-sitter-c`` (via ``tree_sitter.Parser``)
into the unified intermediate representation used by the AST graph engine.

tree-sitter C node model (same as Go):
  - ``node.type`` -> str
  - ``node.text`` -> bytes
  - ``node.children`` -> list of child nodes
  - ``node.start_point`` -> (row, col), row is 0-indexed
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
    FrgType,
)

__all__ = ["Normalizer"]

# ---------------------------------------------------------------------------
# tree-sitter C node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||",
    "+", "-", "*", "/", "%", "=", "!", "~",
    "->", "?", ":", "::",
    "...", "#", "<", ">",
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "return", "goto",
    "typedef", "struct", "union", "enum",
    "const", "volatile", "static", "extern", "inline",
    "void", "char", "short", "int", "long", "float", "double",
    "signed", "unsigned", "auto", "register",
    "NULL",  # C NULL is a child of null node
    "\"", "\n",
})

_LITERAL_TYPES = frozenset({
    "number_literal", "string_literal",
    "char_literal", "true", "false",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier", "type_identifier", "field_identifier",
})

# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter C AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_c as tsc

        lang = Language(tsc.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.c",
            source_content=source,
        )
    """

    language = "c"

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
        if node is None:
            return None
        for c in node.children:
            if c.type in types:
                return c
        return None

    def _find_children_by_type(self, node, *types):
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

        # ---- Include ---------------------------------------------------
        if ntype == "preproc_include":
            return self._walk_include(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Type definition / struct ---------------------------------
        if ntype == "type_definition":
            return self._walk_type_def(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Struct/union/enum specifier (standalone) -------------------
        if ntype in ("struct_specifier", "union_specifier", "enum_specifier"):
            return self._walk_struct(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Function definition ---------------------------------------
        if ntype == "function_definition":
            return self._walk_function_def(node, add_node, add_edge, ctx_stack,
                                            file_path, depth)

        # ---- Function declaration (forward decl / typedef) -------------
        if ntype == "declaration" and self._find_child_by_type(
                node, "function_declarator"):
            return self._walk_function_decl(node, add_node, add_edge, ctx_stack,
                                             file_path, depth)

        # ---- Declaration (variable/typedef) ----------------------------
        if ntype == "declaration":
            return self._walk_declaration(node, add_node, add_edge, ctx_stack,
                                           file_path, depth)

        # ---- If statement ----------------------------------------------
        if ntype == "if_statement":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- For statement ---------------------------------------------
        if ntype == "for_statement":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- While / Do-while -----------------------------------------
        if ntype == "while_statement":
            return self._walk_while(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        if ntype == "do_statement":
            return self._walk_do(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Switch ----------------------------------------------------
        if ntype == "switch_statement":
            return self._walk_switch(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Return ---------------------------------------------------
        if ntype == "return_statement":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Break / Continue / Goto ----------------------------------
        if ntype in ("break_statement", "continue_statement", "goto_statement"):
            return self._walk_control(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Expression statement --------------------------------------
        if ntype == "expression_statement":
            inner = self._find_child_by_type(node, "call_expression",
                                              "assignment_expression",
                                              "update_expression",
                                              "binary_expression",
                                              "unary_expression")
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Call expression -------------------------------------------
        if ntype == "call_expression":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Assignment expression ------------------------------------
        if ntype == "assignment_expression":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Binary / Unary expression ---------------------------------
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if ntype == "unary_expression":
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        if ntype == "update_expression":
            return self._walk_update(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Conditional expression (ternary) --------------------------
        if ntype == "conditional_expression":
            return self._walk_ternary(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Subscript expression (a[i]) -----------------------------
        if ntype == "subscript_expression":
            return self._walk_subscript(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Member access (a->b or a.b) -----------------------------
        if ntype in ("member_expression", "field_expression"):
            return self._walk_member(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Cast expression ------------------------------------------
        if ntype == "cast_expression":
            return self._walk_cast(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Sizeof ---------------------------------------------------
        if ntype == "sizeof_expression":
            return self._walk_sizeof(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Pointer dereference / address-of -------------------------
        if ntype == "pointer_expression":
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Compound literal -----------------------------------------
        if ntype == "compound_literal":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Compound statement ----------------------------------------
        if ntype == "compound_statement":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Null (NULL constant) --------------------------------------
        if ntype == "null":
            return self._emit_const(add_node, "NULL",
                                    self._lineno(node), ConstType.NULL)

        # ---- Literals -------------------------------------------------
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # ---- Identifiers ----------------------------------------------
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, file_path)

        # ---- Parenthesized expression ----------------------------------
        if ntype == "parenthesized_expression":
            inner = self._find_child_by_type(node, *[t for t in (
                "binary_expression", "unary_expression", "call_expression",
                "assignment_expression", "conditional_expression",
                "cast_expression", "identifier", "member_expression")])
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Fallback -------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Include (#include)
    # ===================================================================

    def _walk_include(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        # tree-sitter C: preproc_include > system_lib_string | string_literal
        sys_str = self._find_child_by_type(node, "system_lib_string")
        lit_str = self._find_child_by_type(node, "string_literal")

        if sys_str:
            path = self._text(sys_str).strip("<>").strip('"')
        elif lit_str:
            path = self._text(lit_str).strip('"')
        else:
            path = ""

        import_name = path or "<include>"
        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": import_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": ImportType.INCLUDE.value,
                "source": path,
                "raw_type": "PreprocInclude",
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
                "attrs": {"type": FrgType.INCLUDE.value},
            })

        return pos

    # ===================================================================
    # Type Definition (typedef)
    # ===================================================================

    def _walk_type_def(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        # typedef struct { ... } Name;
        # typedef ... Name;
        type_id = self._find_child_by_type(node, "type_identifier")
        name = self._text(type_id) if type_id else "<typedef>"

        struct_node = self._find_child_by_type(node, "struct_specifier")
        union_node = self._find_child_by_type(node, "union_specifier")
        enum_node = self._find_child_by_type(node, "enum_specifier")

        if struct_node:
            cls_type = ClassType.STRUCT.value
        elif union_node:
            cls_type = ClassType.STRUCT.value
        elif enum_node:
            cls_type = ClassType.ENUM.value
        else:
            cls_type = ClassType.CLASS.value

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": cls_type,
                "raw_type": "TypeDefinition",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk struct/union/enum fields
        for spec_node in (struct_node, union_node, enum_node):
            if spec_node is not None:
                fields = self._find_children_by_type(
                    spec_node, "field_declaration")
                for f_idx, field in enumerate(fields):
                    fname = self._find_child_by_type(field, "field_identifier",
                                                      "identifier")
                    if fname:
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
    # Struct specifier (standalone, not in typedef)
    # ===================================================================

    def _walk_struct(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        type_id = self._find_child_by_type(node, "type_identifier")
        name = self._text(type_id) if type_id else "<anonymous_struct>"

        cls_type = ClassType.STRUCT.value
        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": cls_type,
                "raw_type": node.type,
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        fields = self._find_children_by_type(node, "field_declaration")
        for f_idx, field in enumerate(fields):
            fname = self._find_child_by_type(field, "field_identifier",
                                              "identifier")
            if fname:
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
    # Function definition
    # ===================================================================

    def _walk_function_def(self, node, add_node, add_edge,
                           ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        # function_definition: type function_declarator compound_statement
        func_decl = self._find_child_by_type(node, "function_declarator")
        body = self._find_child_by_type(node, "compound_statement")

        # Name
        name = "<func>"
        if func_decl:
            name_node = self._find_child_by_type(func_decl, "identifier")
            name = self._text(name_node) if name_node else "<func>"

        # Return type: first child before function_declarator
        ret_type = ""
        for child in node.children:
            if child == func_decl:
                break
            if child.type in ("primitive_type", "type_identifier"):
                ret_type = self._text(child)
                break

        # Parameters
        params = []
        if func_decl:
            param_list = self._find_child_by_type(func_decl, "parameter_list")
            if param_list:
                params = self._find_children_by_type(param_list,
                                                      "parameter_declaration")

        param_strs = []
        for p in params:
            pname_node = self._find_child_by_type(p, "identifier")
            # Might be wrapped in pointer_declarator or array_declarator
            if not pname_node:
                ptr = self._find_child_by_type(p, "pointer_declarator",
                                                 "array_declarator")
                if ptr:
                    pname_node = self._find_child_by_type(ptr, "identifier")
            # Function pointer params: int (*op)(const char *)
            if not pname_node:
                func_decl = self._find_child_by_type(p, "function_declarator")
                if func_decl:
                    pname_node = self._find_child_by_type(func_decl, "identifier")
                    if not pname_node:
                        paren = self._find_child_by_type(
                            func_decl, "parenthesized_declarator")
                        if paren:
                            pname_node = self._find_child_by_type(
                                paren, "identifier")
                            if not pname_node:
                                ptr2 = self._find_child_by_type(
                                    paren, "pointer_declarator")
                                if ptr2:
                                    pname_node = self._find_child_by_type(
                                        ptr2, "identifier")
            pname = self._text(pname_node) if pname_node else "?"

            ptype_node = self._find_child_by_type(p, "primitive_type",
                                                    "type_identifier")
            ptype = self._text(ptype_node) if ptype_node else ""

            # Check for pointer/array type
            if not ptype:
                ptr = self._find_child_by_type(p, "pointer_declarator")
                if ptr:
                    ptype = self._text(ptr).split("*")[0].strip() + "*"
            param_strs.append(f"{ptype} {pname}" if ptype else pname)

        signature = (f"{ret_type} {name}({', '.join(param_strs)})"
                     if ret_type else f"{name}({', '.join(param_strs)})")

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
                "raw_type": "FunctionDefinition",
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
        if body is not None:
            body_offset = len(params)
            for child_idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, body_offset + child_idx)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Function declaration (forward decl)
    # ===================================================================

    def _walk_function_decl(self, node, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        func_decl = self._find_child_by_type(node, "function_declarator")
        name = "<func>"
        if func_decl:
            name_node = self._find_child_by_type(func_decl, "identifier")
            name = self._text(name_node) if name_node else "<func>"

        ret_type = ""
        for child in node.children:
            if child.type in ("primitive_type", "type_identifier"):
                ret_type = self._text(child)
                break

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": FunctionType.FUNCTION.value,
                "signature": f"{ret_type} {name}(...)" if ret_type else f"{name}(...)",
                "file_path": file_path,
                "raw_type": "FunctionDeclaration",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Variable declaration
    # ===================================================================

    def _walk_declaration(self, node, add_node, add_edge,
                          ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # declaration: type init_declarator [, init_declarator ...] ;
        # init_declarator: identifier [= expr]
        declarators = self._find_children_by_type(node, "init_declarator",
                                                    "pointer_declarator")
        init_decls = self._find_children_by_type(node, "init_declarator")

        if not init_decls:
            # Might be just: type identifier ;
            idents = self._find_children_by_type(node, "identifier",
                                                  "array_declarator")
            type_node = self._find_child_by_type(node, "primitive_type",
                                                    "type_identifier")
            last_pos = None
            for id_node in idents:
                # array_declarator 的文本是整个 "cmd[256]"，需要深入到
                # 其内部 identifier 子节点，否则后续引用 "cmd" 时同变量
                # 匹配失败导致 DFG 断裂。
                if id_node.type == "array_declarator":
                    inner_ident = self._find_child_by_type(
                        id_node, "identifier")
                    if inner_ident is None:
                        continue
                    id_pos = self._walk_identifier(
                        inner_ident, add_node, file_path)
                else:
                    id_pos = self._walk_identifier(id_node, add_node, file_path)
                if id_pos is not None:
                    self._own_edge(add_edge, ctx_stack, id_pos, depth)
                    last_pos = id_pos
            return last_pos

        last_pos = None
        for decl in init_decls:
            # init_declarator > identifier [= expr]
            # Check function pointer first (nested identifier inside
            # function_declarator > parenthesized_declarator > pointer_declarator)
            # to avoid matching the RHS identifier instead
            func_decl = self._find_child_by_type(decl, "function_declarator")
            if func_decl:
                paren_decl = self._find_child_by_type(
                    func_decl, "parenthesized_declarator")
                if not paren_decl:
                    paren_decl = func_decl
                name_node = None
                if paren_decl:
                    ptr = self._find_child_by_type(
                        paren_decl, "pointer_declarator")
                    if ptr:
                        name_node = self._find_child_by_type(
                            ptr, "identifier")
                    if not name_node:
                        name_node = self._find_child_by_type(
                            paren_decl, "identifier")
            else:
                name_node = self._find_child_by_type(decl, "identifier")
                # Might be pointer_declarator > identifier
                # or pointer_declarator > array_declarator > identifier
                if not name_node:
                    ptr = self._find_child_by_type(
                        decl, "pointer_declarator", "array_declarator")
                    if ptr:
                        name_node = self._find_child_by_type(ptr, "identifier")
                        # Handle nested: pointer_declarator > array_declarator > identifier
                        if not name_node:
                            arr = self._find_child_by_type(ptr, "array_declarator")
                            if arr:
                                name_node = self._find_child_by_type(arr, "identifier")

            id_pos = None
            if name_node:
                id_pos = self._walk_identifier(name_node, add_node, file_path)
                if id_pos is not None:
                    self._own_edge(add_edge, ctx_stack, id_pos, depth)
                    last_pos = id_pos

            # Check for initializer (= expr or = initializer_list)
            # In tree-sitter C, = and expr are siblings of identifier
            found_eq = False
            for child in decl.children:
                if child.type == "=":
                    found_eq = True
                    continue
                if found_eq and child.type not in _SKIP_TYPES:
                    # initializer_list: walk all elements and create DFG
                    # edges from each to the declared variable, so taint can
                    # flow from initializer elements (e.g. argv[1]) into
                    # the declared array variable.  Also keep an ast[value]
                    # edge to the last element for backward compatibility.
                    if child.type == "initializer_list":
                        last_pos = None
                        for init_child in child.children:
                            if init_child.type in _SKIP_TYPES:
                                continue
                            val_pos = self._walk_node(
                                init_child, add_node, add_edge,
                                ctx_stack, file_path, 0)
                            if val_pos is not None:
                                last_pos = val_pos
                                if id_pos is not None:
                                    add_edge({
                                        "label": "dfg",
                                        "source": val_pos,
                                        "target": id_pos,
                                        "attrs": {"type": "initializer"},
                                    })
                        # Keep ast[value] to last element for backward compat
                        if last_pos is not None and id_pos is not None:
                            self._ast_edge(add_edge, id_pos, last_pos,
                                           AstRole.VALUE.value)
                    else:
                        val_pos = self._walk_node(child, add_node, add_edge,
                                                   ctx_stack, file_path, 0)
                        if val_pos is not None and id_pos is not None:
                            # Function pointer assignment: use assign operator
                            # + LHS/RHS so DFG builder creates forward_slice
                            # edges needed by alias builder for indirect calls
                            if func_decl:
                                eq_pos = add_node({
                                    "label": NodeLabel.OPERATOR.value,
                                    "name": "=",
                                    "lineno": lineno,
                                    "language": self.language,
                                    "attrs": {
                                        "type": OperatorType.ASSIGN.value,
                                        "raw_type": "func_ptr_init",
                                    },
                                })
                                self._own_edge(add_edge, ctx_stack, eq_pos,
                                                depth + 1)
                                self._ast_edge(add_edge, eq_pos, id_pos,
                                               AstRole.LHS.value)
                                self._ast_edge(add_edge, eq_pos, val_pos,
                                               AstRole.RHS.value)
                            else:
                                # Variable initialization: create assign operator
                                # + LHS/RHS so DFG builder creates forward_slice
                                # edges. E.g. int size = atoi(argv[1]) needs
                                # atoi→size DFG to reach malloc(size) sink.
                                eq_pos = add_node({
                                    "label": NodeLabel.OPERATOR.value,
                                    "name": "=",
                                    "lineno": lineno,
                                    "language": self.language,
                                    "attrs": {
                                        "type": OperatorType.ASSIGN.value,
                                        "raw_type": "var_init",
                                    },
                                })
                                self._own_edge(add_edge, ctx_stack, eq_pos,
                                                depth + 1)
                                self._ast_edge(add_edge, eq_pos, id_pos,
                                               AstRole.LHS.value)
                                self._ast_edge(add_edge, eq_pos, val_pos,
                                               AstRole.RHS.value)
                    break

        return last_pos

    # ===================================================================
    # Branch: If
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # if_statement: if parenthesized_expression compound_statement
        #                [else_clause]
        cond_node = self._find_child_by_type(node, "parenthesized_expression")
        then_block = self._find_child_by_type(node, "compound_statement")

        cond_text = ""
        if cond_node:
            # Get inner expression
            inner = self._find_child_by_type(
                cond_node, "binary_expression", "unary_expression",
                "call_expression", "identifier", "member_expression")
            if inner:
                cond_text = self._text(inner)
            else:
                cond_text = self._text(cond_node)

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

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # then block
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if then_block:
            for idx, child in enumerate(then_block.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)

        # else
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause:
            elif_if = self._find_child_by_type(else_clause, "if_statement")
            if elif_if:
                self._walk_if(elif_if, add_node, add_edge, ctx_stack,
                              file_path, depth + 1)
            else:
                else_block = self._find_child_by_type(else_clause,
                                                        "compound_statement")
                if else_block:
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
                    for idx, child in enumerate(else_block.children):
                        if child.type in _SKIP_TYPES:
                            continue
                        self._walk_node(child, add_node, add_edge,
                                       ctx_stack, file_path, idx)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: For
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # C for: for (init; cond; update) body
        cond_text = "<for>"
        cond_node = self._find_child_by_type(
            node, "binary_expression", "unary_expression",
            "identifier", "call_expression")
        if cond_node:
            cond_text = self._text(cond_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": cond_text,
                "raw_type": "ForStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk init, condition, update (skip parenthesized_expression wrapper)
        paren = self._find_child_by_type(node, "parenthesized_expression")
        if paren:
            # Walk children inside parens
            for child in paren.children:
                if child.type in _SKIP_TYPES:
                    continue
                child_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos,
                                   AstRole.CONDITION.value)
        else:
            # Walk non-body children
            body = self._find_child_by_type(node, "compound_statement")
            for child in node.children:
                if child == body or child.type in _SKIP_TYPES:
                    continue
                child_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos,
                                   AstRole.CONDITION.value)

        # Body
        body = self._find_child_by_type(node, "compound_statement")
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: While
    # ===================================================================

    def _walk_while(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        cond_node = self._find_child_by_type(node, "parenthesized_expression")
        cond_text = ""
        if cond_node:
            inner = self._find_child_by_type(
                cond_node, "binary_expression", "unary_expression",
                "call_expression", "identifier")
            if inner:
                cond_text = self._text(inner)
            else:
                cond_text = self._text(cond_node)

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

        if cond_node:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        body = self._find_child_by_type(node, "compound_statement")
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: Do-while
    # ===================================================================

    def _walk_do(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<do>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": "",
                "raw_type": "DoStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        body = self._find_child_by_type(node, "compound_statement")
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if body:
            for idx, child in enumerate(body.children):
                if child.type in _SKIP_TYPES:
                    continue
                self._walk_node(child, add_node, add_edge, ctx_stack,
                               file_path, idx)
        ctx_stack.pop()

        # While condition (after body)
        while_cond = self._find_child_by_type(node, "parenthesized_expression")
        if while_cond:
            cond_pos = self._walk_node(while_cond, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        return pos

    # ===================================================================
    # Branch: Switch
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # switch_statement: switch parenthesized_expression { case_clause... }
        cond_node = self._find_child_by_type(node, "parenthesized_expression")
        subject_text = ""
        if cond_node:
            inner = self._find_child_by_type(
                cond_node, "identifier", "call_expression",
                "binary_expression", "member_expression")
            if inner:
                subject_text = self._text(inner)
            else:
                subject_text = self._text(cond_node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"switch {subject_text}" if subject_text else "<switch>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": subject_text,
                "raw_type": "SwitchStatement",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if cond_node:
            subj_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if subj_pos is not None:
                self._ast_edge(add_edge, pos, subj_pos, AstRole.CONDITION.value)

        # case clauses
        c_idx = 0
        body = self._find_child_by_type(node, "compound_statement")
        if body:
            for child in body.children:
                if child.type == "case_statement":
                    case_text = "<case>"
                    # case: [case value :] statement*
                    case_val = self._find_child_by_type(
                        child, "number_literal", "string_literal",
                        "char_literal", "identifier", "unary_expression")
                    if case_val:
                        case_text = self._text(case_val)

                    is_default = False
                    for c in child.children:
                        if c.type == "default":
                            is_default = True
                            break

                    case_pos = add_node({
                        "label": NodeLabel.BRANCH.value,
                        "name": "<default>" if is_default else case_text,
                        "lineno": self._lineno(child),
                        "language": self.language,
                        "attrs": {
                            "type": BranchType.DEFAULT.value if is_default else BranchType.CASE.value,
                            "condition": "" if is_default else case_text,
                            "raw_type": "CaseClause",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.OWN.value,
                        "source": pos,
                        "target": case_pos,
                        "attrs": {"index": c_idx},
                    })

                    if case_val and not is_default:
                        cv_pos = self._walk_node(case_val, add_node, add_edge,
                                                   ctx_stack, file_path, 0)
                        if cv_pos is not None:
                            self._ast_edge(add_edge, case_pos, cv_pos,
                                           AstRole.CONDITION.value)

                    # Walk case body
                    ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
                    for idx, stmt in enumerate(child.children):
                        if stmt.type in _SKIP_TYPES or stmt.type in (
                                "case", "default", ":", "number_literal",
                                "string_literal", "char_literal",
                                "identifier"):
                            continue
                        if stmt.type not in ("case_statement",):
                            self._walk_node(stmt, add_node, add_edge,
                                           ctx_stack, file_path, idx)
                    ctx_stack.pop()

                    c_idx += 1

                elif child.type == "labeled_statement":
                    # Might contain case inside label
                    inner_case = self._find_child_by_type(child, "case_statement")
                    if inner_case:
                        # Walk the case inside
                        pass

        return pos

    # ===================================================================
    # Return
    # ===================================================================

    def _walk_return(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "<return>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {"raw_type": "ReturnStatement"},
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Return value(s)
        for idx, child in enumerate(node.children):
            if child.type in _SKIP_TYPES:
                continue
            expr_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, idx)
            if expr_pos is not None:
                self._ast_edge(add_edge, pos, expr_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Control: break / continue / goto
    # ===================================================================

    def _walk_control(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        label_node = self._find_child_by_type(node, "identifier")
        label_text = self._text(label_node) if label_node else ""
        name = f"<{node.type.replace('_statement', '')}>{label_text}"

        op_type = OperatorType.BREAK.value
        if "continue" in node.type:
            op_type = OperatorType.CONTINUE.value
        elif "goto" in node.type:
            op_type = OperatorType.GOTO.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {"type": op_type, "raw_type": node.type},
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Call expression
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        func_node = self._find_child_by_type(
            node, "identifier", "field_expression", "member_expression",
            "subscript_expression", "parenthesized_expression",
            "call_expression", "pointer_expression",
            "cast_expression")
        arg_list = self._find_child_by_type(node, "argument_list")

        callee_text = self._text(func_node) if func_node else "<call>"
        callee_text = callee_text.split("(")[0].strip() if "(" in callee_text else callee_text

        if func_node and func_node.type in ("field_expression",
                                              "member_expression"):
            call_type = OperatorType.METHOD_CALL.value
        else:
            call_type = OperatorType.CALL.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": call_type,
                "raw_type": "CallExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if func_node:
            callee_pos = self._walk_node(func_node, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if callee_pos is not None:
                self._ast_edge(add_edge, pos, callee_pos, AstRole.CALLEE.value)

        if arg_list:
            arg_idx = 0
            for child in arg_list.children:
                if child.type in _SKIP_TYPES:
                    continue
                arg_pos = self._walk_node(child, add_node, add_edge,
                                            ctx_stack, file_path, arg_idx)
                if arg_pos is not None:
                    self._ast_edge(add_edge, pos, arg_pos, AstRole.ARG.value,
                                   extra={"arg_index": arg_idx})
                arg_idx += 1

        # use edge to function (callee target, may be external)
        if callee_text and isinstance(callee_text, str) and callee_text != "<call>":
            func_name = callee_text.rsplit(".", 1)[-1]
            if "::" in func_name:
                func_name = func_name.rsplit("::", 1)[-1]
            if "static" in call_type:
                cg_call_type = CgCallType.STATIC
            elif call_type == OperatorType.METHOD_CALL.value:
                cg_call_type = CgCallType.METHOD
            else:
                cg_call_type = CgCallType.DIRECT
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": func_name,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": callee_text,
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
    # Assignment expression
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # assignment_expression: left = right
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        op_text = "="
        for c in node.children:
            if c.type in ("=", "+=", "-=", "*=", "/=", "%=",
                          "&=", "|=", "^=", "<<=", ">>="):
                op_text = self._text(c)
                break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "operator": op_text,
                "raw_type": "AssignmentExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if len(children) >= 2:
            left_pos = self._walk_node(children[0], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LHS.value)
            right_pos = self._walk_node(children[-1], add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Binary expression
    # ===================================================================

    def _walk_binary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]

        op_text = ""
        for c in node.children:
            if c.type not in ("binary_expression", "unary_expression",
                              "call_expression", "identifier",
                              "number_literal", "string_literal",
                              "char_literal", "null",
                              "member_expression", "field_expression",
                              "subscript_expression", "cast_expression",
                              "parenthesized_expression",
                              "conditional_expression",
                              "pointer_expression"):
                op_text = self._text(c)
                break

        if not op_text and len(children) >= 3:
            op_text = self._text(node.children[len(node.children) // 2])

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": op_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": op_text,
                "raw_type": "BinaryExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if len(children) >= 2:
            left_pos = self._walk_node(children[0], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if left_pos is not None:
                self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)
            right_pos = self._walk_node(children[-1], add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if right_pos is not None:
                self._ast_edge(add_edge, pos, right_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Unary expression
    # ===================================================================

    def _walk_unary(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        op_text = "!"
        for c in node.children:
            if c.type in ("!", "-", "+", "*", "&", "~"):
                op_text = self._text(c)
                break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{op_text}<expr>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": op_text,
                "raw_type": "UnaryExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in children:
            child_pos = self._walk_node(child, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Update expression (i++, i--)
    # ===================================================================

    def _walk_update(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        name = self._text(children[0]) if children else "?"
        op_text = "++"
        for c in node.children:
            if c.type in ("++", "--"):
                op_text = self._text(c)
                break

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{name}{op_text}",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": op_text,
                "raw_type": "UpdateExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if children:
            self._walk_node(children[0], add_node, add_edge, ctx_stack,
                           file_path, 0)

        return pos

    # ===================================================================
    # Ternary expression (cond ? then : else)
    # ===================================================================

    def _walk_ternary(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<ternary>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TERNARY.value,
                "condition": "",
                "raw_type": "ConditionalExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if len(children) >= 3:
            cond_pos = self._walk_node(children[0], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)
            then_pos = self._walk_node(children[1], add_node, add_edge,
                                         ctx_stack, file_path, 0)
            if then_pos is not None:
                self._ast_edge(add_edge, pos, then_pos, AstRole.IFTRUE.value)
            else_pos = self._walk_node(children[2], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if else_pos is not None:
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

        return pos

    # ===================================================================
    # Subscript expression (a[i])
    # ===================================================================

    def _walk_subscript(self, node, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        name = self._text(children[0]) if children else "<index>"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{name}[...]",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "raw_type": "SubscriptExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if len(children) >= 2:
            obj_pos = self._walk_node(children[0], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if obj_pos is not None:
                self._ast_edge(add_edge, pos, obj_pos, AstRole.LEFT.value)
            idx_pos = self._walk_node(children[1], add_node, add_edge,
                                       ctx_stack, file_path, 0)
            if idx_pos is not None:
                self._ast_edge(add_edge, pos, idx_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Member access (a.b / a->b)
    # ===================================================================

    def _walk_member(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # field_expression: expression . identifier
        # member_expression: expression -> identifier
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        obj_text = self._text(children[0]) if children else ""
        field_text = self._text(children[-1]) if len(children) >= 2 else ""

        op = "." if "->" not in self._text(node) else "->"
        full_name = f"{obj_text}{op}{field_text}" if obj_text and field_text else field_text

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": full_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.METHOD_CALL.value,
                "raw_type": "MemberExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        if len(children) >= 2:
            obj_pos = self._walk_node(children[0], add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if obj_pos is not None:
                add_edge({
                    "label": EdgeLabel.MEMBER.value,
                    "source": obj_pos,
                    "target": pos,
                    "attrs": {"access_type": MemberAccessType.PROPERTY.value},
                })

            field_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": field_text,
                "lineno": self._lineno(children[-1]),
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.FIELD.value,
                    "raw_type": "FieldIdentifier",
                },
            })
            self._ast_edge(add_edge, pos, field_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Cast expression
    # ===================================================================

    def _walk_cast(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        type_node = self._find_child_by_type(node, "primitive_type",
                                                "type_identifier")
        cast_type = self._text(type_node) if type_node else ""

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"({cast_type})",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.TYPE_CAST.value,
                "raw_type": "CastExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk the expression being cast
        children = [c for c in node.children
                    if c.type not in _SKIP_TYPES and c != type_node]
        for child in children:
            child_pos = self._walk_node(child, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Sizeof expression
    # ===================================================================

    def _walk_sizeof(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "sizeof",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "raw_type": "SizeofExpression",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)

        children = [c for c in node.children
                    if c.type not in _SKIP_TYPES]
        for child in children:
            child_pos = self._walk_node(child, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if child_pos is not None:
                self._ast_edge(add_edge, pos, child_pos, AstRole.ARG.value)

        return pos

    # ===================================================================
    # Parameter
    # ===================================================================

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        if param_node is None:
            return None
        name_node = self._find_child_by_type(param_node, "identifier")
        if not name_node:
            ptr = self._find_child_by_type(param_node, "pointer_declarator",
                                             "array_declarator")
            if ptr:
                name_node = self._find_child_by_type(ptr, "identifier")
        # Function pointer params: int (*op)(const char *)
        # identifier nested under function_declarator → parenthesized_declarator → pointer_declarator
        if not name_node:
            func_decl = self._find_child_by_type(param_node, "function_declarator")
            if func_decl:
                name_node = self._find_child_by_type(func_decl, "identifier")
                if not name_node:
                    paren = self._find_child_by_type(func_decl,
                                                     "parenthesized_declarator")
                    if paren:
                        name_node = self._find_child_by_type(paren, "identifier")
                        if not name_node:
                            ptr2 = self._find_child_by_type(
                                paren, "pointer_declarator")
                            if ptr2:
                                name_node = self._find_child_by_type(
                                    ptr2, "identifier")
        name = self._text(name_node) if name_node else ""
        if not name:
            return None

        lineno = self._lineno(param_node)
        type_node = self._find_child_by_type(param_node, "primitive_type",
                                                "type_identifier")

        pos = add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "c_type": self._text(type_node) if type_node else "",
                "file_path": file_path,
            },
        })
        return pos

    # ===================================================================
    # Identifier
    # ===================================================================

    def _walk_identifier(self, node, add_node, file_path) -> int:
        name = self._text(node)
        lineno = self._lineno(node)

        id_type = IdentifierType.VARIABLE.value
        if node.type == "type_identifier":
            id_type = IdentifierType.STATIC.value
        elif node.type == "field_identifier":
            id_type = IdentifierType.FIELD.value

        return add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": id_type,
                "raw_type": node.type,
            },
        })

    # ===================================================================
    # Literal
    # ===================================================================

    def _walk_literal(self, node, add_node, file_path) -> int:
        name = self._text(node)
        lineno = self._lineno(node)

        ntype = node.type
        if ntype == "number_literal":
            const_type = ConstType.NUMBER
        elif ntype == "string_literal":
            const_type = ConstType.STRING
        elif ntype == "char_literal":
            const_type = ConstType.STRING
        elif ntype in ("true", "false"):
            const_type = ConstType.BOOLEAN
        else:
            const_type = ConstType.CONSTANT

        return self._emit_const(add_node, name, lineno, const_type)

    def _emit_const(self, add_node, name: str, lineno: int,
                     const_type: ConstType) -> int:
        return add_node({
            "label": NodeLabel.CONST.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {"type": const_type.value},
        })

    # ===================================================================
    # Fallback: walk children
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        if node is None:
            return None
        last_pos = None
        child_depth = 0
        for child in node.children:
            if self._is_skip(child):
                continue
            pos = self._walk_node(child, add_node, add_edge, ctx_stack,
                                 file_path, child_depth)
            if pos is not None:
                last_pos = pos
            child_depth += 1
        return last_pos
