"""Go AST Normalizer — maps tree-sitter Go AST to UnifiedNode / UnifiedEdge.

Converts Go source parsed by ``tree-sitter-go`` (via ``tree_sitter.Parser``)
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
    MemberAccessType,
    CrgType,
    FrgType,
)

__all__ = ["Normalizer"]

# ---------------------------------------------------------------------------
# tree-sitter Go node type classification
# ---------------------------------------------------------------------------

_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||",
    "+", "-", "*", "/", "%", "=", "!", "!=",
    "->", "<-", ":=", "...", "*&",
    "func", "var", "const", "type", "return", "go", "defer", "select",
    "switch", "case", "default", "for", "if", "else",
    "break", "continue", "fallthrough", "goto",
    "package", "import", "struct", "interface", "map",
    "nil", "true", "false",
    "chan", "send_statement",
})

_LITERAL_TYPES = frozenset({
    "int_literal", "float_literal", "imaginary_literal",
    "interpreted_string_literal", "raw_string_literal",
    "rune_literal",
})

_IDENTIFIER_TYPES = frozenset({
    "identifier", "type_identifier", "field_identifier",
    "package_identifier",
})


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts tree-sitter Go AST output into UnifiedNode / UnifiedEdge lists.

    Usage::

        from tree_sitter import Language, Parser
        import tree_sitter_go as tsgo

        lang = Language(tsgo.language())
        parser = Parser(lang)
        ts_tree = parser.parse(source.encode())

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ts_tree,
            file_path="/path/to/main.go",
            source_content=source,
        )
    """

    language = "go"

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
                if child.type == "package_clause":
                    self._walk_package(child, _add_node, _add_edge, ctx_stack,
                                       file_path, idx)
                elif child.type == "import_declaration":
                    self._walk_import(child, _add_node, _add_edge, ctx_stack,
                                      file_path, idx)
                else:
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

        # ---- Import ---------------------------------------------------
        if ntype == "import_declaration":
            return self._walk_import(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Package --------------------------------------------------
        if ntype == "package_clause":
            return self._walk_package(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Type (struct/interface) ----------------------------------
        if ntype == "type_declaration":
            return self._walk_type_decl(node, add_node, add_edge, ctx_stack,
                                         file_path, depth)

        # ---- Function -------------------------------------------------
        if ntype == "function_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Method --------------------------------------------------
        if ntype == "method_declaration":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                        file_path, depth, is_method=True)

        # ---- Branch: if ----------------------------------------------
        if ntype == "if_statement":
            return self._walk_if(node, add_node, add_edge, ctx_stack,
                                  file_path, depth)

        # ---- Branch: for ---------------------------------------------
        if ntype == "for_statement":
            return self._walk_for(node, add_node, add_edge, ctx_stack,
                                   file_path, depth)

        # ---- Branch: switch ------------------------------------------
        if ntype == "expression_switch_statement":
            return self._walk_switch(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Branch: type switch -------------------------------------
        if ntype == "type_switch_statement":
            return self._walk_switch(node, add_node, add_edge, ctx_stack,
                                      file_path, depth, is_type_switch=True)

        # ---- Branch: select -------------------------------------------
        if ntype == "select_statement":
            return self._walk_select(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- go / defer statement ------------------------------------
        if ntype == "go_statement":
            return self._walk_go_defer(node, add_node, add_edge, ctx_stack,
                                        file_path, depth, op_type="go")

        if ntype == "defer_statement":
            return self._walk_go_defer(node, add_node, add_edge, ctx_stack,
                                        file_path, depth, op_type="defer")

        # ---- Return --------------------------------------------------
        if ntype == "return_statement":
            return self._walk_return(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        # ---- Break / Continue / Goto ---------------------------------
        if ntype in ("break_statement", "continue_statement", "goto_statement"):
            return self._walk_control(node, add_node, add_edge, ctx_stack,
                                       file_path, depth)

        # ---- Variable declarations ------------------------------------
        if ntype == "short_var_declaration":
            return self._walk_var_decl(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        if ntype == "var_declaration":
            return self._walk_var_decl(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        if ntype == "const_declaration":
            return self._walk_var_decl(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Assignments ---------------------------------------------
        if ntype == "assignment_statement":
            return self._walk_assignment(node, add_node, add_edge, ctx_stack,
                                          file_path, depth)

        # ---- Expression statement -------------------------------------
        if ntype == "expression_statement":
            inner = self._find_child_by_type(node, "call_expression",
                                              "send_statement")
            if inner is not None:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Inc / Dec statement --------------------------------------
        if ntype == "inc_statement":
            return self._walk_inc_dec(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, op="++")

        if ntype == "dec_statement":
            return self._walk_inc_dec(node, add_node, add_edge, ctx_stack,
                                       file_path, depth, op="--")

        # ---- Call expression -----------------------------------------
        if ntype == "call_expression":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Binary / Unary expression --------------------------------
        if ntype == "binary_expression":
            return self._walk_binary(node, add_node, add_edge, ctx_stack,
                                      file_path, depth)

        if ntype == "unary_expression":
            return self._walk_unary(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Selector expression (a.b) --------------------------------
        if ntype == "selector_expression":
            return self._walk_selector(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Index expression (a[i]) ----------------------------------
        if ntype == "index_expression":
            return self._walk_index(node, add_node, add_edge, ctx_stack,
                                     file_path, depth)

        # ---- Slice expression (a[i:j]) --------------------------------
        if ntype == "slice_expression":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Composite literal (MyStruct{...}) -----------------------
        if ntype == "composite_literal":
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Func literal (anonymous function) -----------------------
        if ntype == "func_literal":
            return self._walk_function(node, add_node, add_edge, ctx_stack,
                                        file_path, depth, is_literal=True)

        # ---- Literals ------------------------------------------------
        if ntype in _LITERAL_TYPES:
            return self._walk_literal(node, add_node, file_path)

        # ---- Identifiers --------------------------------------------
        if ntype in _IDENTIFIER_TYPES:
            return self._walk_identifier(node, add_node, file_path)

        # ---- Ternary-like (Go has no ternary) ------------------------
        # (no-op, Go doesn't have ternary operator)

        # ---- Parenthesized expression --------------------------------
        if ntype == "parenthesized_expression":
            inner = self._find_child_by_type(node, *[t for t in
                ("binary_expression", "unary_expression", "call_expression",
                 "selector_expression", "identifier", "type_conversion")])
            if inner:
                return self._walk_node(inner, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        # ---- Type conversion -----------------------------------------
        if ntype == "type_conversion":
            return self._walk_call(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

        # ---- Block / statement_list ----------------------------------
        if ntype == "block":
            stmt_list = self._find_child_by_type(node, "statement_list")
            if stmt_list:
                return self._walk_children(stmt_list, add_node, add_edge,
                                            ctx_stack, file_path, 0)
            return None

        # ---- Fallback ------------------------------------------------
        return self._walk_children(node, add_node, add_edge, ctx_stack,
                                    file_path, depth)

    # ===================================================================
    # Package
    # ===================================================================

    def _walk_package(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        pkg_id = self._find_child_by_type(node, "package_identifier")
        name = self._text(pkg_id) if pkg_id else "main"
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": ClassType.CLASS.value,
                "raw_type": "package",
            },
        })
        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Import
    # ===================================================================

    def _walk_import(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        last_pos = None

        # Collect import_spec nodes
        specs = self._find_children_by_type(node, "import_spec")
        if not specs:
            spec_list = self._find_child_by_type(node, "import_spec_list")
            if spec_list:
                specs = self._find_children_by_type(spec_list, "import_spec")

        for spec in specs:
            spec_lineno = self._lineno(spec)
            name_node = self._find_child_by_type(spec, "interpreted_string_literal")
            path = self._text(name_node).strip('"').strip("`") if name_node else ""

            # Check for alias: `alias "path"` or `_ "path"`
            alias_node = self._find_child_by_type(spec, "package_identifier")
            blank_node = self._find_child_by_type(spec, "blank_identifier")
            alias = ""
            if alias_node is not None:
                alias = self._text(alias_node)
            elif blank_node is not None:
                alias = "_"

            import_name = alias if alias else (path or "<import>")

            pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": import_name,
                "lineno": spec_lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.IMPORT.value,
                    "source": path,
                    "raw_type": "ImportDeclaration",
                },
            })
            self._own_edge(add_edge, ctx_stack, pos, depth)

            if path:
                dep_pos = add_node({
                    "label": NodeLabel.DEPENDENCY.value,
                    "name": path,
                    "lineno": spec_lineno,
                    "language": self.language,
                    "attrs": {"source": path},
                })
                add_edge({
                    "label": EdgeLabel.FRG.value,
                    "source": pos,
                    "target": dep_pos,
                    "attrs": {"type": FrgType.IMPORT.value},
                })

            last_pos = pos

        if last_pos is None:
            # Fallback for single import without import_spec
            name_node = self._find_child_by_type(node, "interpreted_string_literal")
            path = self._text(name_node).strip('"') if name_node else ""
            import_name = path or "<import>"

            last_pos = add_node({
                "label": NodeLabel.IMPORT.value,
                "name": import_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": ImportType.IMPORT.value,
                    "source": path,
                    "raw_type": "ImportDeclaration",
                },
            })
            self._own_edge(add_edge, ctx_stack, last_pos, depth)

        return last_pos

    # ===================================================================
    # Type Declaration (struct/interface)
    # ===================================================================

    def _walk_type_decl(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        spec = self._find_child_by_type(node, "type_spec")
        if spec is None:
            return self._walk_children(node, add_node, add_edge, ctx_stack,
                                        file_path, depth)

        type_id = self._find_child_by_type(spec, "type_identifier")
        name = self._text(type_id) if type_id else "<anonymous>"
        lineno = self._lineno(node)

        # Determine class type
        struct_node = self._find_child_by_type(spec, "struct_type")
        iface_node = self._find_child_by_type(spec, "interface_type")

        if struct_node is not None:
            cls_type = ClassType.CLASS.value
        elif iface_node is not None:
            cls_type = ClassType.INTERFACE.value
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
                "raw_type": spec.type,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk struct fields
        if struct_node is not None:
            fields = self._find_children_by_type(struct_node, "field_declaration")
            for f_idx, field in enumerate(fields):
                fname = self._find_child_by_type(field, "field_identifier")
                ftype = self._find_child_by_type(field, "type_identifier")
                if fname is not None:
                    field_pos = add_node({
                        "label": NodeLabel.IDENTIFIER.value,
                        "name": self._text(fname),
                        "lineno": self._lineno(field),
                        "language": self.language,
                        "attrs": {
                            "type": IdentifierType.PROPERTY.value,
                            "go_type": self._text(ftype) if ftype else "",
                            "raw_type": "FieldDeclaration",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.OWN.value,
                        "source": pos,
                        "target": field_pos,
                        "attrs": {"index": f_idx},
                    })

        # Walk interface methods
        if iface_node is not None:
            methods = self._find_children_by_type(iface_node, "method_elem")
            for m_idx, meth in enumerate(methods):
                mname = self._find_child_by_type(meth, "field_identifier")
                if mname is not None:
                    meth_pos = add_node({
                        "label": NodeLabel.FUNCTION.value,
                        "name": self._text(mname),
                        "lineno": self._lineno(meth),
                        "language": self.language,
                        "attrs": {
                            "type": FunctionType.METHOD.value,
                            "raw_type": "InterfaceMethod",
                        },
                    })
                    add_edge({
                        "label": EdgeLabel.OWN.value,
                        "source": pos,
                        "target": meth_pos,
                        "attrs": {"index": m_idx},
                    })

        return pos

    # ===================================================================
    # Function / Method / Lambda
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth,
                       is_method=False, is_literal=False) -> int:
        lineno = self._lineno(node)
        end_lineno = self._end_lineno(node)

        # Name extraction differs for function vs method vs func_literal
        if is_literal:
            name = "<lambda>"
            func_type = FunctionType.FUNCTION.value
        elif is_method:
            # method_declaration: name is field_identifier child
            name_node = self._find_child_by_type(node, "field_identifier")
            name = self._text(name_node) if name_node else "<method>"
            func_type = FunctionType.METHOD.value
        else:
            name_node = self._find_child_by_type(node, "identifier")
            name = self._text(name_node) if name_node else "<anonymous>"
            func_type = FunctionType.FUNCTION.value

        # Parameters
        all_param_lists = self._find_children_by_type(node, "parameter_list")

        if is_method and len(all_param_lists) >= 2:
            # method_declaration: [0]=receiver, [1]=params, [2]=result(if named returns)
            param_list = all_param_lists[1] if len(all_param_lists) >= 2 else all_param_lists[0]
            params = self._find_children_by_type(param_list,
                                                  "parameter_declaration") if param_list else []
        elif not is_method and len(all_param_lists) >= 2:
            # function_declaration with named returns: [0]=params, [1]=result
            param_list = all_param_lists[0]
            params = self._find_children_by_type(param_list,
                                                  "parameter_declaration") if param_list else []
        else:
            param_list = all_param_lists[0] if all_param_lists else None
            params = self._find_children_by_type(param_list,
                                                  "parameter_declaration") if param_list else []

        param_strs = []
        for p in params:
            pname_node = self._find_child_by_type(p, "identifier")
            pname = self._text(pname_node) if pname_node else "?"
            ptype_node = self._find_child_by_type(p, "type_identifier")
            ptype = self._text(ptype_node) if ptype_node else ""
            if not ptype:
                ptr = self._find_child_by_type(p, "pointer_type")
                if ptr:
                    ptype = self._text(ptr)
            param_strs.append(f"{ptype} {pname}" if ptype else pname)

        # Return type
        ret_type = ""
        block_node = self._find_child_by_type(node, "block")
        last_param = all_param_lists[-1] if all_param_lists else None

        if is_method and len(all_param_lists) >= 3:
            # method with named returns: [0]=receiver, [1]=params, [2]=result
            ret_param_list = all_param_lists[2]
            ret_decls = self._find_children_by_type(ret_param_list, "parameter_declaration")
            ret_parts = []
            for rd in ret_decls:
                ptype_node = self._find_child_by_type(rd, "type_identifier")
                if ptype_node:
                    ret_parts.append(self._text(ptype_node))
                else:
                    ptr = self._find_child_by_type(rd, "pointer_type")
                    if ptr:
                        ret_parts.append(self._text(ptr))
            ret_type = ", ".join(ret_parts)
        elif not is_method and len(all_param_lists) >= 2:
            # function with named returns: [0]=params, [1]=result
            ret_param_list = all_param_lists[1]
            ret_decls = self._find_children_by_type(ret_param_list, "parameter_declaration")
            ret_parts = []
            for rd in ret_decls:
                ptype_node = self._find_child_by_type(rd, "type_identifier")
                if ptype_node:
                    ret_parts.append(self._text(ptype_node))
                else:
                    ptr = self._find_child_by_type(rd, "pointer_type")
                    if ptr:
                        ret_parts.append(self._text(ptr))
            ret_type = ", ".join(ret_parts)
        else:
            # Simple return type: type_identifier between last param_list and block
            found_last_param = False
            for child in node.children:
                if child == last_param:
                    found_last_param = True
                    continue
                if found_last_param:
                    if child.type == "block":
                        break
                    if child.type == "type_identifier":
                        ret_type = self._text(child)
                        break

        signature = f"{ret_type} {name}({', '.join(param_strs)})" if ret_type else f"{name}({', '.join(param_strs)})"

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
                "raw_type": node.type,
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
            stmt_list = self._find_child_by_type(block, "statement_list")
            if stmt_list:
                body_offset = len(params)
                for child_idx, child in enumerate(stmt_list.children):
                    if child.type in _SKIP_TYPES:
                        continue
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, body_offset + child_idx)

        ctx_stack.pop()
        return pos

    def _walk_parameter(self, param_node, add_node, file_path) -> int | None:
        if param_node is None:
            return None
        name_node = self._find_child_by_type(param_node, "identifier")
        name = self._text(name_node) if name_node else ""
        if not name:
            return None

        lineno = self._lineno(param_node)
        type_node = self._find_child_by_type(param_node, "type_identifier")
        ptr_node = self._find_child_by_type(param_node, "pointer_type")
        go_type = ""
        if type_node:
            go_type = self._text(type_node)
        elif ptr_node:
            go_type = self._text(ptr_node)

        return add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": IdentifierType.VARIABLE.value,
                "go_type": go_type,
                "file_path": file_path,
            },
        })

    # ===================================================================
    # Branch: IfStatement
    # ===================================================================

    def _walk_if(self, node, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Go if structure: if init; condition { ... } else { ... }
        # init is optional (short_var_declaration)
        # condition is between "if" and "{"
        cond_text = ""
        cond_node = None
        children = node.children

        # Skip "if" keyword, find condition
        found_if = False
        init_node = None
        for child in children:
            if child.type == "if":
                found_if = True
                continue
            if found_if and child.type == "block":
                break
            if found_if:
                # Could be init statement or condition
                if child.type in ("short_var_declaration", "expression_statement"):
                    if cond_node is None and init_node is None:
                        # Might be init, check if there's another expression before block
                        # Actually, try to determine: if there's a binary_expression
                        # child next, this is init; otherwise this is the condition
                        # Simple heuristic: if child has a binary_expression child,
                        # it's likely the condition wrapper
                        inner_expr = self._find_child_by_type(
                            child, "binary_expression", "unary_expression",
                            "call_expression", "selector_expression")
                        if inner_expr:
                            cond_node = inner_expr
                            cond_text = self._text(child)
                        else:
                            init_node = child
                    elif cond_node is None:
                        cond_node = child
                        cond_text = self._text(child)
                elif child.type in ("binary_expression", "unary_expression",
                                    "call_expression", "selector_expression",
                                    "identifier", "parenthesized_expression"):
                    cond_node = child
                    cond_text = self._text(child)

        if not cond_text:
            cond_text = "<if>"

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": cond_text,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": cond_text,
                "raw_type": "IfStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk init
        if init_node is not None:
            init_pos = self._walk_node(init_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if init_pos is not None:
                self._ast_edge(add_edge, pos, init_pos, AstRole.CONDITION.value)

        # Walk condition
        if cond_node is not None:
            cond_pos = self._walk_node(cond_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if cond_pos is not None:
                self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # then block
        then_block = self._find_child_by_type(node, "block")
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if then_block is not None:
            stmt_list = self._find_child_by_type(then_block, "statement_list")
            if stmt_list:
                for idx, child in enumerate(stmt_list.children):
                    if child.type in _SKIP_TYPES:
                        continue
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)

        # else
        else_clause = self._find_child_by_type(node, "else_clause")
        if else_clause is not None:
            # Check for "else if"
            elif_if = self._find_child_by_type(else_clause, "if_statement")
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
                    stmt_list = self._find_child_by_type(else_block, "statement_list")
                    ctx_stack.pop()
                    ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                    if stmt_list:
                        for idx, child in enumerate(stmt_list.children):
                            if child.type in _SKIP_TYPES:
                                continue
                            self._walk_node(child, add_node, add_edge,
                                           ctx_stack, file_path, idx)

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: ForStatement
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Go for has 3 forms:
        # 1. for init; cond; post { }
        # 2. for cond { }
        # 3. for range_var := range iterable { } (for_range)
        for_clause = self._find_child_by_type(node, "for_clause")
        range_clause = self._find_child_by_type(node, "for_range_clause")  # doesn't exist in TS-Go
        block = self._find_child_by_type(node, "block")

        # Detect range for: for _, v := range arr { }
        children = node.children
        is_range = False
        range_text = ""
        for child in children:
            if child.type in ("for_clause", "block", "for"):
                continue
            txt = self._text(child)
            if "range" in txt:
                is_range = True
                range_text = txt

        if is_range:
            node_dict = {
                "label": NodeLabel.BRANCH.value,
                "name": "<for-range>",
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": BranchType.FOREACH.value,
                    "condition": range_text,
                    "raw_type": "ForRangeStatement",
                },
            }
            pos = add_node(node_dict)
        else:
            cond_text = "<for>"
            if for_clause:
                # Get condition (between init and post)
                exprs = self._find_children_by_type(
                    for_clause, "binary_expression", "unary_expression",
                    "identifier", "call_expression")
                if exprs:
                    cond_text = self._text(exprs[-1]) if len(exprs) > 1 else self._text(exprs[0])

            pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": cond_text,
                "lineno": lineno,
                "language": self.language,
                "attrs": {
                    "type": BranchType.FOR.value,
                    "condition": cond_text if cond_text != "<for>" else "",
                    "raw_type": "ForStatement",
                },
            })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk for_clause children
        if for_clause and not is_range:
            for child in for_clause.children:
                if child.type in _SKIP_TYPES:
                    continue
                child_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.CONDITION.value)

        # Body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        if block is not None:
            stmt_list = self._find_child_by_type(block, "statement_list")
            if stmt_list:
                for idx, child in enumerate(stmt_list.children):
                    if child.type in _SKIP_TYPES:
                        continue
                    self._walk_node(child, add_node, add_edge, ctx_stack,
                                   file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: SwitchStatement
    # ===================================================================

    def _walk_switch(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth,
                     is_type_switch=False) -> int:
        lineno = self._lineno(node)

        # Expression switch: switch expr { case val: ... default: ... }
        # Type switch: switch v := expr.(type) { case int: ... }
        # In tree-sitter Go, the subject expression is a direct child
        children = node.children
        subject_text = ""
        subject_node = None

        for child in children:
            if child.type in ("switch", "{", "}"):
                continue
            if child.type in ("expression_case", "default_case",
                              "type_case"):
                break
            if child.type not in _SKIP_TYPES:
                subject_text = self._text(child)
                subject_node = child
                break

        branch_type = BranchType.SWITCH.value
        if is_type_switch:
            branch_type = BranchType.SWITCH.value

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"switch {subject_text}" if subject_text else "<switch>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": branch_type,
                "condition": subject_text,
                "raw_type": "TypeSwitchStatement" if is_type_switch else "SwitchStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk subject
        if subject_node is not None:
            subj_pos = self._walk_node(subject_node, add_node, add_edge,
                                        ctx_stack, file_path, 0)
            if subj_pos is not None:
                self._ast_edge(add_edge, pos, subj_pos, AstRole.CONDITION.value)

        # Walk cases
        c_idx = 0
        for child in children:
            if child.type in ("expression_case", "type_case"):
                # Regular case
                case_name_node = self._find_child_by_type(child, "expression_list")
                if case_name_node is None:
                    case_name = f"<case {c_idx}>"
                else:
                    # Get first expression from list
                    exprs = [c for c in case_name_node.children
                             if c.type not in _SKIP_TYPES]
                    case_name = ", ".join(self._text(e) for e in exprs[:3]) if exprs else f"<case {c_idx}>"

                case_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": case_name,
                    "lineno": self._lineno(child),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.CASE.value,
                        "condition": case_name,
                        "raw_type": "CaseClause",
                    },
                })
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": case_pos,
                    "attrs": {"index": c_idx},
                })

                # Walk case expressions
                if case_name_node is not None:
                    for expr in case_name_node.children:
                        if expr.type not in _SKIP_TYPES:
                            expr_pos = self._walk_node(expr, add_node, add_edge,
                                                       ctx_stack, file_path, 0)
                            if expr_pos is not None:
                                self._ast_edge(add_edge, case_pos, expr_pos,
                                               AstRole.CONDITION.value)

                # Walk case body
                stmt_list = self._find_child_by_type(child, "statement_list")
                if stmt_list:
                    ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
                    for idx, stmt in enumerate(stmt_list.children):
                        if stmt.type in _SKIP_TYPES:
                            continue
                        self._walk_node(stmt, add_node, add_edge, ctx_stack,
                                       file_path, idx)
                    ctx_stack.pop()

                c_idx += 1

            elif child.type == "default_case":
                def_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<default>",
                    "lineno": self._lineno(child),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.DEFAULT.value,
                        "condition": "",
                        "raw_type": "DefaultClause",
                    },
                })
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": def_pos,
                    "attrs": {"index": c_idx},
                })

                stmt_list = self._find_child_by_type(child, "statement_list")
                if stmt_list:
                    ctx_stack.append((def_pos, NodeLabel.BRANCH.value))
                    for idx, stmt in enumerate(stmt_list.children):
                        if stmt.type in _SKIP_TYPES:
                            continue
                        self._walk_node(stmt, add_node, add_edge, ctx_stack,
                                       file_path, idx)
                    ctx_stack.pop()

                c_idx += 1

        return pos

    # ===================================================================
    # Branch: SelectStatement
    # ===================================================================

    def _walk_select(self, node, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<select>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.SWITCH.value,
                "condition": "",
                "raw_type": "SelectStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        c_idx = 0
        for child in node.children:
            if child.type in ("communication_case",):
                case_name = "<case>"
                case_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": case_name,
                    "lineno": self._lineno(child),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.CASE.value,
                        "condition": "",
                        "raw_type": "CommCase",
                    },
                })
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": case_pos,
                    "attrs": {"index": c_idx},
                })

                stmt_list = self._find_child_by_type(child, "statement_list")
                if stmt_list:
                    ctx_stack.append((case_pos, NodeLabel.BRANCH.value))
                    for idx, stmt in enumerate(stmt_list.children):
                        if stmt.type in _SKIP_TYPES:
                            continue
                        self._walk_node(stmt, add_node, add_edge, ctx_stack,
                                       file_path, idx)
                    ctx_stack.pop()

                c_idx += 1

            elif child.type == "default_case":
                def_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<default>",
                    "lineno": self._lineno(child),
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.DEFAULT.value,
                        "condition": "",
                        "raw_type": "DefaultClause",
                    },
                })
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": def_pos,
                    "attrs": {"index": c_idx},
                })

                stmt_list = self._find_child_by_type(child, "statement_list")
                if stmt_list:
                    ctx_stack.append((def_pos, NodeLabel.BRANCH.value))
                    for idx, stmt in enumerate(stmt_list.children):
                        if stmt.type in _SKIP_TYPES:
                            continue
                        self._walk_node(stmt, add_node, add_edge, ctx_stack,
                                       file_path, idx)
                    ctx_stack.pop()

                c_idx += 1

        return pos

    # ===================================================================
    # go / defer statement
    # ===================================================================

    def _walk_go_defer(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth, op_type="go") -> int:
        lineno = self._lineno(node)
        call_node = self._find_child_by_type(node, "call_expression")

        if call_node is None:
            return None

        callee_text = self._text(call_node)
        # Clean up: remove argument list for name
        callee_text = callee_text.split("(")[0] if "(" in callee_text else callee_text

        op_type_val = OperatorType.CALL.value if op_type == "go" else OperatorType.CALL.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{op_type} {callee_text}",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type_val,
                "raw_type": f"{op_type.capitalize()}Statement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk the call expression
        call_pos = self._walk_call(call_node, add_node, add_edge, ctx_stack,
                                   file_path, 0)
        if call_pos is not None:
            self._ast_edge(add_edge, pos, call_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Return
    # ===================================================================

    def _walk_return(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        expr_list = self._find_child_by_type(node, "expression_list")

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "<return>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {"raw_type": "ReturnStatement"},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if expr_list is not None:
            for idx, child in enumerate(expr_list.children):
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
        label_node = self._find_child_by_type(node, "label")
        label_text = self._text(label_node) if label_node else ""
        name = f"<{node.type.replace('_statement', '')}>{label_text}"

        op_type = OperatorType.BREAK.value
        if "continue" in node.type:
            op_type = OperatorType.CONTINUE.value

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
    # Variable declarations
    # ===================================================================

    def _walk_var_decl(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        specs = self._find_children_by_type(node, "var_spec")
        if not specs:
            # short_var_declaration
            expr_lists = self._find_children_by_type(node, "expression_list")
            if len(expr_lists) >= 2:
                names_list = expr_lists[0]
                vals_list = expr_lists[1]

                pos = add_node({
                    "label": NodeLabel.OPERATOR.value,
                    "name": ":=",
                    "lineno": lineno,
                    "language": self.language,
                    "attrs": {
                        "type": OperatorType.ASSIGN.value,
                        "raw_type": "ShortVarDeclaration",
                    },
                })
                self._own_edge(add_edge, ctx_stack, pos, depth)

                # Names
                for idx, child in enumerate(names_list.children):
                    if child.type in _SKIP_TYPES:
                        continue
                    id_pos = self._walk_identifier(child, add_node, file_path)
                    if id_pos is not None:
                        self._ast_edge(add_edge, pos, id_pos, AstRole.LHS.value,
                                       extra={"decl": True})

                # Values
                for idx, child in enumerate(vals_list.children):
                    if child.type in _SKIP_TYPES:
                        continue
                    val_pos = self._walk_node(child, add_node, add_edge,
                                               ctx_stack, file_path, idx)
                    if val_pos is not None:
                        self._ast_edge(add_edge, pos, val_pos, AstRole.RHS.value)
                return pos

            # Fallback: single expression_list
            for child in node.children:
                if child.type not in _SKIP_TYPES:
                    return self._walk_node(child, add_node, add_edge,
                                           ctx_stack, file_path, depth)
            return None

        # var / const declaration with specs
        last_pos = None
        for spec in specs:
            names = self._find_children_by_type(spec, "identifier")
            expr_list = self._find_child_by_type(spec, "expression_list")
            values = expr_list.children if expr_list else []

            for n_idx, name_node in enumerate(names):
                id_pos = self._walk_identifier(name_node, add_node, file_path)
                if id_pos is not None:
                    self._own_edge(add_edge, ctx_stack, id_pos, depth)
                    last_pos = id_pos

                # Value
                val_idx = 0
                for child in (values):
                    if child.type in _SKIP_TYPES:
                        continue
                    if val_idx == n_idx:
                        val_pos = self._walk_node(child, add_node, add_edge,
                                                   ctx_stack, file_path, 0)
                        if val_pos is not None and id_pos is not None:
                            self._ast_edge(add_edge, id_pos, val_pos,
                                           AstRole.VALUE.value)
                        break
                    val_idx += 1

        return last_pos

    # ===================================================================
    # Assignment
    # ===================================================================

    def _walk_assignment(self, node, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # Go assignment: lhs, op (:=, =, +=, etc.), rhs
        children = [c for c in node.children if c.type not in _SKIP_TYPES]

        op_node = None
        op_text = "="
        for c in node.children:
            if c.type in (":=", "=", "+=", "-=", "*=", "/=", "%=",
                          "&=", "|=", "^=", "<<=", ">>=", "&^="):
                op_node = c
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
                "raw_type": "AssignmentStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # lhs and rhs are separated by op
        found_op = False
        for child in node.children:
            if child.type in _SKIP_TYPES:
                continue
            if child == op_node:
                found_op = True
                continue
            if not found_op:
                child_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.LHS.value)
            else:
                child_pos = self._walk_node(child, add_node, add_edge,
                                              ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Inc / Dec
    # ===================================================================

    def _walk_inc_dec(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth, op="++") -> int:
        lineno = self._lineno(node)
        children = [c for c in node.children if c.type not in _SKIP_TYPES]
        name = self._text(children[0]) if children else op

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": f"{name}{op}",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": op,
                "raw_type": "IncDecStatement",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if children:
            self._walk_node(children[0], add_node, add_edge, ctx_stack,
                           file_path, 0)

        return pos

    # ===================================================================
    # Call expression
    # ===================================================================

    def _walk_call(self, node, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)

        # func() is also a call_expression with func_literal as callee
        func_node = None
        arg_list = self._find_child_by_type(node, "argument_list")

        children = [c for c in node.children if c.type not in ("(", ")", ",", "argument_list")]

        if children:
            func_node = children[0]

        callee_text = self._text(func_node) if func_node else "<call>"
        # Strip argument text for name
        callee_text = callee_text.split("(")[0] if "(" in callee_text else callee_text

        # Determine call type
        if func_node and func_node.type == "selector_expression":
            call_type = OperatorType.METHOD_CALL.value
        elif func_node and func_node.type == "func_literal":
            call_type = OperatorType.CALL.value
            callee_text = "<lambda>"
        elif func_node and func_node.type == "type_conversion":
            callee_text = self._text(func_node).split("(")[0]
            call_type = OperatorType.CALL.value
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

        # Walk callee
        if func_node is not None:
            callee_pos = self._walk_node(func_node, add_node, add_edge,
                                          ctx_stack, file_path, 0)
            if callee_pos is not None:
                self._ast_edge(add_edge, pos, callee_pos, AstRole.CALLEE.value)

        # Walk arguments
        if arg_list is not None:
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
            if c.type not in _SKIP_TYPES and c.type not in ("binary_expression",
                "unary_expression", "call_expression", "selector_expression",
                "identifier", "int_literal", "float_literal",
                "interpreted_string_literal", "raw_string_literal", "nil"):
                op_text = self._text(c)
                break

        if not op_text and len(node.children) >= 3:
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
        op_node = None
        for c in node.children:
            if c.type in ("!", "-", "+", "*", "&", "<-"):
                op_node = c
                break

        op_text = self._text(op_node) if op_node else "!"

        # Detect receive operation
        if op_text == "<-":
            name = "<receive>"
            op_type = OperatorType.BINARY_OP.value
        else:
            name = f"{op_text}<expr>"
            op_type = OperatorType.UNARY_OP.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": op_type,
                "operator": op_text,
                "raw_type": "UnaryExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        for child in children:
            if child != op_node:
                child_pos = self._walk_node(child, add_node, add_edge,
                                             ctx_stack, file_path, 0)
                if child_pos is not None:
                    self._ast_edge(add_edge, pos, child_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Selector expression (a.b)
    # ===================================================================

    def _walk_selector(self, node, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = self._lineno(node)
        obj = self._find_child_by_type(node, "identifier")
        field = self._find_child_by_type(node, "field_identifier")

        obj_text = self._text(obj) if obj else ""
        field_text = self._text(field) if field else ""
        full_name = f"{obj_text}.{field_text}" if obj_text and field_text else field_text

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": full_name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.METHOD_CALL.value,
                "raw_type": "SelectorExpression",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if obj is not None:
            obj_pos = self._walk_identifier(obj, add_node, file_path)
            if obj_pos is not None:
                add_edge({
                    "label": EdgeLabel.MEMBER.value,
                    "source": obj_pos,
                    "target": pos,
                    "attrs": {"access_type": MemberAccessType.PROPERTY.value},
                })

        if field is not None:
            field_pos = add_node({
                "label": NodeLabel.IDENTIFIER.value,
                "name": field_text,
                "lineno": self._lineno(field),
                "language": self.language,
                "attrs": {
                    "type": IdentifierType.PROPERTY.value,
                    "raw_type": "FieldIdentifier",
                },
            })
            self._ast_edge(add_edge, pos, field_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Index expression
    # ===================================================================

    def _walk_index(self, node, add_node, add_edge,
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
                "raw_type": "IndexExpression",
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
    # Identifier
    # ===================================================================

    def _walk_identifier(self, node, add_node, file_path) -> int:
        name = self._text(node)
        lineno = self._lineno(node)

        id_type = IdentifierType.VARIABLE.value
        if name == "nil":
            return self._emit_const(add_node, name, lineno, ConstType.CONSTANT)
        if name in ("true", "false"):
            return self._emit_const(add_node, name, lineno, ConstType.BOOLEAN)
        if node.type == "package_identifier":
            id_type = IdentifierType.VARIABLE.value
        elif node.type == "type_identifier":
            id_type = IdentifierType.STATIC.value

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
        if ntype in ("int_literal",):
            const_type = ConstType.NUMBER
        elif ntype in ("float_literal", "imaginary_literal"):
            const_type = ConstType.NUMBER
        elif ntype in ("interpreted_string_literal", "raw_string_literal"):
            const_type = ConstType.STRING
        elif ntype == "rune_literal":
            const_type = ConstType.STRING
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
