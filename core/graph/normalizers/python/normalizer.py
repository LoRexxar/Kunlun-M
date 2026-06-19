"""Python AST Normalizer — maps stdlib ``ast`` module output to UnifiedNode / UnifiedEdge.

Converts Python source parsed by ``ast.parse()`` into the unified intermediate
representation used by the AST graph engine.  Each Python file produces:
  - 1 file node
  - N class/function/import/dependency nodes (top-level declarations)
  - M operator/branch/return/identifier/const nodes (statement/expression level)
  - edges: own, ast, use, member, crg, frg
"""

from __future__ import annotations

import ast
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
# ast node type → classification
# ---------------------------------------------------------------------------

_CLASS_NODES = (ast.ClassDef,)

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)

_BRANCH_NODES = (ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try,
                 ast.ExceptHandler, ast.Match, ast.IfExp)


# ---------------------------------------------------------------------------
# Operator symbol mappings
# ---------------------------------------------------------------------------

_BINOP_SYMBOLS = {
    ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/",
    ast.FloorDiv: "//", ast.Mod: "%", ast.Pow: "**", ast.LShift: "<<",
    ast.RShift: ">>", ast.BitOr: "|", ast.BitXor: "^", ast.BitAnd: "&",
    ast.MatMult: "@",
}

_UNARYOP_SYMBOLS = {
    ast.UAdd: "+", ast.USub: "-", ast.Not: "not", ast.Invert: "~",
}

_AUGASSIGN_SYMBOLS = {
    ast.Add: "+=", ast.Sub: "-=", ast.Mult: "*=", ast.Div: "/=",
    ast.FloorDiv: "//=", ast.Mod: "%=", ast.Pow: "**=", ast.LShift: "<<=",
    ast.RShift: ">>=", ast.BitOr: "|=", ast.BitXor: "^=", ast.BitAnd: "&=",
    ast.MatMult: "@=",
}

_COMPARE_SYMBOLS = {
    ast.Eq: "==", ast.NotEq: "!=",
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
    ast.Is: "is", ast.IsNot: "is not",
    ast.In: "in", ast.NotIn: "not in",
}


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class Normalizer:
    """Converts stdlib ``ast`` module output into UnifiedNode / UnifiedEdge lists.

    Usage::

        norm = Normalizer()
        file_node, nodes, edges = norm.normalize(
            ast_nodes=ast.parse(code),
            file_path="/path/to/file.py",
            source_content="...",
        )
    """

    language = "python"

    def normalize(
        self,
        ast_nodes: ast.Module,
        file_path: str,
        source_content: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        """Convert Python ast.Module to unified graph data.

        Args:
            ast_nodes: ``ast.Module`` from ``ast.parse()``.
            file_path: Absolute path to the Python file.
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
        """Main walker — dispatches to specialised handlers."""
        if ast_node is None:
            return None

        # ---- Attribute → member edge pattern (handled first) ----------
        if isinstance(ast_node, ast.Attribute):
            return self._walk_attribute(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Subscript → operator(CALL) for __getitem__ ----------------
        if isinstance(ast_node, ast.Subscript):
            return self._walk_subscript(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Class ----------------------------------------------------
        if isinstance(ast_node, ast.ClassDef):
            return self._walk_class(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Function / AsyncFunction / Lambda ------------------------
        if isinstance(ast_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self._walk_function(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Lambda):
            return self._walk_lambda(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Import / ImportFrom ---------------------------------------
        if isinstance(ast_node, (ast.Import, ast.ImportFrom)):
            return self._walk_import(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Global / Nonlocal -----------------------------------------
        if isinstance(ast_node, (ast.Global, ast.Nonlocal)):
            return self._walk_global(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Branch nodes ---------------------------------------------
        if isinstance(ast_node, ast.If):
            return self._walk_if(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.IfExp):
            return self._walk_ifexp(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.While):
            return self._walk_while(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, (ast.For, ast.AsyncFor)):
            return self._walk_for(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Try):
            return self._walk_try(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Match):
            return self._walk_match(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        # Match pattern nodes
        if isinstance(ast_node, ast.MatchValue):
            return self._walk_node(
                ast_node.value, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.MatchSingleton):
            # Match True/False/None → emit const node
            name = repr(ast_node.value)
            return self._emit_const(add_node, name=name, lineno=0,
                                   const_type=ConstType.CONSTANT)
        if isinstance(ast_node, ast.MatchStar):
            return self._emit_const(add_node, name="_", lineno=0,
                                   const_type=ConstType.CONSTANT)
        if isinstance(ast_node, ast.MatchAs):
            if ast_node.pattern:
                return self._walk_node(
                    ast_node.pattern, add_node, add_edge, ctx_stack,
                    file_path, depth,
                )
            return self._emit_const(add_node, name="_", lineno=0,
                                   const_type=ConstType.CONSTANT)
        if isinstance(ast_node, ast.MatchOr):
            # Walk first pattern
            if ast_node.patterns:
                return self._walk_node(
                    ast_node.patterns[0], add_node, add_edge, ctx_stack,
                    file_path, depth,
                )
            return None
        if isinstance(ast_node, ast.MatchSequence):
            # Walk first element
            if ast_node.patterns:
                return self._walk_node(
                    ast_node.patterns[0], add_node, add_edge, ctx_stack,
                    file_path, depth,
                )
            return None
        if isinstance(ast_node, ast.MatchMapping):
            return self._walk_children(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.MatchClass):
            return self._walk_children(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Operators -------------------------------------------------
        if isinstance(ast_node, ast.Compare):
            return self._walk_compare(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.BoolOp):
            return self._walk_boolop(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.BinOp):
            return self._walk_binop(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.UnaryOp):
            return self._walk_unaryop(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Assign):
            return self._walk_assign(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.AugAssign):
            return self._walk_augassign(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Call):
            return self._walk_call(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Control flow ---------------------------------------------
        if isinstance(ast_node, ast.Return):
            return self._walk_return(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Raise):
            return self._walk_raise(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Break):
            return self._walk_break(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Continue):
            return self._walk_continue(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Yield):
            return self._walk_yield(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.YieldFrom):
            return self._walk_yield_from(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Await):
            return self._walk_await(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Leaf nodes -----------------------------------------------
        if isinstance(ast_node, ast.Name):
            return self._walk_name(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )
        if isinstance(ast_node, ast.Constant):
            return self._walk_constant(
                ast_node, add_node, add_edge, ctx_stack, file_path, depth,
            )

        # ---- Fallback: walk child fields ------------------------------
        return self._walk_children(
            ast_node, add_node, add_edge, ctx_stack, file_path, depth,
        )

    # ===================================================================
    # Leaf helpers
    # ===================================================================

    def _emit_identifier(self, add_node, name: str, lineno: int,
                         id_type: IdentifierType, file_path: str) -> int:
        pos = add_node({
            "label": NodeLabel.IDENTIFIER.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": id_type.value,
                "file_path": file_path,
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
    # Class
    # ===================================================================

    def _walk_class(self, node: ast.ClassDef, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        pos = add_node({
            "label": NodeLabel.CLASS.value,
            "name": node.name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "fullname": node.name,
                "type": ClassType.CLASS.value,
                "raw_type": "ClassDef",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # CRG edges for bases
        for base in node.bases:
            base_name = self._expr_text(base)
            if base_name:
                parent_pos = add_node({
                    "label": NodeLabel.CLASS.value,
                    "name": base_name,
                    "lineno": 0,
                    "language": self.language,
                    "attrs": {
                        "fullname": base_name,
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
                # Walk the base expression for side effects
                self._walk_node(
                    base, add_node, add_edge, ctx_stack, file_path, 0,
                )

        # Walk decorators → ANNOTATION nodes
        for dec_idx, dec in enumerate(node.decorator_list):
            ann_name = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    ann_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    ann_name = self._expr_text(dec.func)
                else:
                    ann_name = "<decorator>"
            elif isinstance(dec, ast.Name):
                ann_name = dec.id
            elif isinstance(dec, ast.Attribute):
                ann_name = self._expr_text(dec)
            else:
                ann_name = "<decorator>"
            ann_pos = add_node({
                "label": NodeLabel.ANNOTATION.value,
                "name": ann_name,
                "lineno": dec.lineno if hasattr(dec, "lineno") else 0,
                "language": self.language,
                "attrs": {"raw_type": "Decorator"},
            })
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": ann_pos,
                "attrs": {"index": dec_idx},
            })
            # Also walk the decorator expression for deeper analysis
            self._walk_node(dec, add_node, add_edge, ctx_stack, file_path, 0)

        # Push context, walk body
        ctx_stack.append((pos, NodeLabel.CLASS.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Function / AsyncFunction
    # ===================================================================

    def _walk_function(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        name = node.name
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0
        is_async = isinstance(node, ast.AsyncFunctionDef)

        # Build signature
        param_strs = self._build_param_strs(node.args)
        signature = f"{name}({', '.join(param_strs)})"
        if node.returns:
            ret_text = self._expr_text(node.returns)
            signature += f" -> {ret_text}"

        func_type = FunctionType.FUNCTION.value
        raw_type = "AsyncFunctionDef" if is_async else "FunctionDef"

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
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk decorators → ANNOTATION nodes
        for dec_idx, dec in enumerate(node.decorator_list):
            ann_name = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    ann_name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    ann_name = self._expr_text(dec.func)
                else:
                    ann_name = "<decorator>"
            elif isinstance(dec, ast.Name):
                ann_name = dec.id
            elif isinstance(dec, ast.Attribute):
                ann_name = self._expr_text(dec)
            else:
                ann_name = "<decorator>"
            ann_pos = add_node({
                "label": NodeLabel.ANNOTATION.value,
                "name": ann_name,
                "lineno": dec.lineno if hasattr(dec, "lineno") else 0,
                "language": self.language,
                "attrs": {"raw_type": "Decorator"},
            })
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": ann_pos,
                "attrs": {"index": dec_idx},
            })
            # Also walk the decorator expression for deeper analysis
            self._walk_node(dec, add_node, add_edge, ctx_stack, file_path, 0)

        # Push context, walk parameters then body
        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        # Parameters
        params = self._flatten_args(node.args)
        for idx, (pname, pnode) in enumerate(params):
            p_pos = self._walk_parameter(pnode, add_node, file_path, pname)
            if p_pos is not None:
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": p_pos,
                    "attrs": {"index": idx},
                })

        # Body
        body_offset = len(params)
        for child_idx, child in enumerate(node.body):
            self._walk_node(
                child, add_node, add_edge, ctx_stack, file_path,
                body_offset + child_idx,
            )

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Lambda
    # ===================================================================

    def _walk_lambda(self, node: ast.Lambda, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        param_strs = self._build_param_strs(node.args)
        name = f"<lambda>({', '.join(param_strs)})"

        pos = add_node({
            "label": NodeLabel.FUNCTION.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "fullname": name,
                "type": FunctionType.LAMBDA.value,
                "signature": name,
                "file_path": file_path,
                "raw_type": "Lambda",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        ctx_stack.append((pos, NodeLabel.FUNCTION.value))

        params = self._flatten_args(node.args)
        for idx, (pname, pnode) in enumerate(params):
            p_pos = self._walk_parameter(pnode, add_node, file_path, pname)
            if p_pos is not None:
                add_edge({
                    "label": EdgeLabel.OWN.value,
                    "source": pos,
                    "target": p_pos,
                    "attrs": {"index": idx},
                })

        body_offset = len(params)
        self._walk_node(
            node.body, add_node, add_edge, ctx_stack, file_path, body_offset,
        )

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Parameter
    # ===================================================================

    def _walk_parameter(self, param_node: ast.arg, add_node,
                        file_path: str, name: str = "") -> int | None:
        pname = name or param_node.arg
        if not pname:
            return None
        lineno = param_node.lineno if hasattr(param_node, "lineno") else 0
        annotation = self._expr_text(param_node.annotation) if param_node.annotation else ""

        pos = add_node({
            "label": NodeLabel.PARAMETER.value,
            "name": pname,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type_hint": annotation,
                "default_value": "",
            },
        })
        return pos

    def _build_param_strs(self, args: ast.arguments) -> list[str]:
        """Build display strings for function parameters."""
        strs: list[str] = []
        for arg in args.args:
            s = arg.arg
            if arg.annotation:
                s = f"{self._expr_text(arg.annotation)} {s}"
            strs.append(s)
        if args.vararg:
            s = f"*{args.vararg.arg}"
            if args.vararg.annotation:
                s = f"*{self._expr_text(args.vararg.annotation)} {args.vararg.arg}"
            strs.append(s)
        for arg in args.kwonlyargs:
            s = arg.arg
            if arg.annotation:
                s = f"{self._expr_text(arg.annotation)} {s}"
            strs.append(s)
        if args.kwarg:
            s = f"**{args.kwarg.arg}"
            if args.kwarg.annotation:
                s = f"**{self._expr_text(args.kwarg.annotation)} {args.kwarg.arg}"
            strs.append(s)
        return strs

    def _flatten_args(self, args: ast.arguments) -> list[tuple[str, ast.arg]]:
        """Flatten all parameter groups into (name, ast.arg) pairs."""
        result: list[tuple[str, ast.arg]] = []
        for a in args.args:
            result.append((a.arg, a))
        for a in args.posonlyargs:
            result.append((a.arg, a))
        if args.vararg:
            result.append((args.vararg.arg, args.vararg))
        for a in args.kwonlyargs:
            result.append((a.arg, a))
        if args.kwarg:
            result.append((args.kwarg.arg, args.kwarg))
        return result

    # ===================================================================
    # Import / ImportFrom
    # ===================================================================

    def _walk_import(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imp_type = ImportType.FROM_IMPORT
            frg_type = FrgType.FROM_IMPORT
            names_str = ", ".join(a.name for a in node.names)
            name = names_str
            if module:
                name = f"from {module} import {names_str}"
        else:
            module = ""
            imp_type = ImportType.IMPORT
            frg_type = FrgType.IMPORT
            names_str = ", ".join(a.name for a in node.names)
            name = names_str

        pos = add_node({
            "label": NodeLabel.IMPORT.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": imp_type.value,
                "fullname": module or name,
                "module": module,
                "names": [a.name for a in node.names],
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # DEPENDENCY node for file dependency tracking
        dep_modules = [a.name for a in node.names]
        if isinstance(node, ast.ImportFrom) and node.module:
            dep_modules = [node.module]
        for dep_name in dep_modules:
            dep_pos = add_node({
                "label": NodeLabel.DEPENDENCY.value,
                "name": dep_name,
                "lineno": lineno,
                "language": self.language,
                "attrs": {"source": dep_name},
            })
            add_edge({
                "label": EdgeLabel.FRG.value,
                "source": pos,
                "target": dep_pos,
                "attrs": {"type": frg_type.value},
            })

        # Walk individual import names for identifier nodes
        for alias in node.names:
            alias_name = alias.asname or alias.name
            id_pos = self._emit_identifier(
                add_node, name=alias_name, lineno=lineno,
                id_type=IdentifierType.VARIABLE, file_path=file_path,
            )
            add_edge({
                "label": EdgeLabel.AST.value,
                "source": pos,
                "target": id_pos,
                "attrs": {"role": "import_name"},
            })

        return pos

    # ===================================================================
    # Global / Nonlocal
    # ===================================================================

    def _walk_global(self, node, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        last_pos = None
        for idx, name in enumerate(node.names):
            pos = self._emit_identifier(
                add_node, name=name, lineno=lineno,
                id_type=IdentifierType.GLOBAL, file_path=file_path,
            )
            if pos is not None:
                self._own_edge(add_edge, ctx_stack, pos, depth)
                last_pos = pos
        return last_pos

    # ===================================================================
    # Branch: If / Elif / Else
    # ===================================================================

    def _walk_if(self, node: ast.If, add_node, add_edge,
                 ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        condition = self._expr_text(node.test)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<if>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.IF.value,
                "condition": condition,
                "raw_type": "If",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk condition
        cond_pos = self._walk_node(
            node.test, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if cond_pos is not None:
            self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # Walk body (iftrue branch)
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
        ctx_stack.pop()

        # Handle orelse: if it's a single If node → elif chain
        # If it's a list of statements → else
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                # elif chain
                self._walk_elif_chain(pos, node.orelse[0],
                                      add_node, add_edge, ctx_stack, file_path)
            else:
                # else branch — create branch node as ast[iffalse] child of if
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
                # Connect else to if via ast[iffalse]
                self._ast_edge(add_edge, pos, else_pos, AstRole.IFFALSE.value)

                # Walk else body under else branch context
                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                for idx, child in enumerate(node.orelse):
                    self._walk_node(
                        child, add_node, add_edge, ctx_stack, file_path, idx,
                    )
                ctx_stack.pop()

        return pos

    def _walk_elif_chain(self, parent_pos, elif_node, add_node, add_edge,
                         ctx_stack, file_path):
        """Handle Python elif chain (If node in orelse)."""
        elif_cond = self._expr_text(elif_node.test)
        elif_pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": elif_cond,
            "lineno": elif_node.lineno if hasattr(elif_node, "lineno") else 0,
            "language": self.language,
            "attrs": {
                "type": BranchType.ELIF.value,
                "condition": elif_cond,
                "raw_type": "Elif",
            },
        })
        self._ast_edge(add_edge, parent_pos, elif_pos, AstRole.IFFALSE.value)

        # Walk elif body
        ctx_stack.append((elif_pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(elif_node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
        ctx_stack.pop()

        # Handle next elif or else
        if elif_node.orelse:
            if len(elif_node.orelse) == 1 and isinstance(elif_node.orelse[0], ast.If):
                self._walk_elif_chain(elif_pos, elif_node.orelse[0],
                                       add_node, add_edge, ctx_stack, file_path)
            else:
                # else block
                else_pos = add_node({
                    "label": NodeLabel.BRANCH.value,
                    "name": "<else>",
                    "lineno": elif_node.lineno if hasattr(elif_node, "lineno") else 0,
                    "language": self.language,
                    "attrs": {
                        "type": BranchType.ELSE.value,
                        "condition": "",
                        "raw_type": "Else",
                    },
                })
                self._ast_edge(add_edge, elif_pos, else_pos, AstRole.IFFALSE.value)
                ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
                for idx, child in enumerate(elif_node.orelse):
                    self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
                ctx_stack.pop()

    # ===================================================================
    # Branch: Ternary (IfExp)
    # ===================================================================

    def _walk_ifexp(self, node: ast.IfExp, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        condition = self._expr_text(node.test)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<ternary>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TERNARY.value,
                "condition": condition,
                "raw_type": "IfExp",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # condition
        cond_pos = self._walk_node(
            node.test, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if cond_pos is not None:
            self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # body → role=iftrue
        body_pos = self._walk_node(
            node.body, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if body_pos is not None:
            self._ast_edge(add_edge, pos, body_pos, "iftrue")

        # orelse → role=iffalse
        else_pos = self._walk_node(
            node.orelse, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if else_pos is not None:
            self._ast_edge(add_edge, pos, else_pos, "iffalse")

        return pos

    # ===================================================================
    # Branch: While
    # ===================================================================

    def _walk_while(self, node: ast.While, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        condition = self._expr_text(node.test)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": condition or "<while>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.WHILE.value,
                "condition": condition,
                "raw_type": "While",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # condition
        cond_pos = self._walk_node(
            node.test, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if cond_pos is not None:
            self._ast_edge(add_edge, pos, cond_pos, AstRole.CONDITION.value)

        # body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)

        # orelse (else on while)
        if node.orelse:
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
            ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(node.orelse):
                self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, idx,
                )
            ctx_stack.pop()

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: For / AsyncFor
    # ===================================================================

    def _walk_for(self, node, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0
        is_async = isinstance(node, ast.AsyncFor)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<for>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.FOR.value,
                "condition": "",
                "raw_type": "AsyncFor" if is_async else "For",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk target and iter
        target_pos = self._walk_node(
            node.target, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if target_pos is not None:
            self._ast_edge(add_edge, pos, target_pos, AstRole.LHS.value)

        iter_pos = self._walk_node(
            node.iter, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if iter_pos is not None:
            self._ast_edge(add_edge, pos, iter_pos, AstRole.RHS.value)

        # body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)

        # orelse (else on for)
        if node.orelse:
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
            ctx_stack.append((else_pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(node.orelse):
                self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, idx,
                )
            ctx_stack.pop()

        ctx_stack.pop()
        return pos

    # ===================================================================
    # Branch: Try
    # ===================================================================

    def _walk_try(self, node: ast.Try, add_node, add_edge,
                  ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": "<try>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.TRY.value,
                "condition": "",
                "raw_type": "Try",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # try body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)

        # handlers → CATCH nodes
        for h_idx, handler in enumerate(node.handlers):
            catch_pos = self._walk_excepthandler(
                handler, add_node, add_edge, ctx_stack, file_path, h_idx,
            )
            # own edge from try
            add_edge({
                "label": EdgeLabel.OWN.value,
                "source": pos,
                "target": catch_pos,
                "attrs": {"index": len(node.body) + h_idx},
            })

        # orelse
        if node.orelse:
            for idx, child in enumerate(node.orelse):
                self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, idx,
                )

        # finalbody
        if node.finalbody:
            finally_pos = add_node({
                "label": NodeLabel.BRANCH.value,
                "name": "<finally>",
                "lineno": lineno,
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
                "attrs": {"index": len(node.body) + len(node.handlers)},
            })
            ctx_stack.append((finally_pos, NodeLabel.BRANCH.value))
            for idx, child in enumerate(node.finalbody):
                self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, idx,
                )
            ctx_stack.pop()

        ctx_stack.pop()
        return pos

    def _walk_excepthandler(self, node: ast.ExceptHandler, add_node, add_edge,
                            ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        exc_name = ""
        exc_type = self._expr_text(node.type) if node.type else ""
        if node.name:
            exc_name = node.name

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"except {exc_type}" if exc_type else "<except>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CATCH.value,
                "condition": exc_type,
                "exception_name": exc_name,
                "raw_type": "ExceptHandler",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk the exception type expression
        if node.type:
            type_pos = self._walk_node(
                node.type, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if type_pos is not None:
                self._ast_edge(
                    add_edge, pos, type_pos, AstRole.CONDITION.value,
                )

        # Walk exception name as identifier
        if node.name:
            id_pos = self._emit_identifier(
                add_node, name=node.name, lineno=lineno,
                id_type=IdentifierType.VARIABLE, file_path=file_path,
            )
            self._ast_edge(add_edge, pos, id_pos, AstRole.LHS.value)

        # Walk body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Branch: Match / match_case
    # ===================================================================

    def _walk_match(self, node: ast.Match, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        subject = self._expr_text(node.subject)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"match {subject}" if subject else "<match>",
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.MATCH.value,
                "condition": subject,
                "raw_type": "Match",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk subject
        subj_pos = self._walk_node(
            node.subject, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if subj_pos is not None:
            self._ast_edge(add_edge, pos, subj_pos, AstRole.CONDITION.value)

        # Walk cases
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for case_idx, case in enumerate(node.cases):
            self._walk_match_case(
                case, add_node, add_edge, ctx_stack, file_path, case_idx,
            )
        ctx_stack.pop()

        return pos

    def _walk_match_case(self, node: ast.match_case, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pattern_text = self._expr_text(node.pattern)

        pos = add_node({
            "label": NodeLabel.BRANCH.value,
            "name": f"case {pattern_text}" if pattern_text else "<case>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": BranchType.CASE.value,
                "condition": pattern_text,
                "raw_type": "match_case",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk pattern
        if node.pattern:
            pat_pos = self._walk_node(
                node.pattern, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if pat_pos is not None:
                self._ast_edge(add_edge, pos, pat_pos, AstRole.CONDITION.value)

        # Walk guard
        if node.guard:
            guard_pos = self._walk_node(
                node.guard, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if guard_pos is not None:
                self._ast_edge(add_edge, pos, guard_pos, "guard")

        # Walk body
        ctx_stack.append((pos, NodeLabel.BRANCH.value))
        for idx, child in enumerate(node.body):
            self._walk_node(child, add_node, add_edge, ctx_stack, file_path, idx)
        ctx_stack.pop()

        return pos

    # ===================================================================
    # Operators: Compare
    # ===================================================================

    def _walk_compare(self, node: ast.Compare, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        # name must be the operator symbol for analyzer constraint checking
        # full expression text goes in attrs.expr_text
        op_sym = _COMPARE_SYMBOLS.get(type(node.ops[0]), "??") if node.ops else ""
        expr_text = self._expr_text(node) if hasattr(self, '_expr_text') else ""
        # For multi-compare like a < b < c, concatenate
        name_parts = []
        if node.left:
            name_parts.append(self._expr_text(node.left))
        for op in node.ops:
            name_parts.append(_COMPARE_SYMBOLS.get(type(op), "???"))
        if node.comparators:
            name_parts.append(self._expr_text(node.comparators[0]))
        name = op_sym  # Operator symbol, not full expression text
        if not name:
            name = " ".join(name_parts) if name_parts else "?"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": op_sym,
                "raw_type": "Compare",
                "expr_text": expr_text,
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # left
        left_pos = self._walk_node(
            node.left, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if left_pos is not None:
            self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)

        # comparators → RIGHT
        for cmp_idx, comp in enumerate(node.comparators):
            comp_pos = self._walk_node(
                comp, add_node, add_edge, ctx_stack, file_path, cmp_idx,
            )
            if comp_pos is not None:
                self._ast_edge(add_edge, pos, comp_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Operators: BoolOp (And / Or)
    # ===================================================================

    def _walk_boolop(self, node: ast.BoolOp, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        if isinstance(node.op, ast.Or):
            op_sym = "||"
        elif isinstance(node.op, ast.And):
            op_sym = "&&"
        else:
            op_sym = type(node.op).__name__

        name = op_sym  # Operator symbol for analyzer constraint checking

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": op_sym,
                "raw_type": "BoolOp",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # values → LEFT, RIGHT, ...
        for idx, val in enumerate(node.values):
            val_pos = self._walk_node(
                val, add_node, add_edge, ctx_stack, file_path, idx,
            )
            if val_pos is not None:
                role = AstRole.LEFT.value if idx == 0 else AstRole.RIGHT.value
                self._ast_edge(add_edge, pos, val_pos, role)

        return pos

    # ===================================================================
    # Operators: BinOp
    # ===================================================================

    def _walk_binop(self, node: ast.BinOp, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        op_sym = _BINOP_SYMBOLS.get(type(node.op), "?")
        name = op_sym  # Operator symbol, not full expression text

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BINARY_OP.value,
                "operator": op_sym,
                "raw_type": "BinOp",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # left
        left_pos = self._walk_node(
            node.left, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if left_pos is not None:
            self._ast_edge(add_edge, pos, left_pos, AstRole.LEFT.value)

        # right
        right_pos = self._walk_node(
            node.right, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if right_pos is not None:
            self._ast_edge(add_edge, pos, right_pos, AstRole.RIGHT.value)

        return pos

    # ===================================================================
    # Operators: UnaryOp
    # ===================================================================

    def _walk_unaryop(self, node: ast.UnaryOp, add_node, add_edge,
                      ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        op_sym = _UNARYOP_SYMBOLS.get(type(node.op), "?")
        name = op_sym  # Operator symbol

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.UNARY_OP.value,
                "operator": op_sym,
                "raw_type": "UnaryOp",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        operand_pos = self._walk_node(
            node.operand, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if operand_pos is not None:
            self._ast_edge(add_edge, pos, operand_pos, AstRole.OPERAND.value)

        return pos

    # ===================================================================
    # Operators: Assign
    # ===================================================================

    def _walk_assign(self, node: ast.Assign, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        targets_text = ", ".join(self._expr_text(t) for t in node.targets)
        name = f"{targets_text} = ..."

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.ASSIGN.value,
                "raw_type": "Assign",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # targets → LHS
        for t_idx, target in enumerate(node.targets):
            t_pos = self._walk_node(
                target, add_node, add_edge, ctx_stack, file_path, t_idx,
            )
            if t_pos is not None:
                self._ast_edge(add_edge, pos, t_pos, AstRole.LHS.value)

        # value → RHS
        val_pos = self._walk_node(
            node.value, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if val_pos is not None:
            self._ast_edge(add_edge, pos, val_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Operators: AugAssign
    # ===================================================================

    def _walk_augassign(self, node: ast.AugAssign, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        op_sym = _AUGASSIGN_SYMBOLS.get(type(node.op), "?=")
        target_text = self._expr_text(node.target)
        name = f"{target_text} {op_sym} ..."

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AUG_ASSIGN.value,
                "operator": op_sym,
                "raw_type": "AugAssign",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # target → LHS
        target_pos = self._walk_node(
            node.target, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if target_pos is not None:
            self._ast_edge(add_edge, pos, target_pos, AstRole.LHS.value)

        # value → RHS
        val_pos = self._walk_node(
            node.value, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if val_pos is not None:
            self._ast_edge(add_edge, pos, val_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Operators: Call
    # ===================================================================

    def _walk_call(self, node: ast.Call, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        callee_name = ""
        call_type = CgCallType.DIRECT

        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
            op_type = OperatorType.CALL.value
        elif isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr
            call_type = CgCallType.METHOD
            op_type = OperatorType.METHOD_CALL.value
        else:
            callee_name = self._expr_text(node.func) or "<call>"
            op_type = OperatorType.CALL.value

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": callee_name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": op_type,
                "callee": callee_name,
                "raw_type": "Call",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Handle different func types
        if isinstance(node.func, ast.Name):
            # Simple function call → use edge to function
            target_pos = add_node({
                "label": NodeLabel.FUNCTION.value,
                "name": callee_name,
                "lineno": 0,
                "language": self.language,
                "attrs": {
                    "fullname": callee_name,
                    "type": FunctionType.FUNCTION.value,
                    "is_external": True,
                },
            })
            add_edge({
                "label": EdgeLabel.USE.value,
                "source": pos,
                "target": target_pos,
                "attrs": {
                    "call_type": call_type.value,
                    "lineno": lineno,
                },
            })

        elif isinstance(node.func, ast.Attribute):
            # Method call: walk value, create identifier for attr, member edge
            obj_pos = self._walk_node(
                node.func.value, add_node, add_edge, ctx_stack, file_path, 0,
            )
            member_pos = self._emit_identifier(
                add_node, name=callee_name, lineno=lineno,
                id_type=IdentifierType.PROPERTY, file_path=file_path,
            )
            if obj_pos is not None:
                add_edge({
                    "label": EdgeLabel.MEMBER.value,
                    "source": obj_pos,
                    "target": member_pos,
                    "attrs": {
                        "access_type": MemberAccessType.PROPERTY.value,
                    },
                })
            # ast edge from call to member identifier
            self._ast_edge(add_edge, pos, member_pos, AstRole.CALLEE.value)

        else:
            # Walk func expression
            func_pos = self._walk_node(
                node.func, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if func_pos is not None:
                self._ast_edge(add_edge, pos, func_pos, AstRole.CALLEE.value)

        # Walk arguments → ast[role=arg, arg_index=N]
        for idx, arg in enumerate(node.args):
            arg_pos = self._walk_node(
                arg, add_node, add_edge, ctx_stack, file_path, idx,
            )
            if arg_pos is not None:
                self._ast_edge(
                    add_edge, pos, arg_pos, AstRole.ARG.value,
                    {"arg_index": idx},
                )

        # Walk keyword arguments
        for kw_idx, kw in enumerate(node.keywords):
            kw_pos = self._walk_node(
                kw.value, add_node, add_edge, ctx_stack, file_path,
                len(node.args) + kw_idx,
            )
            if kw_pos is not None:
                self._ast_edge(
                    add_edge, pos, kw_pos, AstRole.ARG.value,
                    {"arg_index": len(node.args) + kw_idx, "keyword": kw.arg},
                )

        return pos

    # ===================================================================
    # Attribute → member edge pattern
    # ===================================================================

    def _walk_attribute(self, node: ast.Attribute, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        # Walk the value (object)
        obj_pos = self._walk_node(
            node.value, add_node, add_edge, ctx_stack, file_path, 0,
        )

        # Create identifier for the attribute name
        member_pos = self._emit_identifier(
            add_node, name=node.attr, lineno=lineno,
            id_type=IdentifierType.PROPERTY, file_path=file_path,
        )

        # MEMBER edge from object to attribute
        if obj_pos is not None:
            add_edge({
                "label": EdgeLabel.MEMBER.value,
                "source": obj_pos,
                "target": member_pos,
                "attrs": {
                    "access_type": MemberAccessType.PROPERTY.value,
                },
            })

        return member_pos

    # ===================================================================
    # Subscript → operator(CALL) for __getitem__
    # ===================================================================

    def _walk_subscript(self, node: ast.Subscript, add_node, add_edge,
                        ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        end_lineno = node.end_lineno if hasattr(node, "end_lineno") else 0

        value_text = self._expr_text(node.value)
        name = f"{value_text}[...]"

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": name,
            "lineno": lineno,
            "end_lineno": end_lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CALL.value,
                "callee": "__getitem__",
                "raw_type": "Subscript",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        # Walk value (the object being subscripted)
        val_pos = self._walk_node(
            node.value, add_node, add_edge, ctx_stack, file_path, 0,
        )
        if val_pos is not None:
            self._ast_edge(add_edge, pos, val_pos, AstRole.CALLEE.value)

        # Walk slice/index → ast[role=arg, arg_index=0]
        if node.slice:
            slice_pos = self._walk_node(
                node.slice, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if slice_pos is not None:
                self._ast_edge(
                    add_edge, pos, slice_pos, AstRole.ARG.value,
                    {"arg_index": 0},
                )

        return pos

    # ===================================================================
    # Return
    # ===================================================================

    def _walk_return(self, node: ast.Return, add_node, add_edge,
                     ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.RETURN.value,
            "name": "",
            "lineno": lineno,
            "language": self.language,
            "attrs": {},
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if node.value:
            val_pos = self._walk_node(
                node.value, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Raise
    # ===================================================================

    def _walk_raise(self, node: ast.Raise, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<raise>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.THROW.value,
                "raw_type": "Raise",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if node.exc:
            exc_pos = self._walk_node(
                node.exc, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if exc_pos is not None:
                self._ast_edge(add_edge, pos, exc_pos, AstRole.VALUE.value)

        if node.cause:
            cause_pos = self._walk_node(
                node.cause, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if cause_pos is not None:
                self._ast_edge(add_edge, pos, cause_pos, AstRole.RHS.value)

        return pos

    # ===================================================================
    # Break / Continue
    # ===================================================================

    def _walk_break(self, node: ast.Break, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "break",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.BREAK.value,
                "raw_type": "Break",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    def _walk_continue(self, node: ast.Continue, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "continue",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.CONTINUE.value,
                "raw_type": "Continue",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)
        return pos

    # ===================================================================
    # Yield / YieldFrom
    # ===================================================================

    def _walk_yield(self, node: ast.Yield, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<yield>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "raw_type": "Yield",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if node.value:
            val_pos = self._walk_node(
                node.value, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.VALUE.value)

        return pos

    def _walk_yield_from(self, node: ast.YieldFrom, add_node, add_edge,
                         ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<yield from>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.YIELD.value,
                "raw_type": "YieldFrom",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if node.value:
            val_pos = self._walk_node(
                node.value, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Await
    # ===================================================================

    def _walk_await(self, node: ast.Await, add_node, add_edge,
                    ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        pos = add_node({
            "label": NodeLabel.OPERATOR.value,
            "name": "<await>",
            "lineno": lineno,
            "language": self.language,
            "attrs": {
                "type": OperatorType.AWAIT.value,
                "raw_type": "Await",
            },
        })

        self._own_edge(add_edge, ctx_stack, pos, depth)

        if node.value:
            val_pos = self._walk_node(
                node.value, add_node, add_edge, ctx_stack, file_path, 0,
            )
            if val_pos is not None:
                self._ast_edge(add_edge, pos, val_pos, AstRole.VALUE.value)

        return pos

    # ===================================================================
    # Leaf: Name (identifier)
    # ===================================================================

    def _walk_name(self, node: ast.Name, add_node, add_edge,
                   ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0

        return self._emit_identifier(
            add_node, name=node.id, lineno=lineno,
            id_type=IdentifierType.VARIABLE, file_path=file_path,
        )

    # ===================================================================
    # Leaf: Constant
    # ===================================================================

    def _walk_constant(self, node: ast.Constant, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int:
        lineno = node.lineno if hasattr(node, "lineno") else 0
        value = node.value
        name = repr(value)

        # Determine const type
        if value is None:
            const_type = ConstType.NULL
        elif isinstance(value, bool):
            const_type = ConstType.BOOLEAN
        elif isinstance(value, (int, float, complex)):
            const_type = ConstType.NUMBER
        elif isinstance(value, str):
            const_type = ConstType.STRING
        else:
            const_type = ConstType.CONSTANT

        return self._emit_const(add_node, name=name, lineno=lineno,
                                const_type=const_type)

    # ===================================================================
    # Fallback: walk child fields
    # ===================================================================

    def _walk_children(self, node, add_node, add_edge,
                       ctx_stack, file_path, depth) -> int | None:
        """Walk child fields of unknown node types."""
        for child in ast.iter_child_nodes(node):
            if child is not None:
                self._walk_node(
                    child, add_node, add_edge, ctx_stack, file_path, depth,
                )
        return None

    # ===================================================================
    # Utility: text representation of an expression
    # ===================================================================

    def _expr_text(self, node) -> str:
        """Best-effort text representation of an AST node."""
        if node is None:
            return ""
        if isinstance(node, str):
            return node

        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.Attribute):
            val = self._expr_text(node.value)
            return f"{val}.{node.attr}"
        if isinstance(node, ast.Subscript):
            val = self._expr_text(node.value)
            sl = self._expr_text(node.slice)
            return f"{val}[{sl}]"
        if isinstance(node, ast.Call):
            func = self._expr_text(node.func)
            return f"{func}()"
        if isinstance(node, ast.BinOp):
            l = self._expr_text(node.left)
            r = self._expr_text(node.right)
            op = _BINOP_SYMBOLS.get(type(node.op), "?")
            return f"{l} {op} {r}"
        if isinstance(node, ast.UnaryOp):
            operand = self._expr_text(node.operand)
            op = _UNARYOP_SYMBOLS.get(type(node.op), "?")
            return f"{op}{operand}"
        if isinstance(node, ast.Compare):
            parts = [self._expr_text(node.left)]
            for op, comp in zip(node.ops, node.comparators):
                op_sym = _COMPARE_SYMBOLS.get(type(op), "?")
                parts.append(op_sym)
                parts.append(self._expr_text(comp))
            return " ".join(parts)
        if isinstance(node, ast.BoolOp):
            vals = [self._expr_text(v) for v in node.values]
            if isinstance(node.op, ast.Or):
                return " || ".join(vals)
            else:
                return " && ".join(vals)
        if isinstance(node, ast.IfExp):
            return f"{self._expr_text(node.body)} if {self._expr_text(node.test)} else {self._expr_text(node.orelse)}"
        if isinstance(node, ast.Starred):
            return f"*{self._expr_text(node.value)}"
        if isinstance(node, ast.Lambda):
            args = self._build_param_strs(node.args)
            return f"lambda {', '.join(args)}: ..."
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elts = [self._expr_text(e) for e in node.elts]
            bracket = {
                ast.List: "[]",
                ast.Tuple: "()",
                ast.Set: "{}",
            }.get(type(node), "[]")
            return f"{bracket[0]}{', '.join(elts)}{bracket[1]}"
        if isinstance(node, ast.Dict):
            items = []
            for k, v in zip(node.keys, node.values):
                k_text = self._expr_text(k) if k else "**"
                v_text = self._expr_text(v)
                items.append(f"{k_text}: {v_text}")
            return "{" + ", ".join(items) + "}"
        if isinstance(node, ast.JoinedStr):
            return "f\"...\""
        if isinstance(node, ast.FormattedValue):
            return self._expr_text(node.value)
        if isinstance(node, ast.Slice):
            lower = self._expr_text(node.lower) if node.lower else ""
            upper = self._expr_text(node.upper) if node.upper else ""
            step = self._expr_text(node.step) if node.step else ""
            return f"{lower}:{upper}:{step}".strip(":")
        if isinstance(node, ast.ListComp):
            return "[...]"
        if isinstance(node, ast.SetComp):
            return "{...}"
        if isinstance(node, ast.DictComp):
            return "{...: ...}"
        if isinstance(node, ast.GeneratorExp):
            return "(...)"
        return str(getattr(node, "name", "")) or type(node).__name__
