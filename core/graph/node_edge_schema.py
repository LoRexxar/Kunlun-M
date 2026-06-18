"""Unified node/edge schema for the AST graph engine.

Defines 12 node labels, 7 edge labels, and their type enums.
All enums inherit from str, Enum for serialization convenience.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    # Node labels
    "NodeLabel",
    "EdgeLabel",
    # Node type enums
    "ClassType",
    "FunctionType",
    "OperatorType",
    "BranchType",
    "ImportType",
    "IdentifierType",
    "ConstType",
    # Edge type enums
    "FrgType",
    "CgCallType",
    "AstRole",
    "DfgType",
    "CrgType",
    "MemberAccessType",
    # Data classes
    "UnifiedNode",
    "UnifiedEdge",
]


# ---------------------------------------------------------------------------
# Node Labels (12)
# ---------------------------------------------------------------------------

class NodeLabel(str, Enum):
    """Unified AST graph node labels.

    12 core labels covering file, type, function, expression, statement,
    and dependency concepts across all supported languages.
    """

    FILE = "file"
    CLASS = "class"
    FUNCTION = "function"
    PARAMETER = "parameter"
    RETURN = "return"
    IDENTIFIER = "identifier"
    CONST = "const"
    OPERATOR = "operator"
    BRANCH = "branch"
    IMPORT = "import"
    ANNOTATION = "annotation"
    DEPENDENCY = "dependency"


# ---------------------------------------------------------------------------
# Edge Labels (7)
# ---------------------------------------------------------------------------

class EdgeLabel(str, Enum):
    """Unified AST graph edge labels.

    7 core relationship types: file dependency (frg), hierarchy containment
    (own), call graph (cg), AST child (ast), data flow (dfg), class
    relationship (crg), member access (member).
    """

    FRG = "frg"
    OWN = "own"
    CG = "cg"
    AST = "ast"
    DFG = "dfg"
    CRG = "crg"
    MEMBER = "member"


# ---------------------------------------------------------------------------
# Node Type Enums
# ---------------------------------------------------------------------------

class ClassType(str, Enum):
    """Type attribute for ``class`` nodes."""

    CLASS = "class"
    INTERFACE = "interface"
    STRUCT = "struct"
    ENUM = "enum"


class FunctionType(str, Enum):
    """Type attribute for ``function`` nodes."""

    FUNCTION = "function"
    METHOD = "method"
    CONSTRUCTOR = "constructor"
    LAMBDA = "lambda"
    DESTRUCTOR = "destructor"


class OperatorType(str, Enum):
    """Type attribute for ``operator`` nodes (16 types).

    Covers function/variable invocations, assignments, arithmetic/logic
    operations, object instantiation, control transfers, and loop
    interrupts.
    """

    CALL = "call"
    STATIC_CALL = "static_call"
    METHOD_CALL = "method_call"
    ASSIGN = "assign"
    AUG_ASSIGN = "aug_assign"
    BINARY_OP = "binary_op"
    UNARY_OP = "unary_op"
    NEW = "new"
    TYPE_CAST = "type_cast"
    THROW = "throw"
    YIELD = "yield"
    AWAIT = "await"
    BREAK = "break"
    CONTINUE = "continue"
    GOTO = "goto"


class BranchType(str, Enum):
    """Type attribute for ``branch`` nodes (14 types).

    Covers conditional branches, loops, switch/case, try/catch/finally,
    and match expressions.
    """

    IF = "if"
    ELIF = "elif"
    ELSE = "else"
    TERNARY = "ternary"
    FOR = "for"
    WHILE = "while"
    FOREACH = "foreach"
    SWITCH = "switch"
    CASE = "case"
    DEFAULT = "default"
    TRY = "try"
    CATCH = "catch"
    FINALLY = "finally"
    MATCH = "match"


class ImportType(str, Enum):
    """Type attribute for ``import`` nodes."""

    IMPORT = "import"
    FROM_IMPORT = "from_import"
    INCLUDE = "include"
    REQUIRE = "require"
    INCLUDE_ONCE = "include_once"
    REQUIRE_ONCE = "require_once"
    USE = "use"


class IdentifierType(str, Enum):
    """Type attribute for ``identifier`` nodes."""

    VARIABLE = "variable"
    PROPERTY = "property"
    FIELD = "field"
    GLOBAL = "global"
    STATIC = "static"
    SUPER = "super"
    THIS = "this"


class ConstType(str, Enum):
    """Type attribute for ``const`` nodes."""

    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NULL = "null"
    CONSTANT = "constant"


# ---------------------------------------------------------------------------
# Edge Type Enums
# ---------------------------------------------------------------------------

class FrgType(str, Enum):
    """Type attribute for ``frg`` edges."""

    INCLUDE = "include"
    IMPORT = "import"
    FROM_IMPORT = "from_import"
    USE = "use"


class CgCallType(str, Enum):
    """call_type attribute for ``cg`` edges."""

    DIRECT = "direct"
    STATIC = "static"
    METHOD = "method"
    DYNAMIC = "dynamic"


class AstRole(str, Enum):
    """role attribute for ``ast`` edges."""

    LHS = "lhs"
    RHS = "rhs"
    ARG = "arg"
    CALLEE = "callee"
    LEFT = "left"
    RIGHT = "right"
    OPERAND = "operand"
    VALUE = "value"


class DfgType(str, Enum):
    """type attribute for ``dfg`` edges."""

    FORWARD_SLICE = "forward_slice"
    SAME = "same"


class CrgType(str, Enum):
    """type attribute for ``crg`` edges."""

    EXTENDS = "extends"
    IMPLEMENTS = "implements"
    TRAIT = "trait"
    MIXIN = "mixin"


class MemberAccessType(str, Enum):
    """access_type attribute for ``member`` edges."""

    PROPERTY = "property"
    ARRAY_OFFSET = "array_offset"
    STATIC_PROPERTY = "static_property"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class UnifiedNode:
    """AST graph node — unified intermediate representation.

    Attributes:
        label: One of 12 :class:`NodeLabel` values.
        name: Primary display name (file name, function name, variable name, etc.).
        lineno: Start line number in source file.
        end_lineno: End line number (0 if unavailable / not meaningful).
        language: Language identifier (php/javascript/java/python/go/c).
        attrs: Label-specific attributes stored as a flat dict.  Keys vary
            by label (e.g. ``fullname`` for functions, ``condition`` for branches).
    """

    label: NodeLabel
    name: str = ""
    lineno: int = 0
    end_lineno: int = 0
    language: str = ""
    attrs: dict[str, Any] = field(default_factory=dict)

    # Convenience helpers ---------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Get a label-specific attribute with a default."""
        return self.attrs.get(key, default)

    def __repr__(self) -> str:  # pragma: no cover
        short = self.name or "<anon>"
        return f"<{self.label.value}:{short} L{self.lineno}>"


@dataclass
class UnifiedEdge:
    """AST graph edge — unified relationship.

    Attributes:
        label: One of 7 :class:`EdgeLabel` values.
        source: Source vertex index (igraph integer id).
        target: Target vertex index (igraph integer id).
        attrs: Edge-specific attributes stored as a flat dict.  Keys vary
            by label (e.g. ``role`` for ast, ``call_type`` for cg).
    """

    label: EdgeLabel
    source: int
    target: int
    attrs: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Get an edge-specific attribute with a default."""
        return self.attrs.get(key, default)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{self.label.value}: {self.source}->{self.target}>"


# ---------------------------------------------------------------------------
# igraph 1.0 属性访问封装
#
# igraph 1.0 的 Vertex/Edge 没有 dict 风格的 .get() 方法。
# 所有模块统一使用 vattr() 访问属性，禁止直接 v["key"] 访问
# 可能不存在的属性。
# ---------------------------------------------------------------------------

def vattr(vertex_or_edge, key: str, default=None):
    """安全读取 igraph Vertex/Edge 属性，等价于 dict.get(key, default)。

    Usage::

        name = vattr(v, "name", "")
        label = vattr(e, "label", "")

    禁止直接使用 ``vertex_or_edge["key"]`` 访问可能不存在的属性。
    """
    try:
        return vertex_or_edge[key]
    except (KeyError, TypeError):
        return default


# 向后兼容别名
_vattr = vattr
