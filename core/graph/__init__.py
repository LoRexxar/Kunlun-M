"""AST Graph Engine — unified intermediate representation for multi-language AST analysis."""

from core.graph.node_edge_schema import (
    NodeLabel,
    EdgeLabel,
    UnifiedNode,
    UnifiedEdge,
    # Re-export all type enums for convenience
    ClassType,
    FunctionType,
    OperatorType,
    BranchType,
    ImportType,
    IdentifierType,
    ConstType,
    FrgType,
    CgCallType,
    AstRole,
    DfgType,
    CrgType,
    MemberAccessType,
)

__all__ = [
    "NodeLabel", "EdgeLabel", "UnifiedNode", "UnifiedEdge",
    "ClassType", "FunctionType", "OperatorType", "BranchType",
    "ImportType", "IdentifierType", "ConstType",
    "FrgType", "CgCallType", "AstRole", "DfgType", "CrgType", "MemberAccessType",
]
