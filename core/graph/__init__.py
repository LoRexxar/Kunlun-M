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
from core.graph.graph_io import AstGraphIO
from core.graph.graph_pipeline import build_ast_graph
from core.graph.sqlite_index import AstNodeIndex, FileHash

__all__ = [
    "NodeLabel", "EdgeLabel", "UnifiedNode", "UnifiedEdge",
    "ClassType", "FunctionType", "OperatorType", "BranchType",
    "ImportType", "IdentifierType", "ConstType",
    "FrgType", "CgCallType", "AstRole", "DfgType", "CrgType", "MemberAccessType",
    "AstGraphIO", "build_ast_graph", "AstNodeIndex", "FileHash",
]
