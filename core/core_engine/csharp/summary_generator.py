#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    C# 函数摘要生成器
    ~~~~~~~~~~~~~~~~~
    用 tree-sitter 解析 C# 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    KunLun-M
    :license:   MIT
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

# tree-sitter 初始化
import tree_sitter_c_sharp as _tscs
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_CS_TS_LANGUAGE = _TS_Language(_tscs.language())
_ts_parser = _TS_Parser(_CS_TS_LANGUAGE)
_HAS_TREE_SITTER = True

# C# 字面量标识符
_LITERAL_IDENTS = frozenset({"null", "true", "false"})

_MAX_TRACE_DEPTH = 10

# 模块级摘要注册表
_summary_registry: Dict[str, FunctionSummary] = {}


def lookup_summary(func_name: str) -> Optional[FunctionSummary]:
    """Query function summary."""
    result = _summary_registry.get(func_name)
    if result:
        return result
    if "." in func_name:
        short_name = func_name.split(".")[-1]
    else:
        short_name = func_name
    return _summary_registry.get(short_name)


def _node_text(node) -> str:
    """获取 tree-sitter 节点的文本内容。"""
    if node is None:
        return ""
    try:
        return node.text.decode("utf-8", errors="ignore")
    except (AttributeError, UnicodeDecodeError):
        return str(node)


def _is_literal(node) -> bool:
    """判断节点是否为字面量。"""
    if node.type in (
        "integer_literal", "real_literal",
        "string_literal", "character_literal",
        "true", "false", "null",
    ):
        return True
    if node.type == "identifier" and _node_text(node) in _LITERAL_IDENTS:
        return True
    return False


def _extract_param_names(param_list_node) -> List[str]:
    """从 parameter_list 节点提取形参名列表。"""
    names: List[str] = []
    for child in param_list_node.children:
        if child.type == "parameter":
            for sub in child.children:
                if sub.type == "identifier":
                    names.append(_node_text(sub))
                    break
    return names


def _find_assignments(func_body) -> Dict[str, object]:
    """在函数体中收集局部变量声明和赋值的左值 -> 右值节点映射。"""
    assignments: Dict[str, object] = {}

    def _walk(node):
        for child in node.children:
            if child.type == "local_variable_declaration":
                for dc in child.children:
                    if dc.type == "variable_declarator":
                        var_name = ""
                        rhs_node = None
                        for vc in dc.children:
                            if vc.type == "identifier" and not var_name:
                                var_name = _node_text(vc)
                            elif vc.type == "equals_value_clause":
                                for ec in vc.children:
                                    if ec.type not in ("=",):
                                        rhs_node = ec
                                        break
                        if var_name and rhs_node:
                            assignments[var_name] = rhs_node

            elif child.type == "assignment_expression":
                left_node = None
                right_node = None
                found_op = False
                for c in child.children:
                    if c.type in ("=", "+=", "-=", "*=", "/=", "%=",
                                  "&=", "|=", "^=", "<<=", ">>="):
                        found_op = True
                        continue
                    if not found_op and left_node is None:
                        left_node = c
                    elif found_op and right_node is None:
                        right_node = c
                if left_node and right_node:
                    left_text = _node_text(left_node).strip()
                    var_match = left_text.split(".")[-1]
                    assignments[var_match] = right_node

            elif child.type in (
                "if_statement", "for_statement", "foreach_statement",
                "while_statement", "do_statement", "switch_statement",
                "try_statement", "block", "statement_list",
            ):
                _walk(child)

    _walk(func_body)
    return assignments


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    file_lines: List[str],
    func_body=None,
    assignments: Optional[Dict[str, object]] = None,
    visited: Optional[Set[int]] = None,
    depth: int = 0,
) -> dict:
    """从表达式节点反向追踪数据流。"""
    if visited is None:
        visited = set()
    if depth > _MAX_TRACE_DEPTH:
        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }

    node_id = expr_node.id if hasattr(expr_node, "id") else id(expr_node)
    if node_id in visited:
        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }
    visited = visited | {node_id}

    # 1. 字面量
    if _is_literal(expr_node):
        return {
            "origin": _node_text(expr_node),
            "origin_type": "literal",
            "dep_params": [],
            "path": [],
        }

    # 2. identifier
    if expr_node.type == "identifier":
        name = _node_text(expr_node)
        if name in param_names:
            idx = param_names.index(name)
            return {
                "origin": name,
                "origin_type": "param",
                "dep_params": [idx],
                "path": [],
            }
        if assignments and name in assignments and func_body is not None:
            rhs_node = assignments[name]
            result = _trace_dataflow(
                rhs_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            result["path"].append({
                "node": name,
                "type": "assign",
                "line": rhs_node.start_point.row + 1 if hasattr(rhs_node, 'start_point') else 0,
            })
            return result
        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. invocation_expression
    if expr_node.type == "invocation_expression":
        func_node = None
        for child in expr_node.children:
            if child.type in ("identifier", "member_access_expression",
                              "generic_name", "qualified_name"):
                func_node = child
                break
        func_name = _node_text(func_node) if func_node else "<unknown>"

        dep_params: List[int] = []
        if func_node:
            sub = _trace_dataflow(
                func_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))

        arg_flows: List[dict] = []
        for child in expr_node.children:
            if child.type == "argument_list":
                for a in child.children:
                    if a.type in ("(", ")", ","):
                        continue
                    sub = _trace_dataflow(
                        a, param_names, file_lines, func_body, assignments,
                        visited, depth + 1,
                    )
                    dep_params.extend(sub.get("dep_params", []))
                    arg_flows.append(sub)

        # 递归查摘要注册表
        short_name = func_name.split(".")[-1] if "." in func_name else func_name
        callee_summary = _summary_registry.get(short_name)

        if callee_summary and callee_summary.return_flow and depth < _MAX_TRACE_DEPTH:
            expanded_deps: List[int] = []
            for rf in callee_summary.return_flow:
                for callee_param_idx in rf.dep_params:
                    if callee_param_idx < len(arg_flows):
                        expanded_deps.extend(arg_flows[callee_param_idx].get("dep_params", []))
            if expanded_deps:
                all_deps = list(dict.fromkeys(dep_params + expanded_deps))
                return {
                    "origin": func_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{
                        "node": func_name,
                        "type": "call",
                        "line": expr_node.start_point.row + 1 if hasattr(expr_node, 'start_point') else 0,
                    }],
                    "expanded_from": short_name,
                }

        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": func_name,
                "type": "call",
                "line": expr_node.start_point.row + 1 if hasattr(expr_node, 'start_point') else 0,
            }],
        }

    # 4. member_access_expression (obj.prop)
    if expr_node.type == "member_access_expression":
        full_text = _node_text(expr_node)
        dep_params: List[int] = []
        # 提取对象部分
        for child in expr_node.children:
            if child.type in ("identifier", "this", "base",
                              "invocation_expression", "member_access_expression"):
                sub = _trace_dataflow(
                    child, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )
                dep_params.extend(sub.get("dep_params", []))
                break

        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": full_text,
                "type": "member_access",
                "line": expr_node.start_point.row + 1 if hasattr(expr_node, 'start_point') else 0,
            }],
        }

    # 5. binary_expression
    if expr_node.type == "binary_expression":
        left = None
        right = None
        found_op = False
        for child in expr_node.children:
            if child.type in ("==", "!=", ">=", "<=", ">", "<", "&&", "||",
                              "+", "-", "*", "/", "%", "??", "?."):
                found_op = True
                continue
            if not found_op and left is None:
                left = child
            elif found_op and right is None:
                right = child

        dep_params: List[int] = []
        path: List[dict] = []
        for side in (left, right):
            if side is None:
                continue
            sub = _trace_dataflow(
                side, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            if sub.get("path"):
                path.extend(sub["path"])

        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": path,
        }

    # 6. unary_expression
    if expr_node.type == "unary_expression":
        for child in expr_node.children:
            if child.type not in ("-", "!", "~", "+", "++", "--"):
                return _trace_dataflow(
                    child, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )

    # 7. cast_expression
    if expr_node.type == "cast_expression":
        for child in expr_node.children:
            if child.type not in ("(", ")", "identifier", "generic_name",
                                  "predefined_type", "qualified_name"):
                return _trace_dataflow(
                    child, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )

    # 其他情况
    return {
        "origin": _node_text(expr_node),
        "origin_type": "unknown",
        "dep_params": [],
        "path": [],
    }


def _analyze_return_value(
    return_node,
    param_names: List[str],
    func_body,
    file_path: str,
    file_lines: List[str],
    assignments: Optional[Dict[str, object]] = None,
) -> List[ReturnFlowItem]:
    """分析单个 return 语句中每个返回值的数据流。"""
    if assignments is None:
        assignments = {}

    expr_nodes: List[object] = []
    for child in return_node.children:
        if child.type == "return":
            continue
        expr_nodes.append(child)

    items: List[ReturnFlowItem] = []
    for return_index, expr_node in enumerate(expr_nodes):
        result = _trace_dataflow(
            expr_node, param_names, file_lines, func_body, assignments,
        )

        item = ReturnFlowItem(
            order=len(items),
            return_index=return_index,
            origin=result["origin"],
            origin_type=result["origin_type"],
            dep_params=result.get("dep_params", []),
            path=result.get("path", []),
        )
        items.append(item)

    return items


def _process_func_node(
    func_node,
    file_path: str,
    file_lines: List[str],
) -> Optional[FunctionSummary]:
    """处理单个 method_declaration 节点，生成摘要。"""
    func_name = ""
    param_names: List[str] = []
    func_body = None
    is_static = False

    for child in func_node.children:
        if child.type == "identifier" and not func_name:
            func_name = _node_text(child)
        elif child.type == "static":
            is_static = True
        elif child.type == "parameter_list":
            param_names = _extract_param_names(child)
        elif child.type == "block":
            func_body = child

    if not func_name:
        return None

    start_line = func_node.start_point[0] + 1
    end_line = func_node.end_point[0] + 1

    assignments = _find_assignments(func_body) if func_body else {}

    return_items: List[ReturnFlowItem] = []
    if func_body:
        _collect_returns(func_body, param_names, func_body, file_path,
                         file_lines, assignments, return_items)

    return FunctionSummary(
        name=func_name,
        params=param_names,
        line_range=(start_line, end_line),
        return_flow=return_items,
        is_method=not is_static,
    )


def _collect_returns(
    node,
    param_names: List[str],
    func_body,
    file_path: str,
    file_lines: List[str],
    assignments: Dict[str, object],
    result: List[ReturnFlowItem],
) -> None:
    """递归遍历 AST 节点，收集所有 return_statement 的数据流。"""
    for child in node.children:
        if child.type == "return_statement":
            items = _analyze_return_value(
                child, param_names, func_body, file_path, file_lines, assignments,
            )
            result.extend(items)
        elif child.type in (
            "if_statement", "for_statement", "foreach_statement",
            "while_statement", "do_statement", "switch_statement",
            "try_statement", "block", "statement_list",
            "lock_statement", "using_statement", "fixed_statement",
        ):
            _collect_returns(child, param_names, func_body, file_path,
                             file_lines, assignments, result)


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析单个 C# 文件，生成该文件所有函数的摘要。"""
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    if not _HAS_TREE_SITTER or _ts_parser is None:
        logger.debug(f"tree-sitter 不可用，跳过摘要生成: {file_path}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    try:
        tree = _ts_parser.parse(file_content.encode("utf-8"))
    except Exception as e:
        logger.warning(f"解析 C# 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    file_lines = file_content.splitlines()
    root = tree.root_node
    functions: List[FunctionSummary] = []

    def _walk(node):
        for child in node.children:
            if child.type == "method_declaration":
                summary = _process_func_node(child, file_path, file_lines)
                if summary:
                    functions.append(summary)
            elif child.type == "constructor_declaration":
                summary = _process_func_node(child, file_path, file_lines)
                if summary:
                    functions.append(summary)
            elif child.type in ("namespace_declaration", "class_declaration",
                              "struct_declaration", "interface_declaration"):
                _walk(child)

    _walk(root)

    return FileSummary(file=file_path, content_hash=content_hash, functions=functions)


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 C# 文件，生成摘要。"""
    global _summary_registry
    _summary_registry = {}

    summaries: Dict[str, FileSummary] = {}

    for file_path, content in files_dict.items():
        if not file_path.endswith(".cs"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    logger.debug(f"函数摘要生成完成: {len(summaries)} 个文件, {len(_summary_registry)} 个函数")
    return summaries
