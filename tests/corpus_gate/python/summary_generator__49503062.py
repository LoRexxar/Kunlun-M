#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Lua 函数摘要生成器
    ~~~~~~~~~~~~~~~~~~~
    用 tree-sitter 解析 Lua 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

# tree-sitter 初始化
import tree_sitter_lua as _tslua
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_LUA_TS_LANGUAGE = _TS_Language(_tslua.language())
_ts_parser = _TS_Parser(_LUA_TS_LANGUAGE)
_HAS_TREE_SITTER = True

_MAX_TRACE_DEPTH = 10

# 模块级摘要注册表，用于跨函数递归分析
_summary_registry: Dict[str, FunctionSummary] = {}


def lookup_summary(func_name: str) -> Optional[FunctionSummary]:
    """Query function summary. Try exact match first, then fallback to short name."""
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
    try:
        return node.text.decode("utf-8")
    except (AttributeError, UnicodeDecodeError):
        return ""


def _is_literal(node) -> bool:
    """判断节点是否为字面量。"""
    if node.type in (
        "number", "string", "true", "false", "nil",
    ):
        return True
    return False


def _extract_param_names(param_node) -> List[str]:
    """从参数列表节点提取形参名列表。"""
    names: List[str] = []
    if param_node is None:
        return names
    for child in param_node.children:
        if child.type == "identifier" or child.type.startswith("identifier"):
            names.append(_node_text(child))
    return names


def _find_assignments(func_body) -> Dict[str, object]:
    """在函数体中收集 local 声明和赋值的映射。"""
    assignments: Dict[str, object] = {}

    def _walk(node):
        for child in node.children:
            if child.type == "local_declaration":
                var_names = []
                init_expr = None
                for c in child.children:
                    if c.type == "identifier":
                        var_names.append(_node_text(c))
                    elif init_expr is None and c.type in (
                        "function_call", "method_call", "assignment",
                        "binary_operation", "unary_operation",
                        "identifier", "table_constructor",
                        "return_statement", "if_statement",
                    ):
                        init_expr = c
                if var_names and init_expr:
                    for vn in var_names:
                        assignments[vn] = init_expr
            elif child.type == "assignment":
                left = None
                right = None
                found_eq = False
                for c in child.children:
                    if c.type == "=":
                        found_eq = True
                        continue
                    if not found_eq and left is None:
                        if c.type == "identifier":
                            left = _node_text(c)
                    elif found_eq and right is None:
                        right = c
                        break
                if left and right:
                    assignments[left] = right
            elif child.type in (
                "if_statement", "while_statement", "for_statement",
                "for_in_statement", "block", "return_statement",
                "function_call", "method_call",
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
                "line": rhs_node.start_point[0] + 1,
            })
            return result
        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. function_call
    if expr_node.type == "function_call":
        children = expr_node.children
        func_node = children[0] if children else None
        func_name = _node_text(func_node) if func_node else "<unknown>"
        dep_params: List[int] = []

        if func_node:
            sub = _trace_dataflow(
                func_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))

        arg_flows: List[dict] = []
        for arg in children[1:]:
            if arg.type in ("(", ")", ","):
                continue
            if arg.type == "arguments":
                for a in arg.children:
                    if a.type in ("(", ")", ","):
                        continue
                    sub = _trace_dataflow(
                        a, param_names, file_lines, func_body, assignments,
                        visited, depth + 1,
                    )
                    dep_params.extend(sub.get("dep_params", []))
                    arg_flows.append(sub)
            else:
                sub = _trace_dataflow(
                    arg, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )
                dep_params.extend(sub.get("dep_params", []))
                arg_flows.append(sub)

        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": func_name,
                "type": "call",
                "line": expr_node.start_point[0] + 1,
            }],
        }

    # 4. method_call (obj:method(args))
    if expr_node.type == "method_call":
        full_text = _node_text(expr_node)
        dep_params: List[int] = []
        method_name = ""
        for c in expr_node.children:
            if c.type == "identifier":
                method_name = _node_text(c)
                break

        # Walk object and arguments
        for child in expr_node.children:
            if child.type in (":", "identifier", "(", ")", ","):
                continue
            if child.type == "arguments":
                for a in child.children:
                    if a.type in ("(", ")", ","):
                        continue
                    sub = _trace_dataflow(
                        a, param_names, file_lines, func_body, assignments,
                        visited, depth + 1,
                    )
                    dep_params.extend(sub.get("dep_params", []))
            else:
                sub = _trace_dataflow(
                    child, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )
                dep_params.extend(sub.get("dep_params", []))

        return {
            "origin": full_text,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": full_text,
                "type": "method_call",
                "line": expr_node.start_point[0] + 1,
            }],
        }

    # 5. binary_operation
    if expr_node.type == "binary_operation":
        dep_params: List[int] = []
        path: List[dict] = []
        op_node = None
        for child in expr_node.children:
            if child.type in ("+", "-", "*", "/", "%", "^", "..",
                              "==", "~=", "<=", ">=", "<", ">",
                              "and", "or", "not", "&", "|", "<<", ">>", "~"):
                if op_node is None:
                    op_node = child
                continue
            sub = _trace_dataflow(
                child, param_names, file_lines, func_body, assignments,
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

    # 6. unary_operation
    if expr_node.type == "unary_operation":
        for child in expr_node.children:
            if child.type in ("-", "not", "#", "~"):
                continue
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
    """处理单个 function_declaration 节点，生成摘要。"""
    func_name = ""
    param_names: List[str] = []
    func_body = None

    for child in func_node.children:
        if child.type == "identifier" and not func_name:
            func_name = _node_text(child)
        elif child.type in ("parameters", "parameter_list"):
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
        receiver_name="",
        is_method=False,
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
            "if_statement", "while_statement", "for_statement",
            "for_in_statement", "block", "function_call", "method_call",
            "local_declaration", "assignment", "do_statement",
            "repeat_statement",
        ):
            _collect_returns(child, param_names, func_body, file_path,
                             file_lines, assignments, result)


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析单个 Lua 文件，生成该文件所有函数的摘要。"""
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    if not _HAS_TREE_SITTER or _ts_parser is None:
        logger.debug(f"tree-sitter 不可用，跳过摘要生成: {file_path}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    try:
        tree = _ts_parser.parse(file_content.encode("utf-8"))
    except Exception as e:
        logger.warning(f"解析 Lua 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    file_lines = file_content.splitlines()
    root = tree.root_node
    functions: List[FunctionSummary] = []

    for child in root.children:
        if child.type == "function_declaration":
            summary = _process_func_node(child, file_path, file_lines)
            if summary:
                functions.append(summary)
        elif child.type in ("local_declaration", "assignment"):
            # Check for local f = function(...) ... end
            for sub in child.children:
                if sub.type == "function_definition":
                    # Anonymous function assigned to variable
                    summary = _process_anonymous_func(sub, file_path, file_lines, child)
                    if summary:
                        functions.append(summary)

    return FileSummary(file=file_path, content_hash=content_hash, functions=functions)


def _process_anonymous_func(func_node, file_path, file_lines, parent_node):
    """处理匿名函数（function_definition）节点，生成摘要。"""
    # Try to get the variable name from parent
    func_name = "<anonymous>"
    for child in parent_node.children:
        if child.type == "identifier" and child != func_node:
            func_name = _node_text(child)
            break

    param_names: List[str] = []
    func_body = None
    for child in func_node.children:
        if child.type in ("parameters", "parameter_list"):
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
        receiver_name="",
        is_method=False,
    )


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 Lua 文件，生成摘要。"""
    global _summary_registry
    _summary_registry = {}

    summaries: Dict[str, FileSummary] = {}

    for file_path, content in files_dict.items():
        if not file_path.endswith(".lua"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：二次分析
    for file_path, content in files_dict.items():
        if not file_path.endswith(".lua"):
            continue
        old_fs = summaries[file_path]
        new_fs = generate_file_summaries(file_path, content)
        changed = False
        for i, fn in enumerate(new_fs.functions):
            if fn.return_flow:
                if i < len(old_fs.functions):
                    old_fn = old_fs.functions[i]
                    if len(fn.return_flow) != len(old_fn.return_flow):
                        old_fs.functions[i] = fn
                        changed = True
        if changed:
            summaries[file_path] = old_fs

    logger.debug(f"函数摘要生成完成: {len(summaries)} 个文件, {len(_summary_registry)} 个函数")
    return summaries
