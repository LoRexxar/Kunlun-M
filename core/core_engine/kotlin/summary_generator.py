#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Kotlin 函数摘要生成器
    ~~~~~~~~~~~~~~~~~~~~~
    用 tree-sitter 解析 Kotlin 源文件，提取每个函数的返回值数据流摘要。
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
import tree_sitter_kotlin as _tskotlin
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_KOTLIN_TS_LANGUAGE = _TS_Language(_tskotlin.language())
_ts_parser = _TS_Parser(_KOTLIN_TS_LANGUAGE)
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
        "integer_literal", "real_literal",
        "string_literal", "true", "false", "null",
    ):
        return True
    return False


def _extract_param_names(param_node) -> List[str]:
    """从 parameter 节点提取形参名列表。"""
    names: List[str] = []
    if param_node is None:
        return names
    for child in param_node.children:
        if child.type == "parameter":
            for sub in child.children:
                if sub.type == "simple_identifier":
                    names.append(_node_text(sub))
                    break
    return names


def _find_child_by_type(node, *types):
    """返回第一个匹配类型的子节点。"""
    if node is None:
        return None
    for c in node.children:
        if c.type in types:
            return c
    return None


def _find_assignments(func_body) -> Dict[str, object]:
    """在函数体中收集变量声明和赋值的映射。"""
    assignments: Dict[str, object] = {}

    def _walk(node):
        for child in node.children:
            if child.type == "property_declaration":
                var_name = None
                init_expr = None
                for c in child.children:
                    if c.type == "simple_identifier" and var_name is None:
                        var_name = _node_text(c)
                    if init_expr is None and c.type in (
                        "call_expression", "dot_expression",
                        "binary_expression", "prefix_expression",
                        "string_literal", "integer_literal", "real_literal",
                        "if_expression", "when_expression",
                        "lambda_expression", "anonymous_function",
                        "simple_identifier",
                    ):
                        init_expr = c
                if var_name and init_expr:
                    assignments[var_name] = init_expr
            elif child.type == "assignment":
                left = None
                right = None
                found_eq = False
                for c in child.children:
                    if c.type == "=":
                        found_eq = True
                        continue
                    if not found_eq and left is None:
                        if c.type == "simple_identifier":
                            left = _node_text(c)
                    elif found_eq and right is None:
                        right = c
                        break
                if left and right:
                    assignments[left] = right
            elif child.type in (
                "if_expression", "when_expression", "for_statement",
                "while_statement", "do_while_statement",
                "try_expression", "block", "lambda_expression",
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

    # 2. simple_identifier
    if expr_node.type == "simple_identifier":
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

    # 3. call_expression
    if expr_node.type == "call_expression":
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
            sub = _trace_dataflow(
                arg, param_names, file_lines, func_body, assignments,
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
                        "line": expr_node.start_point[0] + 1,
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
                "line": expr_node.start_point[0] + 1,
            }],
        }

    # 4. binary_expression
    if expr_node.type == "binary_expression":
        dep_params: List[int] = []
        path: List[dict] = []
        for child in expr_node.children:
            if child.type in ("==", "!=", ">=", "<=", ">", "<", "&&", "||",
                              "+", "-", "*", "/", "%", "..", "plus", "minus",
                              "times", "div", "mod"):
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
    in_class: bool = False,
) -> Optional[FunctionSummary]:
    """处理单个 function_declaration 节点，生成摘要。"""
    func_name = ""
    param_names: List[str] = []
    func_body = None

    for child in func_node.children:
        if child.type == "simple_identifier" and not func_name:
            func_name = _node_text(child)
        elif child.type == "parameter":
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
        is_method=in_class,
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
    """递归遍历 AST 节点，收集所有 return_expression 的数据流。"""
    for child in node.children:
        if child.type == "return_expression":
            items = _analyze_return_value(
                child, param_names, func_body, file_path, file_lines, assignments,
            )
            result.extend(items)
        elif child.type in (
            "if_expression", "when_expression", "for_statement",
            "while_statement", "do_while_statement", "try_expression",
            "block", "lambda_expression",
        ):
            _collect_returns(child, param_names, func_body, file_path,
                             file_lines, assignments, result)


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析单个 Kotlin 文件，生成该文件所有函数的摘要。"""
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    if not _HAS_TREE_SITTER or _ts_parser is None:
        logger.debug(f"tree-sitter 不可用，跳过摘要生成: {file_path}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    try:
        tree = _ts_parser.parse(file_content.encode("utf-8"))
    except Exception as e:
        logger.warning(f"[AST][Kotlin] 摘要生成解析失败: {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    file_lines = file_content.splitlines()
    root_node = tree.root_node
    functions: List[FunctionSummary] = []

    for child in root_node.children:
        if child is None or not hasattr(child, 'type'):
            continue

        if child.type == 'function_declaration':
            fs = _process_func_node(child, file_path, file_lines)
            if fs:
                functions.append(fs)
                _summary_registry[fs.name] = fs

        elif child.type in ('class_declaration', 'object_declaration',
                             'interface_declaration', 'enum_declaration'):
            body = _find_child_by_type(child, 'class_body')
            if body:
                for sub in body.children:
                    if sub.type == 'function_declaration':
                        fs = _process_func_node(sub, file_path, file_lines, in_class=True)
                        if fs:
                            functions.append(fs)
                            _summary_registry[fs.name] = fs
                    # companion object
                    if sub.type == 'companion_object':
                        comp_body = _find_child_by_type(sub, 'class_body')
                        if comp_body:
                            for comp_sub in comp_body.children:
                                if comp_sub.type == 'function_declaration':
                                    fs = _process_func_node(comp_sub, file_path, file_lines, in_class=True)
                                    if fs:
                                        functions.append(fs)
                                        _summary_registry[fs.name] = fs

    logger.debug(f"[AST][Kotlin] 摘要生成完成: {file_path}, {len(functions)} 个函数")
    return FileSummary(file=file_path, content_hash=content_hash, functions=functions)


def generate_summaries_for_target(target_dir, files_dict):
    """为目标目录中的文件生成摘要。"""
    results = {}
    for fp, content in files_dict.items():
        try:
            fs = generate_file_summaries(fp, content)
            results[fp] = fs
        except Exception as e:
            logger.warning(f"[AST][Kotlin] 摘要生成异常: {fp}: {e}")
    return results
