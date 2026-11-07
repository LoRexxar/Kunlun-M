#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    PHP 函数摘要生成器
    ~~~~~~~~~~~~~~~~~
    用 lphply 解析 PHP 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from phply import phpast as php
from phply.phplex import lexer as _php_lexer
from phply.phpparse import make_parser

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

_MAX_TRACE_DEPTH = 10

_summary_registry: Dict[str, FunctionSummary] = {}


def lookup_summary(func_name: str) -> Optional[FunctionSummary]:
    """Query function summary. Try exact match first, then fallback to short name."""
    # Exact match first (caller may pass qualified name like ClassName.methodName)
    result = _summary_registry.get(func_name)
    if result:
        return result
    # Extract short name for fallback
    if "::" in func_name:
        short_name = func_name.split("::")[-1]
    elif "." in func_name:
        short_name = func_name.split(".")[-1]
    else:
        short_name = func_name
    return _summary_registry.get(short_name)


def _walk(nodes):
    """递归遍历 PHP AST 节点列表。"""
    for node in nodes:
        yield node
        if hasattr(node, "nodes") and isinstance(node.nodes, list):
            yield from _walk(node.nodes)
        if hasattr(node, "node") and node.node is not None and not isinstance(node.node, list):
            yield node.node


def _expr_to_str(node) -> str:
    """将 PHP AST 节点转为文本表示。"""
    if node is None:
        return "..."
    if isinstance(node, str):
        return node
    if isinstance(node, php.Variable):
        return node.name
    if isinstance(node, php.FunctionCall):
        args = ", ".join(_expr_to_str(_unwrap_param(p)) for p in (node.params or []))
        return f"{node.name}({args})"
    if isinstance(node, php.MethodCall):
        obj = _expr_to_str(node.node)
        args = ", ".join(_expr_to_str(_unwrap_param(p)) for p in (node.params or []))
        return f"{obj}->{node.name}({args})"
    if isinstance(node, php.StaticMethodCall):
        args = ", ".join(_expr_to_str(_unwrap_param(p)) for p in (node.params or []))
        return f"{node.class_}::{node.name}({args})"
    if isinstance(node, php.BinaryOp):
        return f"{_expr_to_str(node.left)} {node.op} {_expr_to_str(node.right)}"
    if isinstance(node, php.ObjectProperty):
        return f"{_expr_to_str(node.node)}->{node.name}"
    if isinstance(node, php.ArrayOffset):
        return f"{_expr_to_str(node.node)}[{_expr_to_str(node.expr)}]"
    if isinstance(node, php.TernaryOp):
        return f"{_expr_to_str(node.expr)} ? {_expr_to_str(node.iftrue)} : {_expr_to_str(node.iffalse)}"
    if isinstance(node, php.Assignment):
        return f"{_expr_to_str(node.node)} = {_expr_to_str(node.expr)}"
    if isinstance(node, php.Constant):
        return node.name
    if isinstance(node, php.Parameter):
        return _expr_to_str(node.node)
    try:
        return repr(node)
    except Exception:
        return "..."


def _unwrap_param(param):
    """从 Parameter 包装器中提取实际节点。"""
    if isinstance(param, php.Parameter):
        return param.node
    return param


def _is_literal(node) -> bool:
    """判断节点是否为字面量（字符串、数字、布尔等）。"""
    if isinstance(node, str):
        return True
    if isinstance(node, php.Constant):
        return node.name.lower() in ("true", "false", "null")
    if isinstance(node, (int, float)):
        return True
    return False


def _extract_param_names(params) -> List[str]:
    """从 PHP 函数参数列表提取参数名。

    PHP 参数通常是 FormalParameter 对象，name 字段包含 $ 前缀。
    返回的名称列表不带 $ 前缀。
    """
    names: List[str] = []
    for p in params:
        if isinstance(p, php.FormalParameter):
            raw_name = p.name
            names.append(raw_name.lstrip("$"))
        elif isinstance(p, php.Variable):
            names.append(p.name.lstrip("$"))
        elif hasattr(p, "name") and isinstance(p.name, str):
            names.append(p.name.lstrip("$"))
        elif isinstance(p, str):
            names.append(p.lstrip("$"))
    return names


def _find_assignments(func_body_nodes) -> Dict[str, object]:
    """在函数体节点列表中收集赋值语句的变量名 -> 右值节点映射。

    仅记录 $var = expr 形式的简单赋值。
    """
    assignments: Dict[str, object] = {}

    for node in _walk(func_body_nodes):
        if isinstance(node, php.Assignment) and isinstance(node.node, php.Variable):
            var_name = node.node.name.lstrip("$")
            assignments[var_name] = node.expr

    return assignments


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    func_body_nodes=None,
    assignments: Optional[Dict[str, object]] = None,
    visited: Optional[Set[int]] = None,
    depth: int = 0,
) -> dict:
    """从表达式节点反向追踪数据流。

    返回字典包含 origin, origin_type, dep_params, path 四个字段。
    不做安全判定，只记录数据流事实。
    """
    if visited is None:
        visited = set()
    if depth > _MAX_TRACE_DEPTH:
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }

    node_id = id(expr_node)
    if node_id in visited:
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": [],
            "path": [],
        }
    visited = visited | {node_id}

    # 1. 字面量（字符串、数字、布尔常量）
    if _is_literal(expr_node):
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "literal",
            "dep_params": [],
            "path": [],
        }

    # 2. 变量 php.Variable
    if isinstance(expr_node, php.Variable):
        raw_name = expr_node.name
        name = raw_name.lstrip("$")

        if name in param_names:
            idx = param_names.index(name)
            return {
                "origin": raw_name,
                "origin_type": "param",
                "dep_params": [idx],
                "path": [],
            }

        if assignments and name in assignments and func_body_nodes is not None:
            rhs_node = assignments[name]
            result = _trace_dataflow(
                rhs_node, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            lineno = getattr(rhs_node, "lineno", 0)
            result["path"].append({
                "node": raw_name,
                "type": "assign",
                "line": lineno,
            })
            return result

        return {
            "origin": raw_name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. 函数调用 php.FunctionCall
    if isinstance(expr_node, php.FunctionCall):
        func_name = expr_node.name
        dep_params: List[int] = []

        arg_flows: List[dict] = []
        for p in (expr_node.params or []):
            actual = _unwrap_param(p)
            sub = _trace_dataflow(
                actual, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            arg_flows.append(sub)

        # 递归查摘要注册表
        short_name = func_name.split("::")[-1] if "::" in func_name else func_name
        callee_summary = _summary_registry.get(short_name)

        if callee_summary and callee_summary.return_flow and depth < _MAX_TRACE_DEPTH:
            expanded_deps: List[int] = []
            for rf in callee_summary.return_flow:
                for callee_param_idx in rf.dep_params:
                    if callee_param_idx < len(arg_flows):
                        expanded_deps.extend(arg_flows[callee_param_idx].get("dep_params", []))

            if expanded_deps:
                all_deps = list(dict.fromkeys(dep_params + expanded_deps))
                lineno = getattr(expr_node, "lineno", 0)
                return {
                    "origin": func_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{"node": func_name, "type": "call", "line": lineno}],
                    "expanded_from": short_name,
                }

        lineno = getattr(expr_node, "lineno", 0)
        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": func_name, "type": "call", "line": lineno}],
        }

    # 4. 方法调用 php.MethodCall
    if isinstance(expr_node, php.MethodCall):
        obj_str = _expr_to_str(expr_node.node)
        method_name = f"{obj_str}->{expr_node.name}"
        dep_params: List[int] = []

        # 追踪对象变量
        sub = _trace_dataflow(
            expr_node.node, param_names, func_body_nodes, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))

        arg_flows: List[dict] = []
        for p in (expr_node.params or []):
            actual = _unwrap_param(p)
            sub = _trace_dataflow(
                actual, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            arg_flows.append(sub)

        # 递归查摘要注册表
        short_name = expr_node.name
        callee_summary = _summary_registry.get(short_name)

        if callee_summary and callee_summary.return_flow and depth < _MAX_TRACE_DEPTH:
            expanded_deps: List[int] = []
            for rf in callee_summary.return_flow:
                for callee_param_idx in rf.dep_params:
                    if callee_param_idx < len(arg_flows):
                        expanded_deps.extend(arg_flows[callee_param_idx].get("dep_params", []))

            if expanded_deps:
                all_deps = list(dict.fromkeys(dep_params + expanded_deps))
                lineno = getattr(expr_node, "lineno", 0)
                return {
                    "origin": method_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{"node": method_name, "type": "call", "line": lineno}],
                    "expanded_from": short_name,
                }

        lineno = getattr(expr_node, "lineno", 0)
        return {
            "origin": method_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": method_name, "type": "call", "line": lineno}],
        }

    # 5. 静态方法调用 php.StaticMethodCall
    if isinstance(expr_node, php.StaticMethodCall):
        call_name = f"{expr_node.class_}::{expr_node.name}"
        dep_params: List[int] = []

        arg_flows: List[dict] = []
        for p in (expr_node.params or []):
            actual = _unwrap_param(p)
            sub = _trace_dataflow(
                actual, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            arg_flows.append(sub)

        short_name = expr_node.name
        callee_summary = _summary_registry.get(short_name)

        if callee_summary and callee_summary.return_flow and depth < _MAX_TRACE_DEPTH:
            expanded_deps: List[int] = []
            for rf in callee_summary.return_flow:
                for callee_param_idx in rf.dep_params:
                    if callee_param_idx < len(arg_flows):
                        expanded_deps.extend(arg_flows[callee_param_idx].get("dep_params", []))

            if expanded_deps:
                all_deps = list(dict.fromkeys(dep_params + expanded_deps))
                lineno = getattr(expr_node, "lineno", 0)
                return {
                    "origin": call_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{"node": call_name, "type": "call", "line": lineno}],
                    "expanded_from": short_name,
                }

        lineno = getattr(expr_node, "lineno", 0)
        return {
            "origin": call_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": call_name, "type": "call", "line": lineno}],
        }

    # 6. 二元运算 php.BinaryOp
    if isinstance(expr_node, php.BinaryOp):
        dep_params: List[int] = []
        path: List[dict] = []
        for side in (expr_node.left, expr_node.right):
            sub = _trace_dataflow(
                side, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            if sub.get("path"):
                path.extend(sub["path"])

        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": path,
        }

    # 7. 属性访问 php.ObjectProperty（如 $obj->prop）
    if isinstance(expr_node, php.ObjectProperty):
        full_text = _expr_to_str(expr_node)
        dep_params: List[int] = []
        sub = _trace_dataflow(
            expr_node.node, param_names, func_body_nodes, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))
        lineno = getattr(expr_node, "lineno", 0)
        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": full_text, "type": "selector", "line": lineno}],
        }

    # 8. 数组访问 php.ArrayOffset
    if isinstance(expr_node, php.ArrayOffset):
        dep_params: List[int] = []
        sub = _trace_dataflow(
            expr_node.node, param_names, func_body_nodes, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))
        if expr_node.expr is not None:
            sub_key = _trace_dataflow(
                expr_node.expr, param_names, func_body_nodes, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub_key.get("dep_params", []))
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 9. 三元运算 php.TernaryOp
    if isinstance(expr_node, php.TernaryOp):
        dep_params: List[int] = []
        for branch in (expr_node.iftrue, expr_node.iffalse):
            if branch is not None:
                sub = _trace_dataflow(
                    branch, param_names, func_body_nodes, assignments,
                    visited, depth + 1,
                )
                dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 10. Parameter 包装器（递归展开）
    if isinstance(expr_node, php.Parameter):
        return _trace_dataflow(
            expr_node.node, param_names, func_body_nodes, assignments,
            visited, depth + 1,
        )

    # 其他情况
    return {
        "origin": _expr_to_str(expr_node),
        "origin_type": "unknown",
        "dep_params": [],
        "path": [],
    }


def _analyze_function(func_node, file_content: str) -> FunctionSummary:
    """分析单个 PHP 函数定义，生成摘要。"""
    params = _extract_param_names(func_node.params)
    assignments = _find_assignments(func_node.nodes)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    for node in _walk(func_node.nodes):
        if not isinstance(node, php.Return) or node.node is None:
            continue

        flow = _trace_dataflow(node.node, params, func_node.nodes, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    lineno = getattr(func_node, "lineno", 0)
    end_lineno = getattr(func_node, "end_lineno", lineno)

    return FunctionSummary(
        name=func_node.name,
        params=params,
        line_range=[lineno, end_lineno],
        return_flow=return_flow,
    )


def _analyze_method(method_node, class_name: str, file_content: str) -> FunctionSummary:
    """分析单个 PHP 类方法定义，生成摘要。

    方法名格式为 "ClassName::methodName"。
    参数列表中的 $this 不占 dep_params index（和 Go 的 receiver 类似）。
    """
    params = _extract_param_names(method_node.params)
    # $this 不占参数 index，移除之
    this_index = -1
    for i, p in enumerate(params):
        if p == "this":
            this_index = i
            break
    if this_index >= 0:
        params.pop(this_index)

    # 构造用于数据流追踪的参数列表（包含 $this 用于赋值链追踪，但不占 index）
    trace_params = list(params)

    assignments = _find_assignments(method_node.nodes)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    for node in _walk(method_node.nodes):
        if not isinstance(node, php.Return) or node.node is None:
            continue

        flow = _trace_dataflow(node.node, trace_params, method_node.nodes, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    lineno = getattr(method_node, "lineno", 0)
    end_lineno = getattr(method_node, "end_lineno", lineno)
    qualified_name = f"{class_name}::{method_node.name}"

    return FunctionSummary(
        name=qualified_name,
        params=params,
        line_range=[lineno, end_lineno],
        return_flow=return_flow,
        is_method=True,
    )


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析一个 PHP 文件，生成函数摘要。

    用 lphply 解析 PHP AST，遍历所有 Function 和 Class->Method
    节点，对每个函数提取返回值数据流。

    :param file_path: 文件路径，用于记录在摘要中
    :param file_content: PHP 源文件内容
    :return: FileSummary 实例，解析失败时返回空摘要
    """
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    try:
        parser = make_parser()
        ast_nodes = parser.parse(
            file_content, debug=False, lexer=_php_lexer.clone(), tracking=True,
        )
    except Exception as e:
        logger.warning(f"解析 PHP 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    functions: List[FunctionSummary] = []
    for node in ast_nodes:
        if isinstance(node, php.Function):
            fn = _analyze_function(node, file_content)
            functions.append(fn)
        elif isinstance(node, php.Class):
            for member in node.nodes:
                if isinstance(member, php.Method):
                    fn = _analyze_method(member, node.name, file_content)
                    functions.append(fn)

    return FileSummary(
        file=file_path,
        content_hash=content_hash,
        functions=functions,
    )


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 PHP 文件，生成摘要。

    两遍处理：
    1. 第一遍：生成所有文件的摘要，注册到全局注册表
    2. 第二遍：对有自定义方法调用的函数做二次分析（可递归展开）

    :param target_path: 扫描目标路径（仅用于日志）
    :param files_dict: {file_path: file_content} 字典
    :return: {file_path: FileSummary} 字典
    """
    global _summary_registry
    _summary_registry = {}

    summaries: Dict[str, FileSummary] = {}

    # 第一遍：生成所有摘要并注册
    for file_path, content in files_dict.items():
        if not file_path.endswith(".php"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：对有自定义方法调用的函数做二次分析
    for file_path, content in files_dict.items():
        if not file_path.endswith(".php"):
            continue
        old_fs = summaries[file_path]
        new_fs = generate_file_summaries(file_path, content)
        changed = False
        for i, fn in enumerate(new_fs.functions):
            if fn.return_flow:
                old_fn = old_fs.functions[i]
                if len(fn.return_flow) != len(old_fn.return_flow):
                    old_fs.functions[i] = fn
                    changed = True
                else:
                    for j, rf in enumerate(fn.return_flow):
                        if rf.dep_params != old_fn.return_flow[j].dep_params:
                            old_fs.functions[i] = fn
                            changed = True
                            break
        if changed:
            summaries[file_path] = old_fs

    logger.debug(f"函数摘要生成完成: {len(summaries)} 个文件, {len(_summary_registry)} 个函数")
    return summaries
