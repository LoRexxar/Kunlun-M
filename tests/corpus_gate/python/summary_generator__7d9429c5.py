#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Python 函数摘要生成器
    ~~~~~~~~~~~~~~~~~~~~~~
    用 ast 模块解析 Python 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
from __future__ import annotations

import ast
import hashlib
from typing import Dict, List, Optional, Set

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

_MAX_TRACE_DEPTH = 10

# 模块级摘要注册表，用于跨函数递归分析
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


def _get_name(node) -> Optional[str]:
    """从 AST 节点提取变量名。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, (ast.Tuple, ast.List)):
        return None
    return None


def _expr_to_str(node) -> str:
    """将 AST 节点转为文本表示。"""
    try:
        return ast.unparse(node)
    except Exception:
        return "..."


def _is_literal(node) -> bool:
    """判断节点是否为字面量。"""
    return isinstance(node, (ast.Constant, ast.Num, ast.Str, ast.List, ast.Dict, ast.Tuple, ast.Set))


def _find_assignments(func_body) -> Dict[str, ast.AST]:
    """在函数体中收集赋值语句的左值 -> 右值节点映射。

    仅记录 identifier = expr 形式的简单赋值，暂不处理元组解构。
    """
    assignments: Dict[str, ast.AST] = {}

    for node in ast.walk(func_body):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target_name = _get_name(node.targets[0])
            if target_name:
                assignments[target_name] = node.value
        elif isinstance(node, ast.AnnAssign) and node.target and node.value:
            target_name = _get_name(node.target)
            if target_name:
                assignments[target_name] = node.value

    return assignments


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    func_body=None,
    assignments: Optional[Dict[str, ast.AST]] = None,
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

    # 1. 字面量
    if _is_literal(expr_node):
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "literal",
            "dep_params": [],
            "path": [],
        }

    # 2. 变量名 ast.Name
    if isinstance(expr_node, ast.Name):
        name = expr_node.id
        if name in param_names:
            idx = param_names.index(name)
            return {
                "origin": name,
                "origin_type": "param",
                "dep_params": [idx],
                "path": [],
            }

        # 检查函数内是否有对 name 的赋值
        if assignments and name in assignments and func_body is not None:
            rhs_node = assignments[name]
            result = _trace_dataflow(
                rhs_node, param_names, func_body, assignments,
                visited, depth + 1,
            )
            line = getattr(rhs_node, "lineno", 0)
            result["path"].append({
                "node": name,
                "type": "assign",
                "line": line,
            })
            return result

        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. 函数调用 ast.Call
    if isinstance(expr_node, ast.Call):
        func_name = _expr_to_str(expr_node.func)
        dep_params: List[int] = []

        # 追踪函数名部分（ast.Attribute 可能包含参数引用）
        sub = _trace_dataflow(
            expr_node.func, param_names, func_body, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))

        # 收集参数的数据流信息（用于递归展开时做参数映射）
        arg_flows: List[dict] = []
        for arg in expr_node.args:
            sub = _trace_dataflow(
                arg, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
            arg_flows.append(sub)
        for kw in expr_node.keywords:
            if kw.value:
                sub = _trace_dataflow(
                    kw.value, param_names, func_body, assignments,
                    visited, depth + 1,
                )
                dep_params.extend(sub.get("dep_params", []))

        # 递归查摘要注册表，展开自定义方法调用
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
                line = getattr(expr_node, "lineno", 0)
                return {
                    "origin": func_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{
                        "node": func_name,
                        "type": "call",
                        "line": line,
                    }],
                    "expanded_from": short_name,
                }

        line = getattr(expr_node, "lineno", 0)
        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": func_name,
                "type": "call",
                "line": line,
            }],
        }

    # 4. 属性访问 ast.Attribute（如 request.GET）
    if isinstance(expr_node, ast.Attribute):
        full_text = _expr_to_str(expr_node)
        dep_params: List[int] = []
        sub = _trace_dataflow(
            expr_node.value, param_names, func_body, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))
        line = getattr(expr_node, "lineno", 0)
        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": full_text,
                "type": "selector",
                "line": line,
            }],
        }

    # 5. 二元运算 ast.BinOp（如 a + b）
    if isinstance(expr_node, ast.BinOp):
        dep_params: List[int] = []
        path: List[dict] = []
        for side in (expr_node.left, expr_node.right):
            sub = _trace_dataflow(
                side, param_names, func_body, assignments,
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

    # 6. 一元运算 ast.UnaryOp
    if isinstance(expr_node, ast.UnaryOp):
        return _trace_dataflow(
            expr_node.operand, param_names, func_body, assignments,
            visited, depth + 1,
        )

    # 7. 下标访问 ast.Subscript（如 request.GET["key"]）
    if isinstance(expr_node, ast.Subscript):
        dep_params: List[int] = []
        sub = _trace_dataflow(
            expr_node.value, param_names, func_body, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))
        # 追踪 slice 部分
        if isinstance(expr_node.slice, ast.AST):
            sub_slice = _trace_dataflow(
                expr_node.slice, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub_slice.get("dep_params", []))
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 8. 三元表达式 ast.IfExp（a if cond else b）
    if isinstance(expr_node, ast.IfExp):
        dep_params: List[int] = []
        for branch in (expr_node.body, expr_node.orelse):
            sub = _trace_dataflow(
                branch, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 9. 元组 / 列表字面量中的表达式（如 return a, b 中的单个元素已由上层拆分）
    if isinstance(expr_node, (ast.Tuple, ast.List)):
        dep_params: List[int] = []
        for elt in expr_node.elts:
            sub = _trace_dataflow(
                elt, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 其他情况
    return {
        "origin": _expr_to_str(expr_node),
        "origin_type": "unknown",
        "dep_params": [],
        "path": [],
    }


def _analyze_function(func_node, file_content: str) -> FunctionSummary:
    """分析单个函数定义，生成摘要。

    提取函数名、参数（跳过 self）、行号范围，分析返回值数据流。
    """
    params = [arg.arg for arg in func_node.args.args]
    # 跳掉 self / cls
    if params and params[0] in ("self", "cls"):
        params = params[1:]

    # 收集函数体中的赋值
    assignments = _find_assignments(func_node)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    for node in ast.walk(func_node):
        if not isinstance(node, ast.Return) or node.value is None:
            continue

        # Python return 支持多值（元组）
        if isinstance(node.value, ast.Tuple):
            for idx, elt in enumerate(node.value.elts):
                flow = _trace_dataflow(elt, params, func_node, assignments)
                return_flow.append(ReturnFlowItem(
                    order=order,
                    return_index=idx,
                    origin=flow["origin"],
                    origin_type=flow["origin_type"],
                    dep_params=flow["dep_params"],
                    path=flow.get("path", []),
                ))
        else:
            flow = _trace_dataflow(node.value, params, func_node, assignments)
            return_flow.append(ReturnFlowItem(
                order=order,
                return_index=0,
                origin=flow["origin"],
                origin_type=flow["origin_type"],
                dep_params=flow["dep_params"],
                path=flow.get("path", []),
            ))
        order += 1

    return FunctionSummary(
        name=func_node.name,
        params=params,
        line_range=[func_node.lineno, func_node.end_lineno or func_node.lineno],
        return_flow=return_flow,
    )


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析一个 Python 文件，生成函数摘要。

    用 ast 模块解析 Python AST，遍历所有 FunctionDef 和 AsyncFunctionDef
    节点，对每个函数提取返回值数据流。

    :param file_path: 文件路径，用于记录在摘要中
    :param file_content: Python 源文件内容
    :return: FileSummary 实例，解析失败时返回空摘要
    """
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    try:
        tree = ast.parse(file_content)
    except SyntaxError as e:
        logger.warning(f"解析 Python 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    functions: List[FunctionSummary] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_summary = _analyze_function(node, file_content)
            functions.append(fn_summary)

    return FileSummary(
        file=file_path,
        content_hash=content_hash,
        functions=functions,
    )


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 Python 文件，生成摘要。

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
        if not file_path.endswith(".py"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：对有自定义方法调用的函数做二次分析
    for file_path, content in files_dict.items():
        if not file_path.endswith(".py"):
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
