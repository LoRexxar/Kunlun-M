#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    JavaScript 函数摘要生成器
    ~~~~~~~~~~~~~~~~~~~~~~~~~
    用 lesprima 解析 JS 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from esprima import parse
from esprima import nodes as js

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


def _walk(stmts):
    """递归遍历 JS AST 语句列表，深入常见子节点属性。"""
    for stmt in stmts:
        yield stmt
        # 语句级属性
        for attr in ("body", "consequent", "alternate", "cases", "block",
                      "expression", "test", "declarations", "arguments",
                      "left", "right", "init", "value",
                      "callee", "object", "property", "elements"):
            val = getattr(stmt, attr, None)
            if val is None:
                continue
            if isinstance(val, (list, tuple)):
                for item in val:
                    if hasattr(item, 'type'):
                        yield from _walk([item])
            elif hasattr(val, 'type'):
                yield from _walk([val])


def _expr_to_str(node) -> str:
    """将 JS AST 节点转为文本表示。"""
    if node is None:
        return "..."
    if isinstance(node, js.Identifier):
        return node.name
    if isinstance(node, js.Literal):
        return repr(node.value)
    if isinstance(node, js.StringLiteral):
        return repr(node.value)
    if isinstance(node, js.BooleanLiteral):
        return repr(node.value)
    if isinstance(node, js.NullLiteral):
        return "null"
    if isinstance(node, js.ThisExpression):
        return "this"
    if isinstance(node, (js.StaticMemberExpression, js.ComputedMemberExpression)):
        obj = _expr_to_str(node.object)
        if isinstance(node, js.ComputedMemberExpression):
            prop = _expr_to_str(node.property)
            return f"{obj}[{prop}]"
        prop = _expr_to_str(node.property)
        return f"{obj}.{prop}"
    if isinstance(node, js.CallExpression):
        callee = _expr_to_str(node.callee)
        args = ", ".join(_expr_to_str(a) for a in (node.arguments or []))
        return f"{callee}({args})"
    if isinstance(node, js.NewExpression):
        callee = _expr_to_str(node.callee)
        args = ", ".join(_expr_to_str(a) for a in (node.arguments or []))
        return f"new {callee}({args})"
    if isinstance(node, js.BinaryExpression):
        left = _expr_to_str(node.left)
        right = _expr_to_str(node.right)
        return f"{left} {node.operator} {right}"
    if isinstance(node, js.LogicalExpression):
        left = _expr_to_str(node.left)
        right = _expr_to_str(node.right)
        return f"{left} {node.operator} {right}"
    if isinstance(node, js.UnaryExpression):
        arg = _expr_to_str(node.argument)
        if node.prefix:
            return f"{node.operator}{arg}"
        return f"{arg}{node.operator}"
    if isinstance(node, js.ConditionalExpression):
        test = _expr_to_str(node.test)
        cons = _expr_to_str(node.consequent)
        alt = _expr_to_str(node.alternate)
        return f"{test} ? {cons} : {alt}"
    if isinstance(node, js.AssignmentExpression):
        left = _expr_to_str(node.left)
        right = _expr_to_str(node.right)
        return f"{left} {node.operator} {right}"
    if isinstance(node, js.TemplateLiteral):
        parts = []
        for i, quasi in enumerate(node.quasis):
            parts.append(quasi.value.cooked if quasi.value else "")
            if i < len(node.expressions):
                parts.append("${" + _expr_to_str(node.expressions[i]) + "}")
        return "`" + "".join(parts) + "`"
    if isinstance(node, js.ObjectExpression):
        props = ", ".join(_expr_to_str(p) for p in (node.properties or []))
        return "{" + props + "}"
    if isinstance(node, js.Property):
        key = _expr_to_str(node.key)
        if node.method:
            return key + "(...)"
        return f"{key}: {_expr_to_str(node.value)}"
    if isinstance(node, js.ArrayExpression):
        elts = ", ".join(_expr_to_str(e) for e in (node.elements or []))
        return f"[{elts}]"
    if isinstance(node, js.FunctionExpression):
        name = node.id.name if node.id else "<anonymous>"
        return f"function {name}(...)"
    if isinstance(node, js.ArrowFunctionExpression):
        return "(...) => ..."
    if isinstance(node, js.SequenceExpression):
        return ", ".join(_expr_to_str(e) for e in node.expressions)
    if isinstance(node, js.AwaitExpression):
        return "await " + _expr_to_str(node.argument)
    try:
        return repr(node)
    except Exception:
        return "..."


def _is_literal(node) -> bool:
    """判断节点是否为字面量。"""
    return isinstance(node, (js.Literal, js.BooleanLiteral, js.NullLiteral))


def _find_assignments(body_stmts) -> Dict[str, object]:
    """在函数体语句中收集赋值语句的变量名 -> 右值节点映射。

    仅记录 var/let/const x = expr 和 x = expr 形式的简单赋值。
    """
    assignments: Dict[str, object] = {}

    for node in _walk(body_stmts):
        # var/let/const x = expr
        if isinstance(node, js.VariableDeclaration):
            for decl in node.declarations:
                if isinstance(decl, js.VariableDeclarator) and decl.init is not None:
                    if isinstance(decl.id, js.Identifier):
                        assignments[decl.id.name] = decl.init
        # x = expr
        elif isinstance(node, js.ExpressionStatement):
            expr = node.expression
            if isinstance(expr, js.AssignmentExpression) and isinstance(expr.left, js.Identifier):
                assignments[expr.left.name] = expr.right

    return assignments


def _get_line(node) -> int:
    """从节点获取行号。"""
    loc = getattr(node, "loc", None)
    if loc:
        return loc.start.line
    return 0


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    func_body=None,
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

    # 1. 字面量
    if _is_literal(expr_node):
        return {
            "origin": _expr_to_str(expr_node),
            "origin_type": "literal",
            "dep_params": [],
            "path": [],
        }

    # 2. 标识符 js.Identifier
    if isinstance(expr_node, js.Identifier):
        name = expr_node.name
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
                rhs_node, param_names, func_body, assignments,
                visited, depth + 1,
            )
            result["path"].append({
                "node": name,
                "type": "assign",
                "line": _get_line(rhs_node),
            })
            return result

        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. new 表达式 js.NewExpression（必须在 CallExpression 之前，因为 NewExpression 继承自 CallExpression）
    if isinstance(expr_node, js.NewExpression):
        func_name = _expr_to_str(expr_node.callee)
        dep_params: List[int] = []

        # new Promise(callback) 特殊处理：
        # 追踪 callback body 中所有 CallExpression 的参数是否依赖函数参数
        # 这覆盖两种模式：
        #   1) resolve(param) — 直接传参给 resolve
        #   2) exec(param, cb -> resolve(stdout)) — 参数传给内部调用，结果间接 resolve
        if func_name == "Promise" and expr_node.arguments:
            callback_fn = expr_node.arguments[0]
            if isinstance(callback_fn, (js.FunctionExpression, js.ArrowFunctionExpression)):
                callback_body = callback_fn.body.body if hasattr(callback_fn.body, 'body') and isinstance(callback_fn.body.body, list) else []
                for node in _walk(callback_body):
                    if isinstance(node, js.CallExpression) and node.arguments:
                        for arg in node.arguments:
                            sub = _trace_dataflow(
                                arg, param_names, func_body, assignments,
                                visited | {id(expr_node)}, depth + 1,
                            )
                            dep_params.extend(sub.get("dep_params", []))
                if dep_params:
                    return {
                        "origin": f"new {func_name}",
                        "origin_type": "call",
                        "dep_params": list(dict.fromkeys(dep_params)),
                        "path": [{"node": f"new {func_name}", "type": "promise", "line": _get_line(expr_node)}],
                    }

        for arg in (expr_node.arguments or []):
            sub = _trace_dataflow(
                arg, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": f"new {func_name}",
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": f"new {func_name}", "type": "call", "line": _get_line(expr_node)}],
        }

    # 4. 函数调用 js.CallExpression
    if isinstance(expr_node, js.CallExpression):
        func_name = _expr_to_str(expr_node.callee)
        dep_params: List[int] = []

        # 追踪 callee 部分（可能是 MemberExpression，包含参数引用）
        sub = _trace_dataflow(
            expr_node.callee, param_names, func_body, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))

        # 追踪参数
        arg_flows: List[dict] = []
        for arg in (expr_node.arguments or []):
            sub = _trace_dataflow(
                arg, param_names, func_body, assignments,
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
                    "path": [{"node": func_name, "type": "call", "line": _get_line(expr_node)}],
                    "expanded_from": short_name,
                }

        return {
            "origin": func_name,
            "origin_type": "call",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": func_name, "type": "call", "line": _get_line(expr_node)}],
        }

    # 5. 属性访问 js.StaticMemberExpression / js.ComputedMemberExpression
    if isinstance(expr_node, (js.StaticMemberExpression, js.ComputedMemberExpression)):
        full_text = _expr_to_str(expr_node)
        dep_params: List[int] = []
        sub = _trace_dataflow(
            expr_node.object, param_names, func_body, assignments,
            visited, depth + 1,
        )
        dep_params.extend(sub.get("dep_params", []))
        # 追踪 computed 的 property 部分
        if isinstance(expr_node, js.ComputedMemberExpression) and expr_node.property:
            sub_prop = _trace_dataflow(
                expr_node.property, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub_prop.get("dep_params", []))
        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{"node": full_text, "type": "selector", "line": _get_line(expr_node)}],
        }

    # 6. 二元运算 js.BinaryExpression
    if isinstance(expr_node, js.BinaryExpression):
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

    # 7. 逻辑运算 js.LogicalExpression（&& || ??）
    if isinstance(expr_node, js.LogicalExpression):
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

    # 8. 三元表达式 js.ConditionalExpression
    if isinstance(expr_node, js.ConditionalExpression):
        dep_params: List[int] = []
        for branch in (expr_node.consequent, expr_node.alternate):
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

    # 9. 模板字符串 js.TemplateLiteral
    if isinstance(expr_node, js.TemplateLiteral):
        dep_params: List[int] = []
        for expr in (expr_node.expressions or []):
            sub = _trace_dataflow(
                expr, param_names, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": "template",
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
        }

    # 10. 赋值表达式 js.AssignmentExpression（作为表达式使用时）
    if isinstance(expr_node, js.AssignmentExpression):
        sub = _trace_dataflow(
            expr_node.right, param_names, func_body, assignments,
            visited, depth + 1,
        )
        return sub

    # 11. 一元运算 js.UnaryExpression
    if isinstance(expr_node, js.UnaryExpression):
        return _trace_dataflow(
            expr_node.argument, param_names, func_body, assignments,
            visited, depth + 1,
        )

    # 12. await 表达式 js.AwaitExpression
    if isinstance(expr_node, js.AwaitExpression):
        return _trace_dataflow(
            expr_node.argument, param_names, func_body, assignments,
            visited, depth + 1,
        )

    # 13. 序列表达式 js.SequenceExpression
    if isinstance(expr_node, js.SequenceExpression):
        if expr_node.expressions:
            return _trace_dataflow(
                expr_node.expressions[-1], param_names, func_body, assignments,
                visited, depth + 1,
            )

    # 其他情况
    return {
        "origin": _expr_to_str(expr_node),
        "origin_type": "unknown",
        "dep_params": [],
        "path": [],
    }


def _analyze_function(func_node) -> FunctionSummary:
    """分析单个函数声明/表达式，生成摘要。"""
    name = func_node.id.name if hasattr(func_node, "id") and func_node.id else "<anonymous>"
    params = [p.name for p in func_node.params if isinstance(p, js.Identifier)]

    # 函数体：block 语句或箭头函数的表达式体
    body_stmts = []
    if hasattr(func_node.body, "body") and isinstance(func_node.body.body, list):
        body_stmts = func_node.body.body

    assignments = _find_assignments(body_stmts)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    # 箭头函数表达式体：直接作为返回值
    if not hasattr(func_node.body, "body") or not isinstance(func_node.body.body, list):
        flow = _trace_dataflow(func_node.body, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    # 块体中的 return 语句
    for node in _walk(body_stmts):
        if not isinstance(node, js.ReturnStatement) or node.argument is None:
            continue

        flow = _trace_dataflow(node.argument, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    loc = getattr(func_node, "loc", None)
    start_line = loc.start.line if loc else 0
    end_line = loc.end.line if loc else 0

    return FunctionSummary(
        name=name,
        params=params,
        line_range=[start_line, end_line],
        return_flow=return_flow,
    )


def _analyze_class_method(method_node, class_name: str) -> FunctionSummary:
    """分析类方法，方法名格式为 "ClassName.methodName"。"""
    method_name = method_node.key.name if isinstance(method_node.key, js.Identifier) else "<anonymous>"
    qualified_name = f"{class_name}.{method_name}" if class_name else method_name
    params = [p.name for p in method_node.params if isinstance(p, js.Identifier)]

    body_stmts = method_node.body.body if hasattr(method_node.body, "body") else []
    assignments = _find_assignments(body_stmts)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    for node in _walk(body_stmts):
        if not isinstance(node, js.ReturnStatement) or node.argument is None:
            continue

        flow = _trace_dataflow(node.argument, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    loc = getattr(method_node, "loc", None)
    start_line = loc.start.line if loc else 0
    end_line = loc.end.line if loc else 0

    return FunctionSummary(
        name=qualified_name,
        params=params,
        line_range=[start_line, end_line],
        return_flow=return_flow,
        is_method=True,
    )


def _analyze_var_function(decl) -> FunctionSummary:
    """从 VariableDeclarator 中提取函数摘要。"""
    name = decl.id.name if isinstance(decl.id, js.Identifier) else "<anonymous>"
    init = decl.init

    params = [p.name for p in init.params if isinstance(p, js.Identifier)]

    body_stmts = []
    if hasattr(init.body, "body") and isinstance(init.body.body, list):
        body_stmts = init.body.body

    assignments = _find_assignments(body_stmts)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    # 箭头函数表达式体
    if not hasattr(init.body, "body") or not isinstance(init.body.body, list):
        flow = _trace_dataflow(init.body, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    for node in _walk(body_stmts):
        if not isinstance(node, js.ReturnStatement) or node.argument is None:
            continue

        flow = _trace_dataflow(node.argument, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    loc = getattr(init, "loc", None)
    start_line = loc.start.line if loc else 0
    end_line = loc.end.line if loc else 0

    return FunctionSummary(
        name=name,
        params=params,
        line_range=[start_line, end_line],
        return_flow=return_flow,
    )


def _collect_functions(stmts, result: List[FunctionSummary]) -> None:
    """递归收集所有函数定义。"""
    for stmt in stmts:
        # 函数声明
        if isinstance(stmt, (js.FunctionDeclaration, js.AsyncFunctionDeclaration)):
            result.append(_analyze_function(stmt))
        # 类声明
        elif isinstance(stmt, js.ClassDeclaration):
            class_name = stmt.id.name if stmt.id else ""
            for member in stmt.body.body:
                if isinstance(member, js.ClassMethod):
                    result.append(_analyze_class_method(member, class_name))
        # 变量声明中的函数表达式/箭头函数
        elif isinstance(stmt, js.VariableDeclaration):
            for decl in stmt.declarations:
                if isinstance(decl, js.VariableDeclarator) and decl.init:
                    if isinstance(decl.init, (js.FunctionExpression, js.ArrowFunctionExpression)):
                        result.append(_analyze_var_function(decl))
        # 对象字面量属性中的方法
        elif isinstance(stmt, js.ExpressionStatement):
            expr = stmt.expression
            if isinstance(expr, js.AssignmentExpression):
                rhs = expr.right
                if isinstance(rhs, js.ObjectExpression):
                    for prop in (rhs.properties or []):
                        if isinstance(prop, js.Property) and prop.method:
                            if isinstance(prop.value, js.FunctionExpression):
                                _collect_obj_method(prop, result)

        # 递归进入块语句
        if hasattr(stmt, "body") and isinstance(stmt.body, list):
            _collect_functions(stmt.body, result)
        elif hasattr(stmt, "consequent") and isinstance(stmt.consequent, list):
            _collect_functions(stmt.consequent, result)
        # if/else 等控制流的 alternate
        if hasattr(stmt, "alternate") and isinstance(stmt.alternate, list):
            _collect_functions(stmt.alternate, result)


def _collect_obj_method(prop, result: List[FunctionSummary]) -> None:
    """收集对象字面量中定义的方法。"""
    method_name = prop.key.name if isinstance(prop.key, js.Identifier) else "<anonymous>"
    func_node = prop.value

    params = [p.name for p in func_node.params if isinstance(p, js.Identifier)]

    body_stmts = []
    if hasattr(func_node.body, "body") and isinstance(func_node.body.body, list):
        body_stmts = func_node.body.body

    assignments = _find_assignments(body_stmts)

    return_flow: List[ReturnFlowItem] = []
    order = 0

    for node in _walk(body_stmts):
        if not isinstance(node, js.ReturnStatement) or node.argument is None:
            continue

        flow = _trace_dataflow(node.argument, params, body_stmts, assignments)
        return_flow.append(ReturnFlowItem(
            order=order,
            return_index=0,
            origin=flow["origin"],
            origin_type=flow["origin_type"],
            dep_params=flow["dep_params"],
            path=flow.get("path", []),
        ))
        order += 1

    loc = getattr(func_node, "loc", None)
    start_line = loc.start.line if loc else 0
    end_line = loc.end.line if loc else 0

    result.append(FunctionSummary(
        name=method_name,
        params=params,
        line_range=[start_line, end_line],
        return_flow=return_flow,
        is_method=True,
    ))


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析一个 JS 文件，生成函数摘要。

    用 lesprima 解析 JS AST，遍历所有 FunctionDeclaration、
    FunctionExpression、ArrowFunctionExpression、ClassMethod 节点，
    对每个函数提取返回值数据流。

    :param file_path: 文件路径，用于记录在摘要中
    :param file_content: JS 源文件内容
    :return: FileSummary 实例，解析失败时返回空摘要
    """
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    try:
        tree = parse(file_content, {"loc": True})
    except Exception as e:
        logger.warning(f"解析 JS 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    functions: List[FunctionSummary] = []
    _collect_functions(tree.body, functions)

    return FileSummary(
        file=file_path,
        content_hash=content_hash,
        functions=functions,
    )


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 JS 文件，生成摘要。

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
        if not file_path.endswith(".js"):
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：对有自定义方法调用的函数做二次分析
    for file_path, content in files_dict.items():
        if not file_path.endswith(".js"):
            continue
        if file_path not in summaries:
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
