# -*- coding: utf-8 -*-
# @Time    : 2025
# @Author  : KunLun-M
# @File    : summary_generator.py

"""
    C/C++ 函数摘要生成器
    ~~~~~~~~~~~~
    用 tree-sitter-c 解析 C/C++ 源文件，提取每个函数的返回值数据流摘要。
    摘要只记录数据流事实，不做安全判定。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Set

from core.core_engine.function_summary import FileSummary, FunctionSummary, ReturnFlowItem
from utils.log import logger

# tree-sitter 初始化
try:
    import tree_sitter_c as tsc
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

    _C_TS_LANGUAGE = _TS_Language(tsc.language())
    _ts_parser = _TS_Parser(_C_TS_LANGUAGE)
    _HAS_TREE_SITTER = True
except Exception as e:
    logger.warning(f"tree-sitter-c 初始化失败: {e}")
    _ts_parser = None
    _HAS_TREE_SITTER = False

# C/C++ 字面量节点类型
_LITERAL_TYPES = frozenset({
    "number_literal", "string_literal", "char_literal",
    "true", "false",
    "null",
})

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


def _node_text(node) -> str:
    """获取 tree-sitter 节点的文本内容。"""
    return node.text.decode("utf-8")


def _is_literal(node) -> bool:
    """判断节点是否为字面量（数字、字符串、字符、布尔、NULL）。"""
    if node.type in _LITERAL_TYPES:
        return True
    if node.type == "identifier" and _node_text(node) in ("NULL", "nullptr", "true", "false"):
        return True
    return False


def _extract_param_names(param_list_node) -> List[str]:
    """从 parameter_list 节点提取形参名列表。

    C 的 parameter_list 子节点为 parameter_declaration。
    parameter_declaration > type + declarator (identifier)
    也可能只有 type (函数声明中省略参数名的情况)。
    """
    names: List[str] = []
    for child in param_list_node.children:
        if child.type == "parameter_declaration":
            name = _extract_declarator_name(child)
            if name:
                names.append(name)
    return names


def _extract_declarator_name(decl_node) -> str:
    """从 parameter_declaration 或 declaration 节点中提取声明符名称。

    C 的声明结构:
    - parameter_declaration > type + declarator (identifier)
    - parameter_declaration > type + declarator (pointer_declarator > declarator (identifier))
    - parameter_declaration > type + declarator (array_declarator > declarator (identifier))
    - declaration > type + init_declarator (declarator (identifier) [= value])
    """
    for child in decl_node.children:
        if child.type == "identifier":
            return _node_text(child)
        # 递归查找 pointer_declarator, array_declarator, parenthesized_declarator 等
        if child.type in (
            "pointer_declarator", "array_declarator",
            "parenthesized_declarator", "init_declarator",
            "parameter_declarator",
        ):
            name = _extract_declarator_name(child)
            if name:
                return name
    return ""


def _find_assignments(func_body) -> Dict[str, object]:
    """在函数体中收集赋值和声明的左值 -> 右值节点映射。

    处理:
    - declaration (带初始化器的声明, 如 int x = expr;)
    - assignment_expression (赋值, 如 x = expr;)
    - declaration 中的 init_declarator (声明+初始化)
    """
    assignments: Dict[str, object] = {}

    def _walk(node):
        for child in node.children:
            # 声明语句: int x = expr; 或 int x, y = expr;
            if child.type == "declaration":
                _process_declaration(child, assignments)
            # 赋值表达式: x = expr;
            elif child.type == "assignment_expression":
                _process_assignment(child, assignments)
            # 递归进入控制结构体
            elif child.type in (
                "if_statement", "for_statement", "while_statement",
                "do_statement", "switch_statement",
                "compound_statement", "expression_statement",
                "else_clause", "case_statement", "labeled_statement",
            ):
                _walk(child)
            # 也处理 return 以外的表达式语句
            elif child.type == "expression_statement":
                for expr in child.children:
                    if expr.type == "assignment_expression":
                        _process_assignment(expr, assignments)

    _walk(func_body)
    return assignments


def _process_declaration(decl_node, assignments: Dict[str, object]) -> None:
    """处理 declaration 节点，提取声明+初始化的映射。

    C 声明结构:
    declaration > type + init_declarator
    init_declarator > declarator + "=" + value
    或 declaration > type + declarator (仅声明，无初始化)
    """
    for child in decl_node.children:
        if child.type == "init_declarator":
            for sub in child.children:
                if sub.type == "declarator":
                    name = _extract_declarator_name(sub)
                    break
            else:
                continue
            if not name:
                continue
            # 找 "=" 后面的值
            found_eq = False
            for sub in child.children:
                if sub.type == "=" or sub.type == ",":
                    if sub.type == "=":
                        found_eq = True
                    continue
                if found_eq and sub.type not in (";", ","):
                    assignments[name] = sub
                    break
        elif child.type == "declarator":
            # 仅声明，无初始化值，跳过
            pass


def _process_assignment(assign_node, assignments: Dict[str, object]) -> None:
    """处理 assignment_expression 节点，提取赋值映射。

    C 赋值结构:
    assignment_expression > left + "=" + right
    left 通常是 identifier
    """
    left = None
    right = None
    found_eq = False

    for child in assign_node.children:
        if child.type == "=" or child.type.endswith("_assignment"):
            found_eq = True
            continue
        if not found_eq:
            left = child
        else:
            right = child

    if left and right:
        if left.type == "identifier":
            name = _node_text(left)
            assignments[name] = right
        elif left.type in ("dereference_expression", "subscript_expression",
                           "field_expression", "pointer_expression"):
            # 复杂左值 (如 *ptr = expr, arr[i] = expr, obj.field = expr)
            # 尝试提取基础变量名
            inner = left.child_by_field_name("argument") or left.child_by_field_name("array") or left.child_by_field_name("expression")
            if inner and inner.type == "identifier":
                name = _node_text(inner)
                assignments[name] = right


def _trace_dataflow(
    expr_node,
    param_names: List[str],
    file_lines: List[str],
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

        # 检查函数内是否有对 name 的赋值
        if assignments and name in assignments and func_body is not None:
            rhs_node = assignments[name]
            result = _trace_dataflow(
                rhs_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            result["path"].append({
                "node": name,
                "type": "assign",
                "line": rhs_node.start_point.row + 1,
            })
            return result

        return {
            "origin": name,
            "origin_type": "global",
            "dep_params": [],
            "path": [],
        }

    # 3. call_expression (函数调用)
    if expr_node.type == "call_expression":
        children = expr_node.children
        func_node = children[0] if children else None
        func_name = _node_text(func_node) if func_node else "<unknown>"

        dep_params: List[int] = []
        # 追踪函数名部分
        if func_node:
            sub = _trace_dataflow(
                func_node, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))

        # 收集参数节点的数据流信息（用于递归展开时做参数映射）
        arg_flows: List[dict] = []
        for arg in children[1:]:
            if arg.type == "argument_list":
                for a in arg.children:
                    if a.type == "," or a.type == "comment":
                        continue
                    sub = _trace_dataflow(
                        a, param_names, file_lines, func_body, assignments,
                        visited, depth + 1,
                    )
                    dep_params.extend(sub.get("dep_params", []))
                    arg_flows.append(sub)

        # 递归查摘要注册表，展开自定义函数调用
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
                return {
                    "origin": func_name,
                    "origin_type": "call",
                    "dep_params": all_deps,
                    "path": [{
                        "node": func_name,
                        "type": "call",
                        "line": expr_node.start_point.row + 1,
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
                "line": expr_node.start_point.row + 1,
            }],
        }

    # 4. field_expression (成员访问, 如 obj.field, ptr->field)
    if expr_node.type == "field_expression":
        full_text = _node_text(expr_node)
        dep_params: List[int] = []
        # argument 或 expression 字段为被访问的对象
        operand = expr_node.child_by_field_name("argument") or expr_node.child_by_field_name("expression")
        if operand:
            sub = _trace_dataflow(
                operand, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))

        return {
            "origin": full_text,
            "origin_type": "global",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [{
                "node": full_text,
                "type": "field",
                "line": expr_node.start_point.row + 1,
            }],
        }

    # 5. binary_expression (如 a + b)
    if expr_node.type == "binary_expression":
        left = expr_node.child_by_field_name("left")
        right = expr_node.child_by_field_name("right")
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

    # 6. unary_expression (如 !x, -x, *ptr, &x, sizeof(x))
    if expr_node.type == "unary_expression":
        operand = expr_node.child_by_field_name("operand") or expr_node.child_by_field_name("argument")
        if operand:
            return _trace_dataflow(
                operand, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )

    # 7. subscript_expression (数组下标, 如 arr[i])
    if expr_node.type == "subscript_expression":
        array = expr_node.child_by_field_name("array") or expr_node.child_by_field_name("argument")
        if array:
            return _trace_dataflow(
                array, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )

    # 8. parenthesized_expression (括号表达式, 递归展开)
    if expr_node.type == "parenthesized_expression":
        for child in expr_node.children:
            if child.type not in ("(", ")"):
                return _trace_dataflow(
                    child, param_names, file_lines, func_body, assignments,
                    visited, depth + 1,
                )

    # 9. type_conversion / cast_expression (类型转换)
    if expr_node.type in ("type_conversion", "cast_expression"):
        inner = expr_node.child_by_field_name("value") or expr_node.child_by_field_name("type")
        # value 是被转换的表达式
        value = expr_node.child_by_field_name("value")
        if value:
            return _trace_dataflow(
                value, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )

    # 10. conditional_expression (三元运算符 ? :)
    if expr_node.type == "conditional_expression":
        dep_params: List[int] = []
        condition = expr_node.child_by_field_name("condition")
        consequence = expr_node.child_by_field_name("consequence")
        alternative = expr_node.child_by_field_name("alternative")
        for part in (consequence, alternative):
            if part is None:
                continue
            sub = _trace_dataflow(
                part, param_names, file_lines, func_body, assignments,
                visited, depth + 1,
            )
            dep_params.extend(sub.get("dep_params", []))
        return {
            "origin": _node_text(expr_node),
            "origin_type": "unknown",
            "dep_params": list(dict.fromkeys(dep_params)),
            "path": [],
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
    """分析单个 return 语句中返回值的数据流。

    C 的 return_statement 中 "return" 关键字后紧跟表达式。
    expression_statement > return_statement
    """
    if assignments is None:
        assignments = {}

    # return_statement 的子节点: "return" + 表达式 + ";"
    expr_nodes: List[object] = []
    for child in return_node.children:
        # 跳过 "return" 关键字、分号和注释
        if child.type in ("return", ";") or child.type.endswith("_comment"):
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
    """处理单个 function_definition 节点，生成摘要。

    C 函数定义结构:
    function_definition
      > type (返回类型)
      > declarator (function_declarator)
          > declarator (identifier)  -- 函数名
          > parameters (parameter_list) -- 形参列表
      > body (compound_statement)  -- 函数体
    """
    func_name = ""
    param_names: List[str] = []
    func_body = None

    # 从 function_definition 找到 declarator (function_declarator)
    type_node = func_node.child_by_field_name("type")
    declarator_node = func_node.child_by_field_name("declarator")
    body_node = func_node.child_by_field_name("body")

    if body_node:
        func_body = body_node

    # 从 function_declarator 中提取函数名和参数列表
    if declarator_node:
        # 函数名在 function_declarator 的 declarator 字段 (或第一个 identifier 子节点)
        inner_decl = declarator_node.child_by_field_name("declarator")
        if inner_decl and inner_decl.type == "identifier":
            func_name = _node_text(inner_decl)
        else:
            # 备选: 遍历子节点找第一个 identifier (如 pointer_declarator 包裹的情况)
            for child in declarator_node.children:
                if child.type == "identifier" and not func_name:
                    func_name = _node_text(child)
                elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                    name = _extract_declarator_name(child)
                    if name and not func_name:
                        func_name = name

        # 参数列表在 function_declarator 的 parameters 字段
        param_node = declarator_node.child_by_field_name("parameters")
        if param_node and param_node.type == "parameter_list":
            param_names = _extract_param_names(param_node)

    # 备选: 如果上述方式未提取到，遍历直接子节点查找
    if not func_name or not param_names:
        for child in func_node.children:
            if child.type == "function_declarator" and not func_name:
                inner = child.child_by_field_name("declarator")
                if inner and inner.type == "identifier":
                    func_name = _node_text(inner)
                param_node = child.child_by_field_name("parameters")
                if param_node and param_node.type == "parameter_list":
                    param_names = _extract_param_names(param_node)
            elif child.type == "compound_statement" and not func_body:
                func_body = child

    if not func_name:
        return None

    start_line = func_node.start_point.row + 1
    end_line = func_node.end_point.row + 1

    # 收集函数体中的赋值
    assignments = _find_assignments(func_body) if func_body else {}

    # 找到所有 return 语句
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
            "if_statement", "for_statement", "while_statement",
            "do_statement", "switch_statement",
            "compound_statement", "else_clause",
            "case_statement", "labeled_statement",
            "expression_statement",
        ):
            _collect_returns(child, param_names, func_body, file_path,
                             file_lines, assignments, result)


def generate_file_summaries(file_path: str, file_content: str) -> FileSummary:
    """解析单个 C/C++ 文件，生成该文件所有函数的摘要。

    用 tree-sitter-c 解析 C AST，遍历所有 function_definition 节点，
    对每个函数提取返回值数据流。

    :param file_path: 文件路径，用于记录在摘要中
    :param file_content: C/C++ 源文件内容
    :return: FileSummary 实例，tree-sitter 不可用时返回空摘要
    """
    content_hash = hashlib.sha256(file_content.encode("utf-8")).hexdigest()

    if not _HAS_TREE_SITTER or _ts_parser is None:
        logger.debug(f"tree-sitter 不可用，跳过摘要生成: {file_path}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    try:
        tree = _ts_parser.parse(file_content.encode("utf-8"))
    except Exception as e:
        logger.warning(f"解析 C/C++ 文件失败 {file_path}: {e}")
        return FileSummary(file=file_path, content_hash=content_hash, functions=[])

    file_lines = file_content.splitlines()
    root = tree.root_node
    functions: List[FunctionSummary] = []

    # C 的 function_definition 可能嵌套在 translation_unit 下
    _walk_for_functions(root, file_path, file_lines, functions)

    return FileSummary(file=file_path, content_hash=content_hash, functions=functions)


def _walk_for_functions(
    node,
    file_path: str,
    file_lines: List[str],
    functions: List[FunctionSummary],
) -> None:
    """递归遍历 AST 查找 function_definition 节点。

    在 C 中，函数定义可能出现在 translation_unit 的顶层，
    也可能嵌套在其他结构中（如 struct 内的函数定义在某些扩展中）。
    """
    for child in node.children:
        if child.type == "function_definition":
            summary = _process_func_node(child, file_path, file_lines)
            if summary:
                functions.append(summary)
        # 递归进入可能包含函数定义的节点
        elif child.type in (
            "declaration",
            "type_definition",
            "struct_specifier",
            "union_specifier",
            "enum_specifier",
            "class_specifier",
            "namespace_definition",
            "translation_unit",
        ):
            _walk_for_functions(child, file_path, file_lines, functions)


def generate_summaries_for_target(
    target_path: str,
    files_dict: Dict[str, str],
) -> Dict[str, FileSummary]:
    """便捷入口：遍历所有 C/C++ 文件，生成摘要。

    两遍处理：
    1. 第一遍：生成所有文件的摘要，注册到全局注册表
    2. 第二遍：对有自定义函数调用的函数做二次分析（可递归展开）

    :param target_path: 扫描目标路径（仅用于日志）
    :param files_dict: {file_path: file_content} 字典
    :return: {file_path: FileSummary} 字典
    """
    global _summary_registry
    _summary_registry = {}  # 重置注册表

    summaries: Dict[str, FileSummary] = {}

    # C/C++ 文件扩展名
    _C_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hxx"})

    # 第一遍：生成所有摘要并注册
    for file_path, content in files_dict.items():
        import os
        _, ext = os.path.splitext(file_path)
        if ext not in _C_EXTENSIONS:
            continue
        logger.debug(f"生成函数摘要: {file_path}")
        fs = generate_file_summaries(file_path, content)
        summaries[file_path] = fs
        # 注册到全局注册表
        for fn in fs.functions:
            _summary_registry[fn.name] = fn

    # 第二遍：对有自定义函数调用的函数做二次分析
    for file_path, content in files_dict.items():
        import os
        _, ext = os.path.splitext(file_path)
        if ext not in _C_EXTENSIONS:
            continue
        old_fs = summaries[file_path]
        new_fs = generate_file_summaries(file_path, content)
        # 更新有变化的函数
        changed = False
        for i, fn in enumerate(new_fs.functions):
            if fn.return_flow:
                if i < len(old_fs.functions):
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
