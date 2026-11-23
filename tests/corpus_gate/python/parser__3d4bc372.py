#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    C/C++ AST Parser — C/C++ 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    使用 tree-sitter-c 解析 C/C++ 源码 AST，从 sink（敏感函数调用参数）
    反向追踪到 source（可控输入源），支持跨函数追踪。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
import traceback
import os
from typing import Optional, List, Dict, Set, Tuple, Any

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.c.builtin_knowledge import lookup as lookup_builtin, KNOWLEDGE as _BUILTIN_KNOWLEDGE
from core.core_engine.c.source_discovery import SourceRegistry, SourceInfo, discover_sources
from core.core_engine.c.summary_generator import lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager

# tree-sitter C AST 解析
try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

    _C_TS_LANGUAGE = _TS_Language(_tsc.language())
    _ts_parser = _TS_Parser(_C_TS_LANGUAGE)
    _HAS_TREE_SITTER = True
except Exception as e:
    logger.warning("[AST][C] tree-sitter-c 初始化失败: {}".format(e))
    _ts_parser = None
    _HAS_TREE_SITTER = False

# ---------------------------------------------------------------------------
# 全局状态（与 Go/Python parser 保持一致的模式）
# ---------------------------------------------------------------------------
scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存
_trace_cache = TraceCache("c")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# AST 缓存: file_path → tree
_ast_cache = {}

# 函数定义索引: (file_path, func_name) → (param_names, func_body_node, def_lineno, end_lineno)
_func_def_index = {}
_func_def_indexed_files = set()

_sd_registry = None  # Source Discovery 注册表

# ---------------------------------------------------------------------------
# C/C++ 可控输入源
# ---------------------------------------------------------------------------
C_CONTROLLED_SOURCES = [
    # argv/argc removed: CLI-only, not web-controllable
    # read/fread/fgets/getc/getdelim/recv/recvfrom/recvmsg removed:
    # file/network I/O functions, not user HTTP input
    "getenv", "secure_getenv",
    "scanf", "fscanf", "sscanf",
    "gets",
    "stdin", "FILE stdin", "std::cin",
    "cin",
]

# scanf family: writes to args after the format string (arg 0)
SCANF_FAMILY = {"scanf", "fscanf", "sscanf"}

# C/C++ 字面量节点类型
_LITERAL_NODE_TYPES = frozenset({
    "number_literal", "string_literal", "char_literal",
    "true", "false", "null",
})


# ---------------------------------------------------------------------------
# tree-sitter AST 辅助函数
# ---------------------------------------------------------------------------

def _node_text(node) -> str:
    """获取 tree-sitter 节点的文本内容。"""
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="ignore")


def _is_literal_node(node) -> bool:
    """检查 AST 节点是否为字面量。"""
    if node is None:
        return False
    if node.type in _LITERAL_NODE_TYPES:
        return True
    if node.type == "identifier" and _node_text(node) in ("NULL", "nullptr", "true", "false"):
        return True
    # 带符号的数字字面量: -42, +3.14
    if node.type == "unary_expression" and node.children:
        op = _node_text(node.children[0])
        if op in ("-", "+") and len(node.children) >= 2:
            return _is_literal_node(node.children[-1])
    return False


def _parse_c_ast(file_path):
    """用 tree-sitter 解析 C/C++ 文件，返回 AST tree（带缓存）。"""
    if file_path in _ast_cache:
        return _ast_cache[file_path]
    try:
        with open(file_path, "rb") as f:
            source = f.read()
        if _ts_parser is None:
            return None
        tree = _ts_parser.parse(source)
        _ast_cache[file_path] = tree
        return tree
    except Exception as e:
        logger.warning(f"[AST][C] C AST 解析失败: file={file_path}, error={e}")
        return None


def _get_source_lines(file_path):
    """读取源文件的所有行。"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []


def _c_line_to_text(file_path, lineno):
    """从源文件读取指定行的文本。"""
    lines = _get_source_lines(file_path)
    if lines and 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


def _get_call_func_text(call_node) -> str:
    """获取 call_expression 节点的函数名文本。"""
    if call_node is None or not call_node.children:
        return ""
    func_child = call_node.children[0]
    return _node_text(func_child)


def _get_call_func_name(call_node) -> Optional[str]:
    """获取 call_expression 的函数名（支持 identifier 和 field_expression）。"""
    if call_node is None or not call_node.children:
        return None
    func_child = call_node.children[0]
    if func_child.type == "identifier":
        return _node_text(func_child)
    elif func_child.type == "field_expression":
        return _node_text(func_child)
    elif func_child.type == "subscript_expression":
        return _node_text(func_child)
    return None


def _get_call_args_from_ast(call_node):
    """从 call_expression 节点提取参数 AST 节点列表（不含括号和逗号）。"""
    if call_node is None:
        return []
    for child in call_node.children:
        if child.type == "argument_list":
            args = []
            for arg_child in child.children:
                if arg_child.type not in ("(", ")", ","):
                    args.append(arg_child)
            return args
    return []


def _collect_identifiers_from_ast(node):
    """从 AST 节点中递归收集所有 identifier（变量名）。

    排除 C 关键字和类型名。
    """
    if node is None:
        return []

    _C_KEYWORDS = frozenset({
        "auto", "break", "case", "char", "const", "continue", "default", "do",
        "double", "else", "enum", "extern", "float", "for", "goto", "if",
        "inline", "int", "long", "register", "restrict", "return", "short",
        "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
        "unsigned", "void", "volatile", "while",
        # C99
        "bool", "true", "false", "restrict",
        # C11
        "alignas", "alignof", "atomic", "generic", "noreturn",
        "static_assert", "thread_local",
        # NULL
        "NULL", "nullptr",
        # 常见类型名
        "size_t", "ssize_t", "ptrdiff_t", "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "FILE", "stdin", "stdout", "stderr",
        "errno",
    })

    identifiers = []
    seen = set()

    def _walk(n):
        if n.type == "identifier":
            name = _node_text(n)
            if name and name not in _C_KEYWORDS and name not in seen:
                identifiers.append(name)
                seen.add(name)
        elif n.type == "field_expression":
            # a.b → 收集 a 作为变量
            if n.children and n.children[0].type == "identifier":
                base = _node_text(n.children[0])
                if base and base not in _C_KEYWORDS and base not in seen:
                    identifiers.append(base)
                    seen.add(base)
            # 继续递归（可能嵌套更深）
            for child in n.children:
                _walk(child)
        elif n.type == "subscript_expression":
            # arr[i] → 收集 arr
            array_node = n.child_by_field_name("array") or n.child_by_field_name("argument")
            if array_node and array_node.type == "identifier":
                name = _node_text(array_node)
                if name and name not in _C_KEYWORDS and name not in seen:
                    identifiers.append(name)
                    seen.add(name)
            for child in n.children:
                _walk(child)
        elif n.type == "call_expression":
            # 函数调用：只收集参数中的标识符
            for child in n.children:
                if child.type == "argument_list":
                    for arg_child in child.children:
                        if arg_child.type not in ("(", ")", ","):
                            _walk(arg_child)
        else:
            for child in n.children:
                _walk(child)

    _walk(node)
    return identifiers


# ---------------------------------------------------------------------------
# 函数查找辅助
# ---------------------------------------------------------------------------

def _find_enclosing_function(tree, lineno):
    """在 AST 中查找包含指定行号的函数定义。

    返回 (func_name, param_names, func_body_node, start_line, end_line) 或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        if node.type == "function_definition":
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= lineno <= end_line:
                func_name = ""
                param_names = []
                body_node = None
                declarator = node.child_by_field_name("declarator")
                body = node.child_by_field_name("body")

                if body:
                    body_node = body

                if declarator:
                    # 函数名
                    inner_decl = declarator.child_by_field_name("declarator")
                    if inner_decl and inner_decl.type == "identifier":
                        func_name = _node_text(inner_decl)
                    else:
                        # pointer_declarator 等包裹
                        for child in declarator.children:
                            if child.type == "identifier" and not func_name:
                                func_name = _node_text(child)
                            elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                                name = _extract_declarator_name_simple(child)
                                if name and not func_name:
                                    func_name = name

                    # 参数列表
                    param_node = declarator.child_by_field_name("parameters")
                    if param_node and param_node.type == "parameter_list":
                        param_names = _extract_param_names(param_node)

                # 备选
                if not func_name:
                    for child in node.children:
                        if child.type == "function_declarator" and not func_name:
                            inner = child.child_by_field_name("declarator")
                            if inner and inner.type == "identifier":
                                func_name = _node_text(inner)
                            p = child.child_by_field_name("parameters")
                            if p and p.type == "parameter_list":
                                param_names = _extract_param_names(p)
                        elif child.type == "compound_statement" and not body_node:
                            body_node = child

                if func_name:
                    result[0] = (func_name, param_names, body_node, start_line, end_line)
                    return

        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _extract_declarator_name_simple(decl_node) -> str:
    """从声明符节点中提取名称（简单版本）。"""
    for child in decl_node.children:
        if child.type == "identifier":
            return _node_text(child)
        if child.type in ("pointer_declarator", "array_declarator",
                          "parenthesized_declarator", "init_declarator",
                          "parameter_declarator"):
            name = _extract_declarator_name_simple(child)
            if name:
                return name
    return ""


def _extract_param_names(param_list_node) -> List[str]:
    """从 parameter_list 节点提取形参名列表。"""
    names = []
    if param_list_node is None:
        return names
    for child in param_list_node.children:
        if child.type == "parameter_declaration":
            name = _extract_declarator_name_simple(child)
            if name:
                names.append(name)
    return names


def _find_call_at_line(tree, lineno, func_name):
    """在 AST 中查找指定行号上的 call_expression 节点。

    匹配 func_name（支持 system、mysql_query 等）。
    """
    if tree is None:
        return None

    short_name = func_name.split("::")[-1] if "::" in func_name else func_name
    short_name = short_name.split(".")[-1] if "." in short_name else short_name

    def _search(node):
        if node.type == "call_expression":
            node_line = node.start_point[0] + 1
            if node_line == lineno:
                # 先递归搜索子节点，找内层调用
                for child in node.children:
                    result = _search(child)
                    if result:
                        return result

                func_text = _get_call_func_text(node)
                if func_name in func_text or short_name in func_text:
                    return node
                return None

        for child in node.children:
            result = _search(child)
            if result:
                return result
        return None

    return _search(tree.root_node)


# ---------------------------------------------------------------------------
# 分支约束追踪（if/else, switch/case）
# ---------------------------------------------------------------------------

def _extract_constraints_from_c_expr(cond_node):
    """从 C 条件表达式中提取 BranchConstraint 列表。

    支持的模式:
    - x == value         -> BranchConstraint(x, ==, value)
    - x != value         -> BranchConstraint(x, !=, value)
    - strcmp(x, "str") == 0  -> BranchConstraint(x, ==, "str")
    - strcmp(x, "str") != 0  -> BranchConstraint(x, !=, "str")
    - !strcmp(x, "str")      -> BranchConstraint(x, ==, "str")
    - x && y / x || y        -> 递归拆分
    """
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    if node_type == 'binary_expression':
        children = cond_node.children
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in children:
            if child.type in ('==', '!=', '>=', '<=', '>', '<', '&&', '||'):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        op_text = _node_text(op_node) if op_node else ''

        if op_text == '&&':
            if left_node:
                constraints.extend(_extract_constraints_from_c_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_c_expr(right_node))
            return constraints

        if op_text == '||':
            or_constraints = []
            if left_node:
                or_constraints.extend(_extract_constraints_from_c_expr(left_node))
            if right_node:
                or_constraints.extend(_extract_constraints_from_c_expr(right_node))
            # 同一变量的多个 == 值合并为 in 约束
            from collections import defaultdict
            eq_values = defaultdict(list)
            other = []
            for c in or_constraints:
                if c.op == '==' and c.var_name:
                    eq_values[c.var_name].append(c.value)
                else:
                    other.append(c)
            for var_name, values in eq_values.items():
                constraints.append(BranchConstraint(
                    var_name=var_name, op='in',
                    value=values if len(values) > 1 else values[0]))
            constraints.extend(other)
            return constraints

        # strcmp(x, "str") == 0 / != 0 模式
        if op_text in ('==', '!='):
            if left_node and right_node:
                strcmp_info = _extract_strcmp_constraint(left_node, right_node, op_text)
                if strcmp_info:
                    return [strcmp_info]
                strcmp_info = _extract_strcmp_constraint(right_node, left_node, op_text)
                if strcmp_info:
                    return [strcmp_info]

            # 普通比较: x == value / x != value
            if op_text in ('==', '!='):
                var_name = _get_c_var_name(left_node)
                if var_name:
                    value = _get_c_literal_value(right_node)
                    constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))

        return constraints

    if node_type == 'unary_expression':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == '!' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                # !strcmp(x, "str") -> strcmp == 0 的简写
                inner_constraints = _extract_constraints_from_c_expr(inner)
                if inner_constraints:
                    constraints = [c.negate() for c in inner_constraints]
                    return constraints
        return constraints

    if node_type == 'call_expression':
        func_node = None
        args = []
        for child in cond_node.children:
            if child.type == 'identifier':
                func_node = child
            elif child.type == 'argument_list':
                args = [c for c in child.children if c.type not in (',', '(', ')')]

        if func_node and args:
            func_name = _node_text(func_node)
            CTYPE_FUNCS = {'isdigit', 'isalpha', 'isalnum', 'isxdigit', 'isupper', 'islower', 'isprint', 'ispunct', 'isspace'}
            if func_name in CTYPE_FUNCS and len(args) >= 1:
                var_name = _get_c_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

        return constraints

    if node_type == 'parenthesized_expression':
        if cond_node.children and len(cond_node.children) >= 2:
            return _extract_constraints_from_c_expr(cond_node.children[1])

    return constraints


def _extract_strcmp_constraint(call_node, literal_node, op_text):
    """检查是否为 strcmp(x, "str") == 0 或 != 0 模式。

    返回 BranchConstraint 或 None。
    """
    if call_node is None or call_node.type != 'call_expression':
        return None
    callee = _get_call_func_name(call_node)
    if callee not in ('strcmp', 'strncmp', 'strcasecmp', 'strncasecmp', 'memcmp', 'bcmp'):
        return None
    args = _get_call_args_from_ast(call_node)
    if len(args) < 2:
        return None
    # 判断哪边是变量哪边是字面量
    var_name = _get_c_var_name(args[0])
    value = None
    if var_name:
        value = _get_c_literal_value(args[1])
    else:
        var_name = _get_c_var_name(args[1])
        if var_name:
            value = _get_c_literal_value(args[0])
    if not var_name or value is None:
        return None
    # strcmp 返回 0 表示相等
    literal_val = _get_c_literal_value(literal_node)
    if literal_val == 0:
        return BranchConstraint(var_name=var_name, op=op_text, value=value)
    if literal_val != 0:
        neg_op = '!=' if op_text == '==' else '=='
        return BranchConstraint(var_name=var_name, op=neg_op, value=value)
    return None


def _get_c_var_name(node):
    """从 tree-sitter C 节点提取变量名。"""
    if node is None:
        return None
    if node.type == 'identifier':
        return _node_text(node)
    if node.type == 'subscript_expression':
        # arr[i] -> arr
        array_node = node.child_by_field_name('argument') or (node.children[0] if node.children else None)
        if array_node and array_node.type == 'identifier':
            return _node_text(array_node)
    return None


def _collect_var_names_recursive(node, names):
    """递归收集 AST 节点中所有 identifier 变量名（用于三元分支变量收集）。"""
    if node is None:
        return
    if node.type == 'identifier':
        name = _node_text(node)
        if name:
            names.add(name)
        return
    for child in node.children:
        _collect_var_names_recursive(child, names)


def _get_c_literal_value(node):
    """从 tree-sitter C 节点提取字面量值。"""
    if node is None:
        return None
    if node.type == 'number_literal':
        text = _node_text(node).strip()
        try:
            if text.startswith('0x') or text.startswith('0X'):
                return int(text, 16)
            return int(text)
        except (ValueError, TypeError):
            try:
                return float(text)
            except (ValueError, TypeError):
                return text
    if node.type == 'string_literal':
        text = _node_text(node)
        if text.startswith('"') and text.endswith('"'):
            return text[1:-1]
        return text
    if node.type == 'char_literal':
        text = _node_text(node)
        # 'x' -> x
        if text.startswith("'") and text.endswith("'"):
            return text[1:-1]
        return text
    if node.type == 'identifier' and _node_text(node) in ('NULL', 'nullptr'):
        return None
    if node.type == 'true':
        return True
    if node.type == 'false':
        return False
    return None


def _check_sink_branch_constraints(tree, vul_lineno, var_name, func_body_node):
    """检查 sink 所在的分支是否有约束阻断。

    遍历函数体内的 if/switch 语句，判断 sink 是否在受约束的分支中。
    返回 True 表示应阻断（返回 (-1, 0)），False 表示不阻断。
    """
    if not func_body_node:
        return False

    for child in func_body_node.children:
        if child.type == 'if_statement':
            result = _check_if_branch_constraint(child, vul_lineno, var_name)
            if result is not None:
                return result
        elif child.type == 'switch_statement':
            result = _check_switch_branch_constraint(child, vul_lineno, var_name)
            if result is not None:
                return result
        elif child.type in ('while_statement', 'do_statement'):
            result = _check_while_constraint(child, vul_lineno, var_name)
            if result is not None:
                return result
        elif child.type == 'compound_statement':
            # 嵌套的 compound_statement（如 for/while 循环体），递归检查
            if _check_sink_branch_constraints(tree, vul_lineno, var_name, child):
                return True

    return False


def _check_if_branch_constraint(if_node, vul_lineno, var_name):
    """检查 if/else 分支约束。

    tree-sitter C if_statement 结构:
      if_statement
        ├── "if"
        ├── parenthesized_expression   ← 条件
        ├── compound_statement         ← if body
        └── else_clause                ← 可选
             ├── "else"
             ├── compound_statement    ← else body
             └── if_statement          ← else if

    返回 True（阻断）/ False（不阻断）/ None（vul_lineno 不在此 if 中）。
    """
    cond_node = None
    if_body = None
    else_body = None

    for child in if_node.children:
        if child.type == 'parenthesized_expression':
            cond_node = child
        elif child.type == 'compound_statement' and if_body is None:
            if_body = child
        elif child.type == 'else_clause':
            for ec in child.children:
                if ec.type == 'compound_statement':
                    else_body = ec
                elif ec.type == 'if_statement':
                    # else if: 递归处理
                    return _check_if_branch_constraint(ec, vul_lineno, var_name)

    if cond_node is None:
        return None

    # 提取 if body 和 else body 的行范围
    if_start = if_body.start_point[0] + 1 if if_body else None
    if_end = if_body.end_point[0] + 1 if if_body else None
    else_start = else_body.start_point[0] + 1 if else_body else None
    else_end = else_body.end_point[0] + 1 if else_body else None

    # 如果没有 else body，只用 if body 的行范围来判断
    # vul_lineno 必须在 if 或 else 的范围内
    in_if = if_start is not None and if_end is not None and if_start <= vul_lineno <= if_end
    in_else = else_start is not None and else_end is not None and else_start <= vul_lineno <= else_end

    if not in_if and not in_else:
        return None

    # 从条件表达式中提取内部表达式（去掉括号）
    inner_cond = None
    if cond_node.children and len(cond_node.children) >= 2:
        inner_cond = cond_node.children[1]

    constraints = _extract_constraints_from_c_expr(inner_cond)

    # 检查约束是否匹配 var_name
    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][C] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!=', 'not in'):
            logger.info("[AST][C] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_while_constraint(while_node, vul_lineno, var_name):
    """检查 while 循环条件约束。

    tree-sitter C while_statement 结构:
      while_statement
        ├── "while"
        ├── parenthesized_expression   ← 条件
        └── compound_statement         ← 循环体

    tree-sitter C do_statement 结构:
      do_statement
        ├── "do"
        ├── compound_statement         ← 循环体
        ├── "while"
        └── parenthesized_expression   ← 条件

    如果 sink 在 while 体内，且条件中有 var_name 的等值约束 → 阻断。
    返回 True（阻断）/ False（不阻断）/ None（vul_lineno 不在此 while 中）。
    """
    if not vul_lineno:
        return None

    vul_lineno = int(vul_lineno)

    cond_node = None
    body_node = None

    for child in while_node.children:
        if child.type == 'parenthesized_expression':
            cond_node = child
        elif child.type == 'compound_statement' and body_node is None:
            body_node = child

    if body_node is None:
        return None

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return None

    if cond_node is None:
        return False

    # 从条件表达式中提取内部表达式（去掉括号）
    inner_cond = None
    if cond_node.children and len(cond_node.children) >= 2:
        inner_cond = cond_node.children[1]

    constraints = _extract_constraints_from_c_expr(inner_cond)

    for c in constraints:
        if c.var_name == var_name and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][C] While constraint BLOCKS: while ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_switch_branch_constraint(switch_node, vul_lineno, var_name):
    """检查 switch/case 分支约束。

    tree-sitter C switch_statement 结构:
      switch_statement
        ├── "switch"
        ├── parenthesized_expression    ← switch 表达式
        └── compound_statement         ← switch body
             ├── case_statement         ← case 值
             │    ├── "case"
             │    ├── char_literal / number_literal
             │    ├── ":"
             │    └── ...               ← case body
             └── case_statement         ← default
                  ├── "default"
                  ├── ":"
                  └── ...

    如果 sink 在非 default case 中 → 阻断（变量值被限定）。
    如果在 default 中 → 不阻断。

    返回 True（阻断）/ False（不阻断）/ None（vul_lineno 不在此 switch 中）。
    """
    switch_body = None
    for child in switch_node.children:
        if child.type == 'compound_statement':
            switch_body = child
            break

    if switch_body is None:
        return None

    for case_node in switch_body.children:
        if case_node.type != 'case_statement':
            continue

        case_start = case_node.start_point[0] + 1
        case_end = case_node.end_point[0] + 1

        if not (case_start <= vul_lineno <= case_end):
            continue

        # vul_lineno 在此 case 中
        first_child = case_node.children[0] if case_node.children else None
        first_text = _node_text(first_child) if first_child else ''

        if first_text == 'default':
            # default 分支不阻断
            return False

        # 非 default case: sink 在固定值分支中，阻断
        case_value = None
        for cc in case_node.children:
            if cc.type in ('char_literal', 'number_literal', 'string_literal'):
                case_value = _get_c_literal_value(cc)
                break

        logger.info("[AST][C] Branch constraint BLOCKS: switch case (value={}) at line {}".format(
            case_value, vul_lineno))
        return True

    return None


def _find_assignment_at_line(tree, lineno, var_name, to_line=None):
    """在 AST 中查找 <= lineno 的 var_name 赋值节点。

    返回 (lhs_name, rhs_node, assign_lineno) 或 None。
    支持多种 C 赋值形式：
    - declaration > init_declarator (带初始化的声明)
    - expression_statement > assignment_expression
    - expression_statement > declaration > init_declarator
    """
    if tree is None:
        return None

    result = [None]
    search_limit = to_line if to_line else lineno

    def _search(node):
        if result[0] is not None:
            return
        node_line = node.start_point[0] + 1
        if node_line > search_limit:
            return  # 超过搜索范围

        # declaration > init_declarator > declarator(identifier) = value
        if node.type == "declaration":
            for child in node.children:
                if child.type == "init_declarator":
                    _check_init_declarator(child, lineno)
                elif child.type == "declarator":
                    # 无初始化的声明，跳过
                    pass
            # 继续递归子节点
            for child in node.children:
                _search(child)
            return

        # expression_statement > assignment_expression
        if node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment_expression":
                    _check_assignment(child, lineno)
                elif child.type == "declaration":
                    _search(child)
            return

        # 直接的 assignment_expression（可能在 for 循环等中）
        if node.type == "assignment_expression":
            _check_assignment(node, lineno)
            for child in node.children:
                _search(child)
            return

        for child in node.children:
            _search(child)

    def _check_init_declarator(init_decl, limit):
        if result[0] is not None:
            return
        name = ""
        value_node = None
        found_eq = False
        for sub in init_decl.children:
            if sub.type in ("declarator", "pointer_declarator"):
                name = _extract_declarator_name_simple(sub)
            elif sub.type == "identifier" and not found_eq and name == "":
                name = _node_text(sub).strip()
            elif sub.type == "=":
                found_eq = True
            elif found_eq and sub.type not in (";", ",") and value_node is None:
                value_node = sub

        if name == var_name and value_node is not None:
            decl_line = init_decl.start_point[0] + 1
            if decl_line <= limit:
                result[0] = (name, value_node, decl_line)

    def _check_assignment(assign_node, limit):
        if result[0] is not None:
            return
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
                if right is None:
                    right = child

        if left is not None and right is not None:
            lhs_name = ""
            if left.type == "identifier":
                lhs_name = _node_text(left)
            elif left.type == "subscript_expression":
                arr = left.child_by_field_name("array") or left.child_by_field_name("argument")
                if arr and arr.type == "identifier":
                    lhs_name = _node_text(arr)

            if lhs_name == var_name:
                assign_line = assign_node.start_point[0] + 1
                if assign_line <= limit:
                    result[0] = (lhs_name, right, assign_line)

    _search(tree.root_node)
    return result[0]


def _find_call_with_var_as_arg(tree, to_line, var_name, to_line_limit):
    """在 AST 中查找 <= to_line 的、以 var_name 作为参数的 call_expression。

    返回 (call_node, arg_index, call_lineno) 或 None。
    用于处理 snprintf(cmd, ...) 等通过参数修改变量的模式。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        node_line = node.start_point[0] + 1
        if node_line > to_line_limit:
            return

        if node.type == "call_expression":
            call_line = node.start_point[0] + 1
            if call_line <= to_line_limit:
                args = _get_call_args_from_ast(node)
                for idx, arg in enumerate(args):
                    if arg.type == "identifier" and _node_text(arg) == var_name:
                        # 优先使用最近（行号最大）的匹配
                        if result[0] is None or call_line > result[0][2]:
                            result[0] = (node, idx, call_line)
            # 不递归进入 call_expression 子节点（避免匹配内层调用）
            return

        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _get_callee_name(call_node):
    """从 call_expression 节点提取被调用函数名。"""
    if call_node is None:
        return None
    func = call_node.child_by_field_name("function")
    if func:
        return _node_text(func)
    # 回退：第一个 identifier 子节点
    for child in call_node.children:
        if child.type == "identifier":
            return _node_text(child)
    return None


def _find_function_def_in_ast(tree, func_name):
    """在 AST 中查找函数定义节点。

    返回 (func_name, param_names, func_body_node, start_line, end_line) 或 None。
    """
    if tree is None:
        return None

    short_name = func_name.split("::")[-1] if "::" in func_name else func_name

    def _search(node):
        if node.type == "function_definition":
            func_n = ""
            param_names = []
            body_node = None

            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if body:
                body_node = body

            if declarator:
                inner_decl = declarator.child_by_field_name("declarator")
                if inner_decl and inner_decl.type == "identifier":
                    func_n = _node_text(inner_decl)
                else:
                    for child in declarator.children:
                        if child.type == "identifier" and not func_n:
                            func_n = _node_text(child)
                        elif child.type in ("pointer_declarator", "parenthesized_declarator"):
                            name = _extract_declarator_name_simple(child)
                            if name and not func_n:
                                func_n = name

                param_node = declarator.child_by_field_name("parameters")
                if param_node and param_node.type == "parameter_list":
                    param_names = _extract_param_names(param_node)

            if not func_n:
                for child in node.children:
                    if child.type == "function_declarator" and not func_n:
                        inner = child.child_by_field_name("declarator")
                        if inner and inner.type == "identifier":
                            func_n = _node_text(inner)
                        p = child.child_by_field_name("parameters")
                        if p and p.type == "parameter_list":
                            param_names = _extract_param_names(p)
                    elif child.type == "compound_statement" and not body_node:
                        body_node = child

            if func_n == short_name:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                return (func_n, param_names, body_node, start_line, end_line)

        for child in node.children:
            r = _search(child)
            if r:
                return r
        return None

    return _search(tree.root_node)


# ---------------------------------------------------------------------------
# 函数定义索引
# ---------------------------------------------------------------------------

def _build_func_def_index(file_path):
    """预扫描文件，索引所有 function_definition。"""
    if file_path in _func_def_indexed_files:
        return
    _func_def_indexed_files.add(file_path)

    tree = _parse_c_ast(file_path)
    if tree is None:
        return

    def _walk(node):
        if node.type == "function_definition":
            func_n = ""
            param_names = []
            body_node = None

            declarator = node.child_by_field_name("declarator")
            body = node.child_by_field_name("body")
            if body:
                body_node = body

            if declarator:
                inner_decl = declarator.child_by_field_name("declarator")
                if inner_decl and inner_decl.type == "identifier":
                    func_n = _node_text(inner_decl)
                else:
                    for child in declarator.children:
                        if child.type == "identifier" and not func_n:
                            func_n = _node_text(child)
                        elif child.type in ("pointer_declarator", "parenthesized_declarator", "function_declarator"):
                            if child.type == "function_declarator":
                                fn_id = child.child_by_field_name("declarator")
                                if fn_id and fn_id.type == "identifier":
                                    name = _node_text(fn_id)
                                else:
                                    name = _extract_declarator_name_simple(child)
                            else:
                                name = _extract_declarator_name_simple(child)
                            if name and not func_n:
                                func_n = name

                param_node = declarator.child_by_field_name("parameters")
                if param_node and param_node.type == "parameter_list":
                    param_names = _extract_param_names(param_node)

            if not func_n:
                for child in node.children:
                    if child.type == "function_declarator" and not func_n:
                        inner = child.child_by_field_name("declarator")
                        if inner and inner.type == "identifier":
                            func_n = _node_text(inner)
                        p = child.child_by_field_name("parameters")
                        if p and p.type == "parameter_list":
                            param_names = _extract_param_names(p)
                    elif child.type == "compound_statement" and not body_node:
                        body_node = child

            if func_n and (file_path, func_n) not in _func_def_index:
                start_line = node.start_point[0] + 1
                end_line = node.end_point[0] + 1
                _func_def_index[(file_path, func_n)] = (param_names, body_node, start_line, end_line)

        for child in node.children:
            _walk(child)

    _walk(tree.root_node)


def _build_func_def_index_cross_file():
    """预扫描所有 C/C++ 文件的函数定义（跨文件索引）。"""
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, "pre_result"):
        return
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get("language") in ("c", "cpp", "c++"):
            _build_func_def_index(other_fp)


# ---------------------------------------------------------------------------
# 可控源判定
# ---------------------------------------------------------------------------

def _is_controllable_source(expr_str, controlled_params=None):
    """检查表达式是否是可控输入源。

    C/C++ 可控源包括 argv、getenv、scanf/fgets 等标准输入。
    """
    if controlled_params is None:
        controlled_params = is_controlled_params

    for cp in controlled_params:
        if cp in expr_str:
            return True

    for src in C_CONTROLLED_SOURCES:
        if src in expr_str:
            return True

    # Source Discovery: 检查用户自定义 source
    if _sd_registry and _sd_registry.is_source_member(expr_str):
        return True

    return False


def _is_repair_function(expr_str, repair_functions=None):
    """
    检查表达式是否包含修复函数 — 精确匹配函数名。
    """
    if repair_functions is None:
        repair_functions = is_repair_functions

    if not repair_functions:
        pass  # 继续检查 builtin

    for rf in repair_functions:
        # 精确匹配：expr_str 就是函数名、或以 "func_name(" 开头
        if expr_str == rf or expr_str.startswith(rf + "("):
            return True

    # 也检查 builtin_knowledge 中标记 safe 的函数（精确匹配）
    for func_name in _BUILTIN_KNOWLEDGE:
        knowledge = _BUILTIN_KNOWLEDGE[func_name]
        if knowledge.get("safe") and (expr_str == func_name or expr_str.startswith(func_name + "(")):
            return True

    return False


# ---------------------------------------------------------------------------
# 参数分割工具
# ---------------------------------------------------------------------------

def _split_args_respecting_parens(args_str):
    """分割函数参数字符串，正确处理嵌套括号和引号内的逗号。"""
    if not args_str or not args_str.strip():
        return []
    args = []
    current = ""
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_string:
            current += ch
            if ch == "\\" and i + 1 < len(args_str):
                current += args_str[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ("\"", "'", "`"):
            in_string = True
            string_char = ch
            current += ch
        elif ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            args.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    if current.strip():
        args.append(current.strip())
    return args


# ---------------------------------------------------------------------------
# 函数摘要初始化
# ---------------------------------------------------------------------------

def _init_function_summaries(file_path):
    """初始化当前文件及依赖文件的函数摘要（带缓存）。"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.c.summary_generator import generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, "target_directory"):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, "pre_result"):
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, "pre_result"):
            for fp, data in pt.pre_result.items():
                if data.get("language") in ("c", "cpp", "c++"):
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            files_dict[fp] = f.read()
                    except Exception:
                        pass
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                files_dict[file_path] = f.read()
        except Exception:
            pass

        if files_dict:
            cached = cache_mgr.load_or_generate(target_dir, files_dict)
            need_generate = {fp: content for fp, content in files_dict.items()
                             if not cached.get(fp) or not cached[fp].functions}
            if need_generate:
                new_summaries = generate_summaries_for_target(target_dir, need_generate)
                for fp, fs in new_summaries.items():
                    cached[fp] = fs
                    cache_mgr.save_file_summary(target_dir, fp, fs)
            _file_summaries = cached
            logger.debug("[AST][C] 摘要初始化完成: {} 个文件".format(len(_file_summaries)))

        _summaries_initialized = True
    except Exception as e:
        logger.warning("[AST][C] 摘要初始化失败: {}".format(e))


# ---------------------------------------------------------------------------
# 反向污点追踪核心
# ---------------------------------------------------------------------------

def _trace_variable_in_lines(file_path, var_name, from_line, to_line,
                              repair_functions=None, controlled_params=None,
                              depth=0, max_depth=10, visited=None):
    """在指定行范围内追踪变量的数据流（缓存包装层）。

    返回: (code, source_lineno) 元组
        code: 1 (可控), 2 (已修复), 3 (未确认), -1 (不可控)
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 顶层调用查缓存
    if depth == 0 and file_path and to_line:
        cached = _trace_cache.get(file_path, var_name, int(to_line))
        if cached is not None:
            return (cached[0], cached[2] if len(cached) > 2 else to_line)

    code, source_lineno = _trace_variable_in_lines_impl(
        file_path, var_name, from_line, to_line,
        repair_functions, controlled_params, depth, max_depth, visited
    )

    # 顶层调用写缓存（仅确定性结果）
    if depth == 0 and file_path and to_line and code in (1, 2, -1):
        _trace_cache.put(file_path, var_name, int(to_line), (code, [], source_lineno))

    return (code, source_lineno)


def _trace_variable_in_lines_impl(file_path, var_name, from_line, to_line,
                                  repair_functions, controlled_params,
                                  depth, max_depth, visited=None):
    """在指定行范围内追踪变量的数据流（实现层）。

    使用 tree-sitter AST 查找 var_name 的赋值，按节点类型分派分析。

    算法：
    1. 解析文件 AST
    2. 找到包含 vul_lineno 的函数体
    3. 在函数体内从 to_line 向上查找 var_name 的赋值
    4. 分析 RHS：字面量/变量/函数调用/表达式
    5. 如果 var_name 是函数形参，追踪调用点
    """
    if depth > max_depth:
        return (-1, 0)

    if visited is None:
        visited = set()
    trace_key = (file_path, var_name, int(to_line))
    if trace_key in visited:
        logger.debug("[AST][C] Circular trace detected: {}@{}".format(var_name, to_line))
        return (-1, 0)
    visited.add(trace_key)

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    tree = _parse_c_ast(file_path)
    if not tree:
        logger.debug("[AST][C] 无法解析 AST: {}".format(file_path))
        return (-1, 0)

    # 找到包含 to_line 的函数体
    func_info = _find_enclosing_function(tree, to_line)
    if not func_info:
        logger.debug("[AST][C] 未找到包含行 {} 的函数".format(to_line))
        return (-1, 0)

    func_name, param_names, body_node, func_start, func_end = func_info

    # ---- 检查 var_name 是否直接是可控源 ----
    if _is_controllable_source(var_name, controlled_params):
        logger.debug("[AST][C] Variable {} is controllable source".format(var_name))
        return (1, to_line)

    # argv/argc removed: CLI-only, not web-controllable

    # ---- 检查 var_name 是否是函数形参 ----
    if var_name in param_names:
        logger.debug("[AST][C] Variable {} is a parameter of function {}, return code=5".format(
            var_name, func_name))
        return (5, func_name)

    # ---- 在函数体内查找 var_name 的赋值 ----
    assign_result = _find_assignment_at_line(tree, to_line, var_name, to_line)
    if assign_result:
        lhs_name, rhs_node, assign_lineno = assign_result

        # 分析 RHS
        result = _analyze_rhs_node(
            rhs_node, var_name, file_path, assign_lineno, to_line,
            repair_functions, controlled_params, depth, max_depth, visited
        )
        if result is not None:
            code, src_lineno = result
            # code=1(可控) 或 code=2(已修复) 是确定性结果，直接返回
            # code=-1(不可控) 但赋值来源是 safe 函数（如 malloc）时，
            # 变量内容可能被后续写入覆盖，需继续检查 _find_call_with_var_as_arg
            if code in (1, 2):
                # 分支约束检查：只在可控(code=1)时检查
                if code == 1 and func_info:
                    _, _, body_node, _, _ = func_info
                    if _check_sink_branch_constraints(tree, to_line, var_name, body_node):
                        logger.info("[AST][C] Branch constraint BLOCKS var {} at line {}".format(var_name, to_line))
                        return (-1, 0)
                return result
            if code == -1:
                rhs_text = _node_text(rhs_node)
                callee = _get_call_func_name(rhs_node) if rhs_node and rhs_node.type == "call_expression" else None
                if callee and lookup_builtin(callee) and lookup_builtin(callee).get("safe"):
                    logger.debug("[AST][C] Variable {} assigned from safe function {}, checking subsequent writes".format(
                        var_name, callee))
                    # 不返回，继续到 _find_call_with_var_as_arg 检查后续写入
                else:
                    return result

    # ---- 查找以 var_name 作为参数的函数调用（如 snprintf(cmd, ...)）----
    call_result = _find_call_with_var_as_arg(tree, to_line, var_name, to_line - 1)
    if call_result:
        call_node, arg_index, call_lineno = call_result
        callee_name = _get_call_func_name(call_node)
        if callee_name:
            knowledge = lookup_builtin(callee_name)
            args = _get_call_args_from_ast(call_node)
            if knowledge and (arg_index in knowledge.get("passthrough", []) or arg_index in knowledge.get("param_flow", {})):
                logger.debug("[AST][C] Variable {} is passthrough arg {} of {}".format(
                    var_name, arg_index, callee_name))
                # 检查其他参数是否包含可控源
                for i, arg in enumerate(args):
                    if i == arg_index:
                        continue
                    if _is_literal_node(arg):
                        continue
                    arg_text = _node_text(arg)
                    if _is_controllable_source(arg_text, controlled_params):
                        logger.debug("[AST][C] Passthrough arg {} of {} is controllable: {}".format(
                            i, callee_name, arg_text[:80]))
                        return (1, call_lineno)
                    # 递归追踪参数中的变量
                    sub_vars = _collect_identifiers_from_ast(arg)
                    for sv in sub_vars:
                        sub_code, sub_lineno = _trace_variable_in_lines(
                            file_path, sv, call_lineno, call_lineno,
                            repair_functions, controlled_params, depth + 1, max_depth, visited
                        )
                        if sub_code == 1:
                            return (1, sub_lineno)

            # param_flow check: output arg inherits controllability from input args
            param_flow = knowledge.get("param_flow", {})
            if knowledge and param_flow and arg_index in param_flow:
                source_info = param_flow[arg_index]
                if isinstance(source_info, str):
                    # 隐式数据源（如 "stdin", "network"）— 直接标记为可控
                    logger.debug("[AST][C] Variable {} is output arg {} of {} with implicit source {}".format(
                        var_name, arg_index, callee_name, source_info))
                    return (1, call_lineno)
                elif isinstance(source_info, int) and source_info < len(args):
                    pt_arg = args[source_info]
                    if not _is_literal_node(pt_arg):
                        pt_text = _node_text(pt_arg)
                        if _is_controllable_source(pt_text, controlled_params):
                            logger.debug("[AST][C] Write target {} inherits controllability from param_flow arg {}".format(
                                var_name, source_info))
                            return (1, call_lineno)
                        pt_vars = _collect_identifiers_from_ast(pt_arg)
                        for pv in pt_vars:
                            if pv == var_name:
                                continue
                            if _is_controllable_source(pv, controlled_params):
                                return (1, call_lineno)
                            sub_code, _ = _trace_variable_in_lines(
                                file_path, pv, call_lineno, call_lineno,
                                repair_functions, controlled_params, depth + 1, max_depth, visited
                            )
                            if sub_code == 1:
                                return (1, call_lineno)

    # ---- 文本回退：逐行扫描 ----
    return _text_trace_variable(file_path, var_name, to_line,
                                repair_functions, controlled_params, depth, max_depth, visited)


def _analyze_rhs_node(rhs_node, var_name, file_path, lineno, to_line,
                      repair_functions, controlled_params, depth, max_depth, visited=None):
    """根据 RHS AST 节点类型分派分析。

    返回: (code, source_lineno) 如果确定，None 如果需要继续扫描。
    """
    rhs_text = _node_text(rhs_node)

    # 快速检查：可控源
    if _is_controllable_source(rhs_text, controlled_params):
        logger.debug("[AST][C] Variable {} RHS is controllable source: {}".format(
            var_name, rhs_text[:80]))
        return (1, lineno)

    # 快速检查：修复函数（仅检查 repair_functions 列表，不含 builtin safe）
    if repair_functions:
        for rf in repair_functions:
            if rf in rhs_text:
                logger.debug("[AST][C] Variable {} RHS is repaired: {}".format(
                    var_name, rhs_text[:80]))
                return (2, lineno)

    node_type = rhs_node.type

    # 字面量 → 安全
    if _is_literal_node(rhs_node):
        return (-1, 0)

    # 函数调用
    if node_type == "call_expression":
        return _handle_call_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth, visited
        )

    # 字符串拼接 (binary_expression with +)
    if node_type == "binary_expression":
        return _handle_binary_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth, visited
        )

    # 简单变量赋值: x = y
    if node_type == "identifier":
        name = rhs_text
        if name == var_name:
            return None  # 自赋值，跳过
        if _is_controllable_source(name, controlled_params):
            return (1, lineno)
        return _trace_variable_in_lines(
            file_path, name, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth, visited
        )

    # subscript_expression (如 argv[1])
    if node_type == "subscript_expression":
        array = rhs_node.child_by_field_name("array") or rhs_node.child_by_field_name("argument")
        if array:
            array_text = _node_text(array)
            # argv/argc removed: CLI-only, not web-controllable
            if _is_controllable_source(array_text, controlled_params):
                return (1, lineno)
            if array.type == "identifier":
                return _trace_variable_in_lines(
                    file_path, array_text, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth, visited
                )

    # field_expression (如 obj.field, ptr->field)
    if node_type == "field_expression":
        operand = (rhs_node.child_by_field_name("argument")
                   or rhs_node.child_by_field_name("expression"))
        if operand:
            operand_text = _node_text(operand)
            if _is_controllable_source(operand_text, controlled_params):
                return (1, lineno)
            if operand.type == "identifier":
                return _trace_variable_in_lines(
                    file_path, operand_text, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth, visited
                )

    # parenthesized_expression → 解包
    if node_type == "parenthesized_expression":
        for child in rhs_node.children:
            if child.type not in ("(", ")"):
                return _analyze_rhs_node(
                    child, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth, visited
                )

    # cast_expression / type_conversion → 追踪被转换的值
    if node_type in ("cast_expression", "type_conversion"):
        value = rhs_node.child_by_field_name("value")
        if value:
            return _analyze_rhs_node(
                value, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth, visited
            )

    # unary_expression (如 !x, -x, *ptr, &x, sizeof(x))
    if node_type == "unary_expression":
        operand = rhs_node.child_by_field_name("operand") or rhs_node.child_by_field_name("argument")
        if operand:
            return _analyze_rhs_node(
                operand, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth, visited
            )

    # pointer_expression / dereference_expression → 追踪被解引用的变量
    if node_type in ("pointer_expression", "dereference_expression"):
        operand = rhs_node.child_by_field_name("operand") or rhs_node.child_by_field_name("argument")
        if operand:
            return _analyze_rhs_node(
                operand, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth, visited
            )

    # conditional_expression (三元运算符 ? :)
    if node_type == "conditional_expression":
        condition = rhs_node.child_by_field_name("condition")
        consequence = rhs_node.child_by_field_name("consequence")
        alternative = rhs_node.child_by_field_name("alternative")

        # 提取三元条件约束
        constraints = _extract_constraints_from_c_expr(condition)

        # 收集 true/false 分支中的变量名
        true_names = set()
        false_names = set()
        if consequence:
            _collect_var_names_recursive(consequence, true_names)
        if alternative:
            _collect_var_names_recursive(alternative, false_names)

        # 检查约束是否与分支中的变量匹配
        for c in constraints:
            c_name = c.var_name
            # var_name (追踪变量如 result) 不在条件约束中，但条件约束的变量（如 cmd）在分支中
            # 所以：约束变量在 true 分支 + op== → 阻断 true 分支
            #       约束变量在 false 分支 + op!= → 阻断 false 分支
            if c.op in ('==', 'in', 'type_validated', 'regex_validated') and c_name in true_names and c_name not in false_names:
                logger.info("[AST][C] Ternary constraint BLOCKS: {} {} {} at line {}".format(
                    c_name, c.op, c.value, lineno))
                return (-1, 0)
            if c.op == '!=' and c_name in false_names and c_name not in true_names:
                logger.info("[AST][C] Ternary constraint BLOCKS: {} {} {} at line {}".format(
                    c_name, c.op, c.value, lineno))
                return (-1, 0)

        # 不受约束，继续追踪两个分支
        for part in (consequence, alternative):
            if part:
                result = _analyze_rhs_node(
                    part, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth, visited
                )
                if result and result[0] in (1, 2):
                    return result
        return None

    # 其他：收集标识符逐一追踪
    var_names = _collect_identifiers_from_ast(rhs_node)
    for vn in var_names:
        if vn == var_name:
            continue
        if _is_controllable_source(vn, controlled_params):
            return (1, lineno)
        r = _trace_variable_in_lines(
            file_path, vn, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth, visited
        )
        if r[0] in (1, 2):
            return r

    return None


def _handle_call_expression_rhs(call_node, var_name, file_path, lineno, to_line,
                                repair_functions, controlled_params, depth, max_depth, visited=None):
    """处理函数调用赋值的 RHS 分析。"""
    func_text = _get_call_func_text(call_node)
    args = _get_call_args_from_ast(call_node)

    # 检查内置知识库
    knowledge = lookup_builtin(func_text)
    if knowledge:
        if knowledge.get("safe") and not knowledge.get("passthrough"):
            logger.debug("[AST][C] RHS call {} is safe per knowledge base".format(func_text))
            return (-1, 0)
        if knowledge.get("passthrough") or knowledge.get("param_flow"):
            for arg_node in args:
                if _is_literal_node(arg_node):
                    continue
                var_names = _collect_identifiers_from_ast(arg_node)
                for vn in var_names:
                    if vn == var_name:
                        continue
                    if _is_controllable_source(vn, controlled_params):
                        return (1, lineno)
                    r = _trace_variable_in_lines(
                        file_path, vn, lineno, to_line,
                        repair_functions, controlled_params, depth + 1, max_depth, visited
                    )
                    if r[0] in (1, 2):
                        return r
            return None

    # 可控源函数（如 getenv, scanf, fgets 等）
    short_name = func_text.split("::")[-1] if "::" in func_text else func_text
    if short_name in C_CONTROLLED_SOURCES or func_text in C_CONTROLLED_SOURCES:
        logger.debug("[AST][C] RHS call {} is controlled source".format(func_text))
        return (1, lineno)

    # 查函数摘要
    callee_summary = lookup_summary(func_text)
    if callee_summary and callee_summary.return_flow:
        for rf in callee_summary.return_flow:
            if rf.origin_type == "param":
                for param_idx in rf.dep_params:
                    if param_idx < len(args):
                        arg_node = args[param_idx]
                        var_names = _collect_identifiers_from_ast(arg_node)
                        for vn in var_names:
                            if _is_controllable_source(vn, controlled_params):
                                logger.debug("[AST][C] Summary: {} param {} is controllable".format(func_text, param_idx))
                                return (1, lineno)
            elif rf.origin_type == "call":
                if controlled_params and rf.origin in controlled_params:
                    logger.debug("[AST][C] Summary: {} call origin {} is controllable".format(func_text, rf.origin))
                    return (1, lineno)
        # 摘要有 return_flow 但未匹配到可控源 → 不可控
        logger.debug("[AST][C] Summary: {} has return_flow but no controllable source".format(func_text))
        return None

    # builtin 和 summary 都没有 → 未确认
    logger.debug("[AST][C] RHS call {} is unknown, return code=3 (unconfirmed)".format(func_text))
    return (3, func_text)


def _handle_binary_expression_rhs(bin_node, var_name, file_path, lineno, to_line,
                                  repair_functions, controlled_params, depth, max_depth, visited=None):
    """处理字符串拼接 (binary_expression) 的 RHS 分析。"""
    for child in bin_node.children:
        if child.type in ("+", "-", "*", "/", "%", "||", "&&", "|", "&", "^",
                          "<<", ">>", "<", ">", "<=", ">=", "==", "!="):
            continue
        if _is_literal_node(child):
            continue
        var_names = _collect_identifiers_from_ast(child)
        for vn in var_names:
            if vn == var_name:
                continue
            if _is_controllable_source(vn, controlled_params):
                return (1, lineno)
            r = _trace_variable_in_lines(
                file_path, vn, lineno, to_line,
                repair_functions, controlled_params, depth + 1, max_depth, visited
            )
            if r[0] in (1, 2):
                return r
    return None


def _text_trace_variable(file_path, var_name, vul_lineno,
                          repair_functions=None, controlled_params=None,
                          depth=0, max_depth=10, visited=None):
    """纯文本 fallback 追踪：不依赖 tree-sitter AST。

    从 vul_lineno 向上逐行查找 var_name 的赋值，判断是否来自可控源。
    返回: (code, source_lineno)
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    if depth > max_depth:
        return (-1, 0)

    if visited is None:
        visited = set()
    trace_key = (file_path, var_name, int(vul_lineno))
    if trace_key in visited:
        return (-1, 0)
    visited.add(trace_key)

    lines = _get_source_lines(file_path)
    if not lines:
        return (-1, 0)

    # 向上查找赋值（最多 50 行，避免跨函数误匹配）
    start = max(0, vul_lineno - 52)
    for i in range(vul_lineno - 2, start, -1):
        line = lines[i].strip()

        # 跳过空行和纯注释
        if not line or line.startswith('//') or line.startswith('/*') or line.startswith('*'):
            continue

        # 匹配 C 赋值: type var = ... 或 var = ...
        # 先匹配带类型的声明: int/char/... var = expr
        # 排除关键字前缀（return/if/else/for/while/switch/case）
        m_decl = re.match(
            r'(?:return|if|else|for|while|switch|case|break|continue)\b',
            line
        )
        if m_decl:
            continue

        m_decl = re.match(
            r'(?:\w+(?:\s*\*)*)\s+' + re.escape(var_name) + r'\s*=\s*(.+)',
            line
        )
        if m_decl:
            rhs = m_decl.group(1).strip().rstrip(";")
        else:
            # 匹配纯赋值: var = expr
            m_assign = re.match(
                r'(?:' + re.escape(var_name) + r')\s*=\s*(.+)',
                line
            )
            if not m_assign:
                continue
            rhs = m_assign.group(1).strip().rstrip(";")

        src_lineno = i + 1

        # 检查是否是可控源函数调用
        if _is_controllable_source(rhs, controlled_params):
            return (1, src_lineno)

        # 检查是否是修复函数
        if _is_repair_function(rhs, repair_functions):
            return (2, src_lineno)

        # 检查子变量
        sub_vars = re.findall(r'[a-zA-Z_]\w*', rhs)
        for sv in sub_vars:
            if sv in ("true", "false", "NULL", "nullptr", "sizeof", "int", "char",
                       "void", "long", "short", "unsigned", "signed", "const",
                       "return", "if", "else", "for", "while", "sizeof"):
                continue
            if sv == var_name:
                continue
            if _is_controllable_source(sv, controlled_params):
                return (1, src_lineno)
            sub_code, sub_line = _text_trace_variable(
                file_path, sv, src_lineno,
                repair_functions, controlled_params, depth + 1, max_depth, visited
            )
            if sub_code == 1:
                return (1, sub_line)

    return (-1, 0)


# ---------------------------------------------------------------------------
# 跨函数追踪
# ---------------------------------------------------------------------------

def _propagate_controllable_in_body(body_node, controllable_local):
    """在函数体 AST 中传播可控变量标记。

    返回 True 如果有新的变量被标记为可控。
    """
    changed = False

    def _walk(node):
        nonlocal changed
        lhs_name = None
        rhs_identifiers = []

        if node.type == "declaration":
            for child in node.children:
                if child.type == "init_declarator":
                    _process_init_declarator(child)
        elif node.type == "expression_statement":
            for child in node.children:
                if child.type == "assignment_expression":
                    _process_assignment(child)
                elif child.type == "call_expression":
                    _process_call_for_propagation(child)
        elif node.type == "call_expression":
            _process_call_for_propagation(node)
        elif node.type == "assignment_expression":
            _process_assignment(node)

        for child in node.children:
            _walk(child)

    def _process_init_declarator(init_decl):
        nonlocal changed
        name = ""
        value_node = None
        found_eq = False
        for sub in init_decl.children:
            if sub.type == "declarator":
                name = _extract_declarator_name_simple(sub)
            elif sub.type == "=":
                found_eq = True
            elif found_eq and sub.type not in (";", ",") and value_node is None:
                value_node = sub

        if name and name not in controllable_local and value_node:
            rhs_ids = _collect_identifiers_from_ast(value_node)
            if rhs_ids and (rhs_ids & controllable_local):
                controllable_local.add(name)
                changed = True

    def _process_assignment(assign_node):
        nonlocal changed
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
                if right is None:
                    right = child

        if left and right:
            lhs_name = ""
            if left.type == "identifier":
                lhs_name = _node_text(left)
            elif left.type == "subscript_expression":
                arr = left.child_by_field_name("array") or left.child_by_field_name("argument")
                if arr and arr.type == "identifier":
                    lhs_name = _node_text(arr)

            if lhs_name and lhs_name not in controllable_local:
                rhs_ids = _collect_identifiers_from_ast(right)
                if rhs_ids and (rhs_ids & controllable_local):
                    controllable_local.add(lhs_name)
                    changed = True

    def _process_call_for_propagation(call_node):
        nonlocal changed
        callee_name = _get_call_func_name(call_node)
        if not callee_name:
            return
        knowledge = lookup_builtin(callee_name)
        if not knowledge:
            return
        args = _get_call_args_from_ast(call_node)
        if not args:
            return

        # passthrough: 返回值透传，标记调用结果为可控（如果透传参数可控）
        passthrough = knowledge.get("passthrough", [])
        if passthrough:
            for idx in passthrough:
                if idx >= len(args):
                    continue
                arg = args[idx]
                if arg.type == "identifier":
                    var = _node_text(arg)
                    if var and var in controllable_local:
                        changed = True
                        logger.debug("[AST][C] Propagation: passthrough arg {} of {} is controllable".format(
                            idx, callee_name))

        # param_flow: 参数间数据流，标记输出参数为可控
        param_flow = knowledge.get("param_flow", {})
        if param_flow:
            for out_idx, source_info in param_flow.items():
                if not isinstance(out_idx, int) or out_idx >= len(args):
                    continue
                if isinstance(source_info, str):
                    # 隐式数据源 → 输出参数直接可控
                    arg = args[out_idx]
                    if arg.type == "identifier":
                        var = _node_text(arg)
                        if var and var not in controllable_local:
                            controllable_local.add(var)
                            changed = True
                            logger.debug("[AST][C] Propagation: {} is output arg {} of {} (source: {})".format(
                                var, out_idx, callee_name, source_info))
                elif isinstance(source_info, int) and source_info < len(args):
                    # 参数间数据流：检查输入参数是否可控
                    src_arg = args[source_info]
                    src_text = _node_text(src_arg)
                    if src_text in controllable_local or _is_controllable_source(src_text, controlled_params):
                        arg = args[out_idx]
                        if arg.type == "identifier":
                            var = _node_text(arg)
                            if var and var not in controllable_local:
                                controllable_local.add(var)
                                changed = True
                                logger.debug("[AST][C] Propagation: {} is output arg {} of {} (from arg {})".format(
                                    var, out_idx, callee_name, source_info))

    _walk(body_node)
    return changed


def _collect_return_values(body_node):
    """从函数体 AST 中收集所有 return 语句的返回值。

    返回 [(expr_text, expr_node), ...]
    """
    results = []

    def _walk(node):
        if node.type == "return_statement":
            for child in node.children:
                if child.type in ("return", ";") or child.type.endswith("_comment"):
                    continue
                results.append((_node_text(child), child))
                break  # 通常只取第一个表达式
        else:
            for child in node.children:
                _walk(child)

    _walk(body_node)
    return results


# ---------------------------------------------------------------------------
# scan_parser — 入口
# ---------------------------------------------------------------------------

def _handle_c_indirect_call(vul_lineno, indirect_map, repair_functions, controlled_params, file_path):
    """
    处理 C 间接调用场景：在 AST 中定位 vul_lineno 处的 call_expression 节点，
    用 indirect_map 确认是间接调用后，提取参数做可控性分析。

    :param vul_lineno: 漏洞行号
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param file_path: 文件路径
    :return: list[dict] scan_results 格式的结果列表，或 None
    """
    global scan_results

    try:
        vul_lineno = int(vul_lineno)
    except (ValueError, TypeError):
        return None

    ast_tree = _parse_c_ast(file_path)
    if ast_tree is None:
        return None

    # 在 AST 中查找 vul_lineno 处的 call_expression
    target_node = None
    matched_sink_name = None

    def _find_call_at_vul_line(node):
        nonlocal target_node, matched_sink_name
        if target_node is not None:
            return
        if node.type == 'call_expression':
            node_line = node.start_point[0] + 1
            if node_line == vul_lineno:
                func_child = node.child_by_field_name('function')
                if not func_child and node.children:
                    func_child = node.children[0]
                if func_child and func_child.type == 'identifier':
                    func_name = _node_text(func_child)
                    if func_name in indirect_map:
                        target_node = node
                        matched_sink_name = indirect_map[func_name]
        for child in node.children:
            _find_call_at_vul_line(child)

    _find_call_at_vul_line(ast_tree.root_node)

    if target_node is None:
        return None

    # 提取参数做可控性分析
    ast_args = _get_call_args_from_ast(target_node)
    if not ast_args:
        return None

    results = []
    saved_results = list(scan_results)

    for arg_idx, arg_node in enumerate(ast_args):
        arg_text = _node_text(arg_node)

        # 字面量 → 不可控
        if _is_literal_node(arg_node):
            continue

        # 提取参数中的所有标识符
        var_names = _collect_identifiers_from_ast(arg_node)

        for var_name in var_names:
            # 直接可控源
            if _is_controllable_source(var_name, controlled_params):
                source_lineno = vul_lineno
                _, sl = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if sl:
                    source_lineno = sl

                results.append({
                    "code": 1,
                    "vul_func": matched_sink_name,
                    "param": var_name,
                    "language": "c",
                    "source_file": file_path,
                    "source_lineno": source_lineno,
                    "chain": [],
                })
                scan_results = results
                return results

            # 反向追踪
            trace_code, src_lineno = _trace_variable_in_lines(
                file_path, var_name, vul_lineno, vul_lineno,
                repair_functions, controlled_params
            )
            if trace_code == 1:
                results.append({
                    "code": 1,
                    "vul_func": matched_sink_name,
                    "param": var_name,
                    "language": "c",
                    "source_file": file_path,
                    "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                })
                scan_results = results
                return results
            elif trace_code == 2:
                results.append({
                    "code": 2,
                    "vul_func": matched_sink_name,
                    "param": var_name,
                    "language": "c",
                    "source_file": file_path,
                    "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                })
                scan_results = results
                return results

    scan_results = saved_results
    return None


def scan_parser(rule_match, vul_lineno, file_path,
                repair_functions=None, controlled_params=None,
                svid=None, is_config_vuln=False, indirect_map=None):
    """C/C++ AST 扫描入口

    :param rule_match: 规则匹配的函数名列表
    :param vul_lineno: 漏洞行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则编号
    :param is_config_vuln: 是否配置型漏洞
    :return: 扫描结果列表

    返回格式（与所有语言一致）：
        [{"code": 1, "vul_func": "system", "param": "cmd", "language": "c",
          "source_file": "...", "source_lineno": 10}]
    code 含义：1=可控, 2=已修复, 3=未确认, 4=NewFunction, -1=不可控
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain
    # 清除上次扫描残留，重建 C_CONTROLLED_SOURCES 初始列表（防止跨项目污染）
    global C_CONTROLLED_SOURCES
    C_CONTROLLED_SOURCES = [
        # argv/argc removed: CLI-only, not web-controllable
        # read/fread/fgets/getc/getdelim/recv/recvfrom/recvmsg removed:
        # file/network I/O functions, not user HTTP input
        "getenv", "secure_getenv",
        "scanf", "fscanf", "sscanf",
        "gets",
        "stdin", "FILE stdin", "std::cin",
        "cin",
    ]
    _trace_cache.clear()

    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # 保存到模块全局（与其他引擎一致）
    is_repair_functions = repair_functions
    is_controlled_params = controlled_params

    # ---- 预建函数定义索引 ----
    _build_func_def_index(file_path)
    _build_func_def_index_cross_file()

    # ---- 初始化函数摘要 ----
    global _summaries_initialized
    _summaries_initialized = False
    _init_function_summaries(file_path)

    results = []

    try:
        vul_lineno = int(vul_lineno)
    except (ValueError, TypeError):
        logger.warning("[AST][C] Invalid vul_lineno: {}".format(vul_lineno))
        return results

    # 获取源码行
    line_text = _c_line_to_text(file_path, vul_lineno)
    if not line_text:
        logger.warning("[AST][C] Cannot read line {} from {}".format(vul_lineno, file_path))
        return results

    logger.debug("[AST][C] Scanning line {}: {}".format(vul_lineno, line_text))

    # ---- 间接调用快速路径 ----
    if indirect_map and isinstance(indirect_map, dict):
        indirect_result = _handle_c_indirect_call(
            vul_lineno, indirect_map, repair_functions, controlled_params, file_path
        )
        if indirect_result:
            scan_results = indirect_result
            return indirect_result

    # 检查行中是否包含规则匹配的函数
    matched_func = None
    for func in rule_match:
        clean_func = func.replace("\\.", ".").replace("\\(", "(").replace("\\)", ")")
        if clean_func in line_text:
            matched_func = clean_func
            break

    if not matched_func:
        # 模糊匹配
        for func in rule_match:
            clean_func = func.replace("\\.", ".").replace("\\(", "(").replace("\\)", ")")
            parts = clean_func.split(".")
            if any(p in line_text for p in parts if len(p) > 2):
                matched_func = clean_func
                break

    if not matched_func:
        logger.debug("[AST][C] No matching function found in line")
        return results

    # ---- tree-sitter 解析 AST ----
    ast_tree = _parse_c_ast(file_path)
    # ---- Source Discovery 预处理 ----
    global _sd_registry
    # 将 tamper 框架的 controlled_params 注入到 C_CONTROLLED_SOURCES
    for cp in controlled_params:
        if cp not in C_CONTROLLED_SOURCES:
            C_CONTROLLED_SOURCES.append(cp)
    _sd_registry = discover_sources(os.path.dirname(os.path.abspath(file_path)), ast_tree, file_path,
                                     extra_sources=C_CONTROLLED_SOURCES)
    # 注入 user source producers 到 C_CONTROLLED_SOURCES
    for func_name in _sd_registry.user_source_functions:
        if func_name not in C_CONTROLLED_SOURCES:
            C_CONTROLLED_SOURCES.append(func_name)
    call_node = None
    ast_args = []

    if ast_tree is not None:
        call_node = _find_call_at_line(ast_tree, vul_lineno, matched_func)
        if call_node is not None:
            ast_args = _get_call_args_from_ast(call_node)

    # AST 提取成功 → 用 AST 节点分析参数
    if ast_args:
        # 注意：不在入口处检查 builtin_knowledge.safe 跳过追踪。
        # safe 标志仅用于嵌套调用的可控性判断（如修复函数），不应阻止
        # 对 sink 函数自身参数的可控性分析。

        # Unconditionally dangerous functions — no parameter tracing needed
        if matched_func in ("gets",):
            logger.debug("[AST][C] {} is unconditionally dangerous".format(matched_func))
            results.append({
                "code": 1,
                "vul_func": matched_func,
                "param": "unbounded_input",
                "language": "c",
                "source_file": file_path,
                "source_lineno": vul_lineno,
                "chain": [],
            })
            scan_results = results
            return results

        for arg_idx, arg_node in enumerate(ast_args):
            arg_text = _node_text(arg_node)

            # 字面量 → 跳过
            if _is_literal_node(arg_node):
                logger.debug("[AST][C] Arg[{}] is literal: {}".format(arg_idx, arg_text))
                continue

            # Function call as argument → 封装 sink，走 NewCore
            if arg_node.type == "call_expression":
                inner_func = _get_call_func_name(arg_node)
                if inner_func:
                    logger.debug("[AST][C] Arg func {} is unknown wrapper, return code=5".format(inner_func))
                    results.append({
                        'code': 5,
                        'source': (inner_func, arg_text, matched_func),
                        'chain': [
                            ('NewFunction', inner_func, file_path, 0),
                            ('sink', matched_func, file_path, vul_lineno)
                        ]
                    })
                    scan_results = results
                    return results

            # 提取参数中的所有标识符
            var_names = _collect_identifiers_from_ast(arg_node)

            for var_name in var_names:
                # 直接可控源
                if _is_controllable_source(var_name, controlled_params):
                    logger.debug("[AST][C] Variable {} controllable".format(var_name))
                    # 分支约束检查
                    if ast_tree is not None:
                        func_info = _find_enclosing_function(ast_tree, vul_lineno)
                        if func_info:
                            _, _, body_node, _, _ = func_info
                            if _check_sink_branch_constraints(ast_tree, vul_lineno, var_name, body_node):
                                logger.info("[AST][C] Branch constraint BLOCKS var {} at line {}".format(var_name, vul_lineno))
                                continue
                    source_lineno = vul_lineno  # 默认
                    # 尝试找到更精确的 source 行号
                    _, sl = _trace_variable_in_lines(
                        file_path, var_name, vul_lineno, vul_lineno,
                        repair_functions, controlled_params
                    )
                    if sl:
                        source_lineno = sl

                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": source_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

                # 反向追踪
                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    # 分支约束检查
                    if ast_tree is not None:
                        func_info = _find_enclosing_function(ast_tree, vul_lineno)
                        if func_info:
                            _, _, body_node, _, _ = func_info
                            if _check_sink_branch_constraints(ast_tree, vul_lineno, var_name, body_node):
                                logger.info("[AST][C] Branch constraint BLOCKS var {} at line {}".format(var_name, vul_lineno))
                                continue
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 2:
                    results.append({
                        "code": 2,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 3:
                    results.append({
                        "code": 3,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 5:
                    wrapper_func = src_lineno
                    wrapper_file = file_path
                    wrapper_lineno = 0
                    lookup_name = wrapper_func.split("::")[-1] if "::" in wrapper_func else wrapper_func
                    for (fp, fname), val in _func_def_index.items():
                        if fname == lookup_name:
                            wrapper_file = fp
                            wrapper_lineno = val[2] if len(val) > 2 else 0
                            break
                    results.append({
                        'code': 5,
                        'source': (wrapper_func, var_name, matched_func),
                        'chain': [
                            ('NewFunction', wrapper_func, wrapper_file, wrapper_lineno),
                            ('sink', matched_func, file_path, vul_lineno)
                        ]
                    })
                    scan_results = results
                    return results

        results.append({"code": -1, "chain": []})
        return results

    # ---- AST 未提取到参数，文本回退 ----
    # 从源码行提取参数
    args_str = _extract_args_from_line(line_text, matched_func)
    if args_str:
        for arg in _split_args_respecting_parens(args_str):
            arg = arg.strip()
            if not arg:
                continue
            # 跳过字面量
            if (arg.startswith('"') and arg.endswith('"')) or \
               (arg.startswith("'") and arg.endswith("'")):
                continue
            if re.match(r'^\d+(\.\d+)?$', arg):
                continue

            # 提取变量名
            var_names = re.findall(r'[a-zA-Z_]\w*', arg)
            for var_name in var_names:
                if _is_controllable_source(var_name, controlled_params):
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    results.append({
                        "code": 1,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 2:
                    results.append({
                        "code": 2,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results
                elif trace_code == 3:
                    results.append({
                        "code": 3,
                        "vul_func": matched_func,
                        "param": var_name,
                        "language": "c",
                        "source_file": file_path,
                        "source_lineno": src_lineno if src_lineno else vul_lineno,
                    "chain": [],
                    })
                    scan_results = results
                    return results

    # ---- NewFunction / 配置型漏洞 ----
    if is_config_vuln:
        results.append({
            "code": 4,
            "vul_func": matched_func,
            "param": matched_func,
            "language": "c",
            "source_file": file_path,
            "source_lineno": vul_lineno,
        "chain": [],
        })
    else:
        results.append({"code": -1, "chain": []})

    scan_results = results
    return results


def _extract_args_from_line(line_text, func_name):
    """从代码行中提取函数调用的参数字符串（括号计数法）。"""
    idx = line_text.find(func_name + "(")
    if idx < 0:
        short_name = func_name.split("::")[-1] if "::" in func_name else func_name
        short_name = short_name.split(".")[-1] if "." in short_name else short_name
        idx = line_text.find(short_name + "(")
        if idx < 0:
            return None
        idx += len(short_name)
    else:
        idx += len(func_name)

    if idx >= len(line_text) or line_text[idx] != "(":
        return None

    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for i in range(idx, len(line_text)):
        ch = line_text[i]
        if in_string:
            if ch == "\\" and i + 1 < len(line_text):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ("\"", "'"):
            in_string = True
            string_char = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return line_text[start:i]
    return None


# ---------------------------------------------------------------------------
# analysis_params — CAST 跨文件分析接口
# ---------------------------------------------------------------------------

def analysis_params(param_name, parent_func_names, vul_function, lineno, file_path,
                    repair_functions=None, controlled_params=None, isexternal=False):
    """C/C++ 变量可控性分析（供 CAST 跨文件分析调用）

    :param param_name: 要追踪的变量名
    :param parent_func_names: 父函数名列表
    :param vul_function: 漏洞函数列表
    :param lineno: 当前行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param isexternal: 是否外部调用
    :return: (is_controllable, controlled_params, expr_lineno, chain)
        is_controllable: 1=可控, -1=不可控, 3=未确认, 4=新漏洞函数
    """
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # 保存到模块全局
    global is_repair_functions, is_controlled_params
    is_repair_functions = repair_functions
    is_controlled_params = controlled_params

    # 预建函数定义索引
    _build_func_def_index(file_path)

    try:
        lineno = int(lineno)
    except (ValueError, TypeError):
        return -1, [], 0, []

    # 追踪变量
    trace_code, src_lineno = _trace_variable_in_lines(
        file_path, param_name, lineno, lineno,
        repair_functions, controlled_params
    )

    if trace_code == 1:
        return 1, controlled_params, lineno, [
            ("source", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    elif trace_code == 2:
        return 2, controlled_params, lineno, [
            ("repair", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    elif trace_code == 3:
        return 3, controlled_params, lineno, [
            ("unconfirmed", param_name, file_path, src_lineno if src_lineno else lineno)
        ]
    elif trace_code == 5:
        wrapper_func = src_lineno
        wrapper_file = file_path
        wrapper_lineno = 0
        lookup_name = wrapper_func.split("::")[-1] if "::" in wrapper_func else wrapper_func
        for (fp, fname), val in _func_def_index.items():
            if fname == lookup_name:
                wrapper_file = fp
                wrapper_lineno = val[2] if len(val) > 2 else 0
                break
        return 5, controlled_params, wrapper_lineno, [
            ('NewFunction', wrapper_func, wrapper_file, wrapper_lineno)
        ]
    else:
        return -1, [], 0, []


# ---------------------------------------------------------------------------
# find_sinks — 间接调用 / 直接调用 sink 检测（供 scanner.py 调用）
# ---------------------------------------------------------------------------

def find_sinks(sink_names, files):
    """
    AST-based sink 查找。遍历所有文件的 tree-sitter AST 节点，查找匹配的函数调用。
    支持直接调用匹配和基于函数指针赋值的间接调用检测。

    :param sink_names: list of SinkName(class_, method) from parse_sink_names()
    :param files: 文件路径列表
    :return: list of dict with keys:
        file_path, lineno, node, is_indirect, callee_name, class_name, matched_sink
    """
    from core.utils import SinkName

    results = []

    for file_path in files:
        file_path = _ast_object_singleton.get_path(file_path)
        if not file_path:
            continue
        tree = _parse_c_ast(file_path)
        if not tree:
            continue

        root = tree.root_node

        # ---- 第一遍：遍历函数体，构建函数指针赋值映射 ----
        # var_to_sink: {变量名: matched SinkName}
        var_to_sink = {}
        # var_reassign_lines: {变量名: list of reassignment line numbers}
        var_reassign_lines = {}

        def _walk_for_declarations(node):
            """遍历 AST，找 init_declarator / declaration 中的函数指针赋值和重新赋值。"""
            if node.type == 'init_declarator':
                # 模式: int (*func)(const char *) = system;
                # init_declarator 包含 declarator 和 value（= 右侧）
                decl_node = node.child_by_field_name('declarator')
                value_node = node.child_by_field_name('value')
                if decl_node and value_node:
                    # 检查是否是函数指针声明（类型包含指针符号）
                    type_text = _node_text(decl_node)
                    if '(' in type_text and '*' in type_text:
                        # 提取左侧变量名
                        var_name = _extract_declarator_name_simple(decl_node)
                        if var_name:
                            # 检查右侧是否是 sink 函数名
                            val_text = _node_text(value_node)
                            if value_node.type == 'identifier':
                                for sink in sink_names:
                                    if sink.class_ is None and val_text == sink.method:
                                        var_to_sink[var_name] = sink
                                        break
                                # 多层间接调用：右侧 identifier 在 var_to_sink 中则继承
                                if val_text in var_to_sink and var_name not in var_to_sink:
                                    var_to_sink[var_name] = var_to_sink[val_text]
                            elif value_node.type == 'call_expression':
                                # cast 赋值: func = (int (*)(const char *))system
                                # call_expression 的 function 可能是 cast
                                pass

            elif node.type == 'declaration':
                # declaration 可能包含 init_declarator
                pass

            elif node.type == 'assignment_expression':
                # 模式: func = (int (*)(const char *))printf;  (重新赋值)
                left_node = node.child_by_field_name('left')
                right_node = node.child_by_field_name('right')
                if left_node and right_node:
                    if left_node.type == 'identifier':
                        var_name = _node_text(left_node)
                        lineno = node.start_point[0] + 1
                        # 检查右侧
                        val_text = _node_text(right_node)
                        if right_node.type == 'identifier':
                            # func = printf; -> 重新赋值
                            # 如果右侧是 sink，更新映射；否则检查多层传播
                            found_sink = None
                            for sink in sink_names:
                                if sink.class_ is None and val_text == sink.method:
                                    found_sink = sink
                                    break
                            if found_sink:
                                var_to_sink[var_name] = found_sink
                            elif val_text in var_to_sink:
                                # 多层间接调用：右侧 identifier 在 var_to_sink 中则继承
                                var_to_sink[var_name] = var_to_sink[val_text]
                            elif var_name in var_to_sink:
                                # 重新赋值为非 sink，清除映射
                                del var_to_sink[var_name]
                        elif right_node.type == 'cast_expression':
                            # func = (type *)other_func;
                            # 尝试提取 cast 内部的 identifier
                            inner = right_node.child_by_field_name('value')
                            if inner and inner.type == 'identifier':
                                inner_text = _node_text(inner)
                                found_sink = None
                                for sink in sink_names:
                                    if sink.class_ is None and inner_text == sink.method:
                                        found_sink = sink
                                        break
                                if found_sink:
                                    var_to_sink[var_name] = found_sink
                                elif var_name in var_to_sink:
                                    del var_to_sink[var_name]
                            else:
                                # cast 到其他类型，清除映射
                                if var_name in var_to_sink:
                                    del var_to_sink[var_name]
                        else:
                            # 其他类型右侧，清除映射
                            if var_name in var_to_sink:
                                del var_to_sink[var_name]

            elif node.type == 'function_definition':
                # 遍历函数体内部
                body = node.child_by_field_name('body')
                if body:
                    for child in body.children:
                        _walk_for_declarations(child)

            for child in node.children:
                _walk_for_declarations(child)

        _walk_for_declarations(root)

        # ---- 第二遍：遍历 call_expression，检测直接和间接调用 ----
        def _walk_for_calls(node):
            if node.type == 'call_expression':
                func_child = node.child_by_field_name('function')
                if not func_child and node.children:
                    func_child = node.children[0]
                if not func_child:
                    for child in node.children:
                        _walk_for_calls(child)
                    return

                func_text = _node_text(func_child)

                # 检查是否是间接调用
                if func_child.type == 'identifier' and func_text in var_to_sink:
                    matched_sink = var_to_sink[func_text]
                    lineno = node.start_point[0] + 1
                    results.append({
                        'file_path': file_path,
                        'lineno': lineno,
                        'node': node,
                        'is_indirect': True,
                        'callee_name': func_text,
                        'class_name': None,
                        'matched_sink': matched_sink,
                    })
                    # 继续遍历子节点
                    for child in node.children:
                        _walk_for_calls(child)
                    return

                # 检查直接调用
                short_name = func_text.split('::')[-1] if '::' in func_text else func_text
                short_name = short_name.split('.')[-1] if '.' in short_name else short_name

                for sink in sink_names:
                    if sink.class_ is None:
                        if func_text == sink.method or short_name == sink.method:
                            lineno = node.start_point[0] + 1
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': func_text,
                                'class_name': None,
                                'matched_sink': sink,
                            })
                            break
                    else:
                        if func_text == '{}.{}'.format(sink.class_, sink.method):
                            lineno = node.start_point[0] + 1
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': func_text,
                                'class_name': sink.class_,
                                'matched_sink': sink,
                            })
                            break

            for child in node.children:
                _walk_for_calls(child)

        _walk_for_calls(root)

    return results
