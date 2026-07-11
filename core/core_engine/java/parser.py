#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import traceback
import javalang
from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
import os
from core.core_engine.java.source_discovery import SourceRegistry, discover_sources
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.java.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.java.summary_generator import lookup_summary

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("java")
_summaries_initialized = False
_file_summaries = {}
_scan_function_stack = []  # 函数追踪栈，防递归
_source_registry = None  # Source Discovery 注册表


# Java 静态方法验证类 — qualifier.method() 返回 true 时参数被约束为安全类型
TYPE_VALIDATION_CLASSES = {
    'StringUtils': {'isNumeric', 'isAlpha', 'isAlphanumeric', 'isAlphaSpace', 'isNumericSpace'},
    'NumberUtils': {'isDigits', 'isCreatable', 'isParsable'},
}


def _is_strict_regex(pattern, is_fullmatch=True):
    """判断正则是否为严格全匹配模式（安全）。

    :param pattern: 正则字符串
    :param is_fullmatch: True 表示默认全匹配（如 Java matches()），不需要 ^...$ 锚定
    """
    if not pattern or not isinstance(pattern, str):
        return False

    if is_fullmatch:
        body = pattern
    else:
        if len(pattern) < 4:
            return False
        if not pattern.startswith('^') or not pattern.endswith('$'):
            return False
        body = pattern[1:-1]

    # 去掉转义的 \. 后检查是否含未转义的 .
    stripped = body.replace('\\.', '')
    if '.' in stripped:
        return False
    if '*' in stripped or '?' in stripped:
        return False
    return True


def _get_java_literal_str(expr):
    """从 Java 表达式提取字符串字面量值（去除引号）"""
    val = _get_java_literal(expr)
    if isinstance(val, str):
        return val
    return None


def _expr_to_text(expr, source_lines):
    """将 AST 表达式转为源码文本（从源码行读取，fallback 用 str()）"""
    if expr is None:
        return ''
    if isinstance(expr, str):
        return expr
    if hasattr(expr, 'position') and expr.position and source_lines:
        lineno = expr.position.line
        if 1 <= lineno <= len(source_lines):
            return source_lines[lineno - 1]
    return str(expr)


def _flatten_chained_calls(node):
    """展开 javalang MethodInvocation/Primary 的 selectors，返回所有链式调用节点列表。

    javalang 解析 a.b().c(arg) 为：
      MethodInvocation(member="b", qualifier="a", selectors=[
          MethodInvocation(member="c", arguments=[arg], qualifier=None)
      ])
    本函数返回 [原始节点, selector[0], selector[1], ...]
    """
    if node is None:
        return []
    nodes = [node]
    if hasattr(node, 'selectors') and node.selectors:
        for sel in node.selectors:
            if isinstance(sel, (javalang.tree.MethodInvocation, javalang.tree.MemberReference)):
                nodes.append(sel)
    return nodes


def _collect_member_references(expr, refs=None):
    """递归收集表达式中的所有变量引用名（MemberReference.member）"""
    if refs is None:
        refs = []
    if expr is None:
        return refs

    if isinstance(expr, str):
        # 纯字符串（源码文本 fallback 传入的参数名）
        refs.append(expr)
        return refs

    if isinstance(expr, javalang.tree.MemberReference):
        refs.append(expr.member)

    elif isinstance(expr, javalang.tree.BinaryOperation):
        _collect_member_references(expr.operandl, refs)
        _collect_member_references(expr.operandr, refs)

    elif isinstance(expr, javalang.tree.MethodInvocation):
        if expr.arguments:
            for arg in expr.arguments:
                _collect_member_references(arg, refs)
        # qualifier 如果是变量名也收集（排除类名：首字母大写）
        if expr.qualifier and isinstance(expr.qualifier, str) and expr.qualifier[0].islower():
            refs.append(expr.qualifier)

        # selectors traversal for chained calls
        if hasattr(expr, 'selectors') and expr.selectors:
            for sel in expr.selectors:
                _collect_member_references(sel, refs)

    elif isinstance(expr, javalang.tree.Cast):
        _collect_member_references(expr.expression, refs)

    elif isinstance(expr, javalang.tree.TernaryExpression):
        _collect_member_references(expr.condition, refs)
        _collect_member_references(expr.if_true, refs)
        _collect_member_references(expr.if_false, refs)

    elif isinstance(expr, javalang.tree.Assignment):
        _collect_member_references(expr.value, refs)

    elif isinstance(expr, javalang.tree.ClassCreator):
        # new SomeClass(arg1, arg2, ...) → 递归检查参数中的变量引用
        if expr.arguments:
            for arg in expr.arguments:
                _collect_member_references(arg, refs)

    elif isinstance(expr, (list, tuple)):
        for item in expr:
            _collect_member_references(item, refs)

    return refs


def _get_assign_target(stmt_expr):
    """从赋值表达式中提取目标变量名"""
    if hasattr(stmt_expr, 'expression') and isinstance(stmt_expr.expression, javalang.tree.Assignment):
        assign = stmt_expr.expression
        left = assign.expressionl  # 注意：javalang 用 expressionl 不是 left
        if isinstance(left, javalang.tree.MemberReference):
            return left.member
        elif hasattr(left, 'name'):
            return left.name
    return None

def _get_assign_rhs(stmt_expr):
    """从赋值表达式中提取右侧节点"""
    if hasattr(stmt_expr, 'expression') and isinstance(stmt_expr.expression, javalang.tree.Assignment):
        return stmt_expr.expression.value
    return None

def _get_var_name(node):
    """从表达式节点提取变量名"""
    if isinstance(node, javalang.tree.MemberReference):
        return node.member
    if hasattr(node, 'name'):
        return node.name
    if hasattr(node, 'member'):
        return node.member
    return None

def _expr_to_str_java(node):
    """将 javalang AST 节点转为字符串表示"""
    if node is None:
        return ''
    if isinstance(node, javalang.tree.Literal):
        return str(node.value) if hasattr(node, 'value') else ''
    if isinstance(node, javalang.tree.MemberReference):
        prefix = ''
        if hasattr(node, 'selectors') and node.selectors:
            prefix = '.'.join(node.selectors) + '.'
        elif hasattr(node, 'qualifier') and node.qualifier:
            prefix = node.qualifier + '.'
        return prefix + (node.member or '')
    if isinstance(node, javalang.tree.MethodInvocation):
        qualifier = node.qualifier or ''
        if qualifier:
            qualifier += '.'
        args = ', '.join(_expr_to_str_java(a) for a in (node.arguments or []))
        return f"{qualifier}{node.member}({args})"
    if isinstance(node, javalang.tree.BinaryOperation):
        left = _expr_to_str_java(node.operandl)
        right = _expr_to_str_java(node.operandr)
        return f"{left} {node.operator} {right}"
    if isinstance(node, javalang.tree.Cast):
        return _expr_to_str_java(node.expression)
    if isinstance(node, javalang.tree.Assignment):
        return _expr_to_str_java(node.value)
    if hasattr(node, '__str__'):
        return str(node)
    return ''

def _collect_names_from_node(node):
    """从 AST 节点收集所有变量名"""
    names = set()
    if node is None:
        return names
    if isinstance(node, javalang.tree.MemberReference):
        names.add(node.member)
    elif isinstance(node, javalang.tree.MethodInvocation):
        if node.qualifier:
            names.add(node.qualifier)
        for arg in (node.arguments or []):
            names.update(_collect_names_from_node(arg))
    elif isinstance(node, javalang.tree.BinaryOperation):
        names.update(_collect_names_from_node(node.operandl))
        names.update(_collect_names_from_node(node.operandr))
    elif isinstance(node, javalang.tree.Assignment):
        names.update(_collect_names_from_node(node.value))
    elif isinstance(node, javalang.tree.Cast):
        names.update(_collect_names_from_node(node.expression))
    return names

def _node_at_line(node, target_line):
    """检查节点是否在目标行"""
    if hasattr(node, 'position') and node.position:
        return node.position[0] == target_line
    return False

def _find_sensitive_calls_in_stmt(stmt, sensitive_func, target_line):
    """在语句中找调用 sensitive_func 的 MethodInvocation 节点"""
    results = []
    _walk_for_calls(stmt, sensitive_func, target_line, results)
    return results

def _walk_for_calls(node, sensitive_func, target_line, results):
    """递归遍历 AST 找敏感函数调用"""
    if isinstance(node, javalang.tree.MethodInvocation):
        func_name = node.member
        qualifier = node.qualifier or ''
        full_name = f"{qualifier}.{func_name}" if qualifier else func_name

        # 匹配检查
        for sf in sensitive_func:
            if full_name == sf or func_name == sf or full_name.endswith('.' + sf):
                if _node_at_line(node, target_line):
                    # 收集每个参数
                    for i, arg in enumerate(node.arguments or []):
                        arg_str = _expr_to_str_java(arg)
                        results.append({
                            'arg_name': _get_var_name(arg) or arg_str,
                            'arg_node': arg,
                            'func_name': full_name,
                            'lineno': target_line,
                        })
                break

    # 递归子节点
    for attr in ('arguments', 'operandl', 'operandr', 'expression', 'value',
                 'expressionl', 'condition', 'body', 'block', 'catches',
                 'then_statement', 'else_statement'):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if hasattr(item, '__dict__'):
                    _walk_for_calls(item, sensitive_func, target_line, results)
        elif hasattr(child, '__dict__'):
            _walk_for_calls(child, sensitive_func, target_line, results)



def extract_constraints_from_java_expr(expr):
    """
    从 Java 条件表达式中提取 BranchConstraint 列表。

    javalang AST 节点类型：
    - x == value     -> BinaryOperation(operator='==', operandl, operandr)
    - x != null      -> BinaryOperation(operator='!=', operandl, operandr)
    - x instanceof T  -> BinaryOperation(operator='instanceof') → 暂不提取
    - x && y          -> BinaryOperation(operator='&&')
    - x || y          -> BinaryOperation(operator='||')
    - !expr           -> UnaryOperation(operator='!', operand)
    - x.equals(y)    -> MethodInvocation(member='equals') → 简化提取
    - x != null       -> MemberReference/member + BinaryOperation
    """
    if expr is None:
        return []

    constraints = []

    if isinstance(expr, javalang.tree.BinaryOperation):
        op = expr.operator

        if op == '&&':
            left = extract_constraints_from_java_expr(expr.operandl)
            right = extract_constraints_from_java_expr(expr.operandr)
            return left + right

        if op == '||':
            # x.equals("a") || x.equals("b") → 收集同一变量的枚举约束
            from collections import defaultdict
            left = extract_constraints_from_java_expr(expr.operandl)
            right = extract_constraints_from_java_expr(expr.operandr)
            or_constraints = left + right
            eq_values = defaultdict(list)
            for c in or_constraints:
                if c.op == '==' and c.var_name:
                    eq_values[c.var_name].append(c.value)
            result = []
            for var_name, values in eq_values.items():
                if values:
                    result.append(BranchConstraint(
                        var_name=var_name, op='in',
                        value=values if len(values) > 1 else values[0]))
            return result

        # 比较运算
        if op in ('==', '!=', '>=', '<=', '>', '<'):
            var_name = _get_java_expr_name(expr.operandl)
            if var_name:
                value = _get_java_literal(expr.operandr)
                constraints.append(BranchConstraint(var_name=var_name, op=op, value=value))
            return constraints

        # instanceof → 暂不提取
        return []

    # ljavalang 没有 UnaryOperation，!expr 通过 prefix_operators 处理
    # 这里暂不处理 !expr 的约束提取

    # x.equals(y) — 方法调用中的相等检查
    if isinstance(expr, javalang.tree.MethodInvocation):
        if hasattr(expr, 'member') and expr.member == 'equals' and len(expr.arguments or []) >= 1:
            obj = _get_java_expr_name(expr.qualifier) if expr.qualifier else None
            # 当 qualifier 是字面量（如 "test".equals(action)），从 argument 中提取变量名
            if not obj and expr.qualifier and isinstance(expr.qualifier, javalang.tree.Literal):
                obj = _get_java_expr_name(expr.arguments[0])
                value = _get_java_literal(expr.qualifier)
            else:
                value = _get_java_literal(expr.arguments[0])
            if obj:
                c = BranchConstraint(var_name=obj, op='==', value=value)
                # ljavalang: !expr 通过 prefix_operators 处理
                if hasattr(expr, 'prefix_operators') and '!' in expr.prefix_operators:
                    c = c.negate()
                constraints.append(c)
            return constraints

        # --- 验证函数识别 ---

        # str.matches(pattern) — 正则匹配
        if hasattr(expr, 'member') and expr.member == 'matches' and len(expr.arguments or []) >= 1:
            pattern = _get_java_literal_str(expr.arguments[0])
            if pattern and _is_strict_regex(pattern, is_fullmatch=True):
                var_name = _get_java_expr_name(expr.qualifier) if expr.qualifier else None
                if var_name:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='regex_validated', value=pattern))
                    return constraints

        # Character.isDigit(ch) 等单字符类型检查
        if hasattr(expr, 'member') and expr.member in ('isDigit', 'isLetter', 'isLetterOrDigit'):
            qualifier_name = _get_java_expr_name(expr.qualifier) if expr.qualifier else None
            if qualifier_name == 'Character' and len(expr.arguments or []) >= 1:
                var_name = _get_java_expr_name(expr.arguments[0])
                if var_name:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='type_validated', value='Character.' + expr.member))
                    return constraints

        # StringUtils.isNumeric(x) / NumberUtils.isDigits(x) 等静态方法验证
        if hasattr(expr, 'member') and hasattr(expr, 'qualifier') and expr.qualifier:
            qualifier_name = _get_java_expr_name(expr.qualifier)
            if qualifier_name in TYPE_VALIDATION_CLASSES:
                if expr.member in TYPE_VALIDATION_CLASSES[qualifier_name]:
                    if len(expr.arguments or []) >= 1:
                        var_name = _get_java_expr_name(expr.arguments[0])
                        if var_name:
                            constraints.append(BranchConstraint(
                                var_name=var_name, op='type_validated',
                                value=qualifier_name + '.' + expr.member))
                            return constraints

        return constraints

    # x != null → BinaryOperation(operator='!=', operandl=MemberReference, operandr=Literal('null'))
    return constraints


def _get_java_expr_name(expr):
    """从 Java 表达式提取变量名字符串。"""
    if expr is None:
        return None
    if isinstance(expr, str):
        return expr
    if isinstance(expr, javalang.tree.MemberReference):
        return expr.member
    if isinstance(expr, javalang.tree.This):
        return 'this'
    # MethodInvocation: e.g. port.charAt(0) → 'port'
    if isinstance(expr, javalang.tree.MethodInvocation) and expr.qualifier:
        return _get_java_expr_name(expr.qualifier)
    return None


def _get_java_literal(expr):
    """从 Java 表达式提取字面量值。"""
    if expr is None:
        return None
    if isinstance(expr, javalang.tree.Literal):
        val = expr.value
        # javalang 把字面量当字符串存储，尝试解析
        if val == 'null':
            return None
        if val == 'true':
            return True
        if val == 'false':
            return False
        try:
            return int(val)
        except (ValueError, TypeError):
            pass
        try:
            return float(val)
        except (ValueError, TypeError):
            pass
        # 去除引号
        if isinstance(val, str) and len(val) >= 2:
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                return val[1:-1]
        return val
    return None


def parameters_back(param_name, stmts, vul_lineno, file_path,
                     repair_functions=None, controlled_params=None, depth=0, max_depth=10,
                     method_params=None, method_name='', class_name=''):
    """
    反向追踪变量 param_name 的数据流来源。
    遍历 stmts 从 vul_lineno 往回找对 param_name 的赋值，判断赋值表达式是否可控。

    返回: (code, cp, expr_lineno)
        code=1: 可控
        code=2: 经过修复函数
        code=3: 未确认
        code=-1: 不可控
        code='deps': 依赖调用者变量
    """
    if depth > max_depth:
        return (3, None, 0)

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 查缓存
    cached = _trace_cache.get(file_path, param_name, vul_lineno)
    if cached is not None:
        return cached

    logger.debug(f"[AST][Java] parameters_back: tracing '{param_name}' from line {vul_lineno}, depth={depth}")

    # 直接可控检查
    for cp in controlled_params:
        if param_name == cp or param_name in cp:
            _trace_cache.put(file_path, param_name, vul_lineno, (1, param_name, vul_lineno))
            return (1, param_name, vul_lineno)

    # 从 vul_lineno 往回遍历语句
    target_line = int(vul_lineno)

    for stmt in reversed(stmts):
        stmt_line = _get_stmt_line(stmt)
        if stmt_line is None or stmt_line > target_line:
            continue

        # 局部变量声明: Type varName = expr
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for decl in stmt.declarators:
                if decl.name == param_name and decl.initializer:
                    result = _trace_expr(decl.initializer, stmts, stmt_line, file_path,
                                         repair_functions, controlled_params, depth + 1, max_depth)
                    _trace_cache.put(file_path, param_name, vul_lineno, result)
                    return result

        # 赋值语句: varName = expr
        if isinstance(stmt, javalang.tree.StatementExpression):
            if isinstance(stmt.expression, javalang.tree.Assignment):
                assign = stmt.expression
                target_name = _get_var_name(assign.expressionl)
                if target_name == param_name:
                    result = _trace_expr(assign.value, stmts, stmt_line, file_path,
                                         repair_functions, controlled_params, depth + 1, max_depth)
                    _trace_cache.put(file_path, param_name, vul_lineno, result)
                    return result

        # 控制流：递归进入
        if isinstance(stmt, javalang.tree.IfStatement):
            java_constraints = extract_constraints_from_java_expr(stmt.condition)

            # 判断 sink 在哪个分支
            sink_branch = _find_sink_branch_java(stmt, vul_lineno)
            logger.debug("[AST][Java] sink_branch={} for param {} lineno {}".format(sink_branch, param_name, vul_lineno))

            if sink_branch == 'if':
                then_stmts = _get_block_stmts(stmt.then_statement) if stmt.then_statement else []
                for c in java_constraints:
                    if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                        logger.info("[AST][Java] Branch constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                        _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
                        return (-1, None, 0)
                if then_stmts:
                    result = parameters_back(param_name, then_stmts, vul_lineno, file_path,
                                              repair_functions, controlled_params, depth + 1, max_depth)
                    if result[0] in (1, 2):
                        _trace_cache.put(file_path, param_name, vul_lineno, result)
                        return result

            elif sink_branch == 'else':
                else_constraints = [c.negate() for c in java_constraints]
                if stmt.else_statement and isinstance(stmt.else_statement, javalang.tree.IfStatement):
                    # else if
                    for c in else_constraints:
                        if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                            logger.info("[AST][Java] Branch constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                            _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
                            return (-1, None, 0)
                    result = parameters_back(param_name, [stmt.else_statement], vul_lineno, file_path,
                                              repair_functions, controlled_params, depth + 1, max_depth)
                    if result[0] in (1, 2):
                        _trace_cache.put(file_path, param_name, vul_lineno, result)
                        return result
                else:
                    else_stmts = _get_block_stmts(stmt.else_statement) if stmt.else_statement else []
                    for c in else_constraints:
                        if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                            logger.info("[AST][Java] Branch constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                            _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
                            return (-1, None, 0)
                    if else_stmts:
                        result = parameters_back(param_name, else_stmts, vul_lineno, file_path,
                                                  repair_functions, controlled_params, depth + 1, max_depth)
                        if result[0] in (1, 2):
                            _trace_cache.put(file_path, param_name, vul_lineno, result)
                            return result
            else:
                # outside: 保持遍历所有分支找重赋值
                then_stmts = _get_block_stmts(stmt.then_statement) if stmt.then_statement else []
                if then_stmts:
                    then_result = parameters_back(param_name, then_stmts, vul_lineno, file_path,
                                                  repair_functions, controlled_params, depth + 1, max_depth)
                    if then_result[0] in (1, 2, 3):
                        _trace_cache.put(file_path, param_name, vul_lineno, then_result)
                        return then_result
                if stmt.else_statement:
                    if isinstance(stmt.else_statement, javalang.tree.IfStatement):
                        else_result = parameters_back(param_name, [stmt.else_statement], vul_lineno, file_path,
                                                      repair_functions, controlled_params, depth + 1, max_depth)
                    else:
                        else_stmts = _get_block_stmts(stmt.else_statement) if stmt.else_statement else []
                        if else_stmts:
                            else_result = parameters_back(param_name, else_stmts, vul_lineno, file_path,
                                                          repair_functions, controlled_params, depth + 1, max_depth)
                        else:
                            else_result = (-1, None, 0)
                    if else_result[0] in (1, 2, 3):
                        _trace_cache.put(file_path, param_name, vul_lineno, else_result)
                        return else_result

        elif isinstance(stmt, (javalang.tree.WhileStatement, javalang.tree.DoStatement)):
            block_stmts = _get_block_stmts(stmt)
            # while 循环条件等值约束检查：如果 while 条件中 param_name 有 == 约束，且 sink 在 while 体内 → 阻断
            if block_stmts and vul_lineno:
                _vul_line = int(vul_lineno)
                body_start = _get_stmt_line(block_stmts[0])
                body_end = _get_stmt_line(block_stmts[-1])
                if body_start and body_end and body_start <= _vul_line <= body_end:
                    constraints = extract_constraints_from_java_expr(stmt.condition)
                    for c in constraints:
                        if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                            logger.info("[AST][Java] While constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                            _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
                            return (-1, None, 0)
            if block_stmts:
                result = parameters_back(param_name, block_stmts, stmt_line, file_path,
                                          repair_functions, controlled_params, depth + 1, max_depth)
                if result[0] in (1, 2):
                    _trace_cache.put(file_path, param_name, vul_lineno, result)
                    return result

        elif isinstance(stmt, javalang.tree.ForStatement):
            block_stmts = _get_block_stmts(stmt)
            if block_stmts:
                result = parameters_back(param_name, block_stmts, stmt_line, file_path,
                                          repair_functions, controlled_params, depth + 1, max_depth)
                if result[0] in (1, 2):
                    _trace_cache.put(file_path, param_name, vul_lineno, result)
                    return result

        # try-catch
        if isinstance(stmt, javalang.tree.TryStatement):
            for block in (stmt.block or []):
                result = parameters_back(param_name, _flatten_statements(block) if isinstance(block, list) else [block],
                                          stmt_line, file_path, repair_functions, controlled_params, depth + 1, max_depth)
                if result[0] in (1, 2):
                    _trace_cache.put(file_path, param_name, vul_lineno, result)
                    return result

        # switch/case 分支约束追踪
        if isinstance(stmt, javalang.tree.SwitchStatement):
            switch_line = _get_stmt_line(stmt)
            # 判断 sink 在哪个 case 中
            sink_case_is_default = False
            sink_in_case = False
            if stmt.cases:
                for case in stmt.cases:
                    case_stmts = case.statements or []
                    if not case_stmts:
                        continue
                    first_line = _get_stmt_line(case_stmts[0])
                    last_line = _get_stmt_line(case_stmts[-1])
                    if first_line and last_line and first_line <= target_line <= last_line:
                        if not case.case:  # default case 的 case 属性为空列表
                            sink_case_is_default = True
                        else:
                            sink_in_case = True
                        break

            if sink_in_case:
                # sink 在非 default case 中 → switch expr == case_value → 阻断
                logger.info("[AST][Java] Switch constraint BLOCKS: sink in non-default case (line {})".format(vul_lineno))
                _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
                return (-1, None, 0)

            # default case 或 sink 不在任何 case 中 → 遍历目标 case
            # 如果目标 case 中未找到赋值，fallthrough 让外层 for 循环继续搜索 switch 之前的 stmts
            if stmt.cases:
                for case in stmt.cases:
                    case_stmts = case.statements or []
                    if not case_stmts:
                        continue
                    # 只处理 sink 所在的 case
                    first_line = _get_stmt_line(case_stmts[0])
                    last_line = _get_stmt_line(case_stmts[-1])
                    if first_line and last_line and first_line <= target_line <= last_line:
                        result = parameters_back(param_name, case_stmts, vul_lineno, file_path,
                                                  repair_functions, controlled_params, depth + 1, max_depth)
                        if result[0] in (1, 2):
                            _trace_cache.put(file_path, param_name, vul_lineno, result)
                            return result
                        # case 内未找到赋值 → 不清除缓存，不写入 -1
                        # break 出内层 for，让外层 for 循环继续处理 switch 之前的 stmts
                        break

    # 检查 param_name 是否是方法形参 → code=5，交给 NewCore
    if method_params is not None and param_name in method_params:
        qualified_name = f"{class_name}.{method_name}" if class_name else method_name
        logger.debug("[AST][Java] Variable {} is a parameter of method {}, return code=5 (wrapper: {})".format(
            param_name, method_name, qualified_name))
        _trace_cache.put(file_path, param_name, vul_lineno, (5, qualified_name, 0))
        return (5, qualified_name, 0)

    # for 循环结束后仍未找到 → 不可控
    _trace_cache.put(file_path, param_name, vul_lineno, (-1, None, 0))
    return (-1, None, 0)


def _trace_expr(expr, stmts, lineno, file_path, repair_functions, controlled_params, depth=0, max_depth=10):
    """
    追踪表达式的数据流来源。

    返回: (code, cp, expr_lineno)
    """
    if expr is None or depth > max_depth:
        return (3, None, 0)

    # 字面量 → 不可控
    if isinstance(expr, javalang.tree.Literal):
        return (-1, None, 0)

    # 变量引用 → 递归追踪
    if isinstance(expr, javalang.tree.MemberReference):
        var_name = expr.member
        # 检查是否是可控源
        if _is_controllable_source(var_name, controlled_params):
            return (1, var_name, lineno)
        # 继续反向追踪
        return parameters_back(var_name, stmts, lineno, file_path,
                                repair_functions, controlled_params, depth + 1, max_depth)

    # 方法调用 → function_back
    if isinstance(expr, javalang.tree.MethodInvocation):
        return function_back_java(expr, stmts, lineno, file_path,
                                   repair_functions, controlled_params, depth, max_depth)

    # 二元运算 → 追踪任一侧可控即可
    if isinstance(expr, javalang.tree.BinaryOperation):
        left_result = _trace_expr(expr.operandl, stmts, lineno, file_path,
                                   repair_functions, controlled_params, depth + 1, max_depth)
        if left_result[0] == 1:
            return left_result
        right_result = _trace_expr(expr.operandr, stmts, lineno, file_path,
                                    repair_functions, controlled_params, depth + 1, max_depth)
        if right_result[0] == 1:
            return right_result
        # 两边都不直接可控，检查 deps
        deps = []
        if left_result[0] == 'deps':
            deps.extend(left_result[1] if isinstance(left_result[1], list) else [left_result[1]])
        if right_result[0] == 'deps':
            deps.extend(right_result[1] if isinstance(right_result[1], list) else [right_result[1]])
        if deps:
            return ('deps', list(set(deps)), lineno)
        return (-1, None, 0)

    # 类型转换 → 追踪内部
    if isinstance(expr, javalang.tree.Cast):
        return _trace_expr(expr.expression, stmts, lineno, file_path,
                           repair_functions, controlled_params, depth + 1, max_depth)

    # 赋值 → 追踪右侧
    if isinstance(expr, javalang.tree.Assignment):
        return _trace_expr(expr.value, stmts, lineno, file_path,
                           repair_functions, controlled_params, depth + 1, max_depth)

    # new 表达式 → 追踪参数
    if isinstance(expr, javalang.tree.ClassCreator):
        for arg in (expr.arguments or []):
            result = _trace_expr(arg, stmts, lineno, file_path,
                                  repair_functions, controlled_params, depth + 1, max_depth)
            if result[0] == 1:
                return result
        return (-1, None, 0)

    # 三元表达式 → 分支约束追踪
    if isinstance(expr, javalang.tree.TernaryExpression):
        true_refs = _collect_member_references(expr.if_true)
        false_refs = _collect_member_references(expr.if_false)
        constraints = extract_constraints_from_java_expr(expr.condition)
        for c in constraints:
            if c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                if c.var_name in true_refs and c.var_name not in false_refs:
                    # 约束变量只在 true 分支 → true 路径中 var == fixed → 阻断
                    logger.info("[AST][Java] Ternary constraint BLOCKS: {} {} {}".format(c.var_name, c.op, c.value))
                    return (-1, None, 0)
                elif c.var_name in false_refs and c.var_name not in true_refs:
                    # 约束变量只在 false 分支 → false 路径中 var != fixed → 不阻断，追踪 false 分支
                    return _trace_expr(expr.if_false, stmts, lineno, file_path,
                                      repair_functions, controlled_params, depth + 1, max_depth)

        # 回退：无明确约束阻断
        true_result = _trace_expr(expr.if_true, stmts, lineno, file_path,
                                   repair_functions, controlled_params, depth + 1, max_depth)
        if true_result[0] == 1:
            return true_result
        false_result = _trace_expr(expr.if_false, stmts, lineno, file_path,
                                    repair_functions, controlled_params, depth + 1, max_depth)
        if false_result[0] == 1:
            return false_result
        return (-1, None, 0)

    return (3, None, 0)


# --- Source 判定函数 ---

_REQUEST_SOURCE_METHODS = frozenset({
    "getParameter", "getHeader", "getInputStream", "getReader",
    "getQueryString", "getCookies", "getParameterValues", "getParameterMap",
    "getPart", "getParts", "getInputStream",
})


def _is_request_source(func_name):
    """检查函数名是否是 HTTP 请求 source（如 getParameter、getHeader 等）"""
    short = func_name.split(".")[-1] if "." in func_name else func_name
    return short in _REQUEST_SOURCE_METHODS


def _is_controllable_source(name, controlled_params):
    """检查变量名是否在可控参数列表中"""
    if not controlled_params:
        return False
    for cp in controlled_params:
        if name == cp or (isinstance(cp, str) and name in cp):
            return True
    return False


def function_back_java(call_node, stmts, vul_lineno, file_path,
                        repair_functions=None, controlled_params=None, depth=0, max_depth=10):
    """
    追踪方法调用的返回值是否可控。
    call_node 是 MethodInvocation 节点。

    返回: (code, cp, expr_lineno)
    """
    global _scan_function_stack

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    func_name = call_node.member
    qualifier = call_node.qualifier or ''
    full_name = f"{qualifier}.{func_name}" if qualifier else func_name

    # 检查递归
    if full_name in _scan_function_stack:
        return (-1, None, 0)

    # 1. 检查是否是可控源（如 request.getParameter）
    if _is_request_source(full_name) or _is_request_source(func_name):
        # 返回值直接来自请求参数
        arg_str = _expr_to_str_java(call_node.arguments[0]) if call_node.arguments else ''
        return (1, f"{full_name}({arg_str})", vul_lineno)

    # Source Discovery: 检查用户自定义 source producer
    if _source_registry is not None:
        source_info = _source_registry.is_source_producer(full_name)
        if source_info:
            logger.debug('[AST][Java] Source Discovery: {} is a source producer ({})'.format(
                full_name, source_info.origin))
            arg_str = _expr_to_str_java(call_node.arguments[0]) if call_node.arguments else ''
            return (1, f"{full_name}({arg_str})", vul_lineno)

    # 2. 查内置知识库
    for name_variant in [full_name, func_name]:
        knowledge = lookup_builtin(name_variant)
        if knowledge:
            if knowledge.get("safe") and not knowledge.get("passthrough") and not knowledge.get("param_flow"):
                return (-1, None, 0)
            if knowledge.get("passthrough") or knowledge.get("param_flow"):
                for pt_idx in knowledge["passthrough"]:
                    if pt_idx < len(call_node.arguments or []):
                        arg = call_node.arguments[pt_idx]
                        result = _trace_expr(arg, stmts, vul_lineno, file_path,
                                             repair_functions, controlled_params, depth + 1, max_depth)
                        if result[0] == 1:
                            return result
                return (-1, None, 0)

    # 3. 检查修复函数
    if _has_repair_function(call_node, repair_functions):
        return (2, full_name, vul_lineno)

    # 4. 查函数摘要
    callee_summary = lookup_summary(full_name)
    if callee_summary and callee_summary.return_flow:
        result = _judge_from_summary_java(callee_summary, call_node, controlled_params)
        if result is not None:
            return result

    # 5. 找函数定义做 AST 分析
    _scan_function_stack.append(full_name)
    try:
        # 从全局方法索引中查找
        global_methods = _build_global_method_map(_ast_object_singleton, file_path)
        method_def = None
        method_tree = None
        method_filepath = None

        param_count = len(call_node.arguments or [])
        gkey = (func_name, param_count)
        if gkey in global_methods:
            for ast_tree, method_node, mfp in global_methods[gkey]:
                method_def = method_node
                method_tree = ast_tree
                method_filepath = mfp
                break

        if method_def and hasattr(method_def, 'body') and method_def.body:
            # 分析函数体的 return 语句
            for rstmt in _flatten_statements(method_def.body):
                if isinstance(rstmt, javalang.tree.ReturnStatement) and rstmt.expression:
                    # 建立参数映射
                    func_params = []
                    if hasattr(method_def, 'parameters') and method_def.parameters:
                        func_params = [p.name for p in method_def.parameters]

                    # 递归追踪 return 表达式
                    ret_result = _trace_return_in_func(
                        rstmt.expression, method_def.body,
                        func_params, call_node.arguments or [],
                        vul_lineno, file_path, repair_functions, controlled_params,
                        depth + 1, max_depth
                    )
                    if ret_result[0] == 1:
                        return ret_result
    finally:
        if full_name in _scan_function_stack:
            _scan_function_stack.remove(full_name)

    # 6. 追踪参数中是否有可控的
    for arg in (call_node.arguments or []):
        result = _trace_expr(arg, stmts, vul_lineno, file_path,
                              repair_functions, controlled_params, depth + 1, max_depth)
        if result[0] == 1:
            return result

    return (-1, None, 0)


def _trace_return_in_func(expr, func_body_stmts, func_params, call_args,
                           vul_lineno, file_path, repair_functions, controlled_params,
                           depth=0, max_depth=10):
    """在函数体内追踪 return 表达式的数据流，带参数映射"""
    if expr is None or depth > max_depth:
        return (3, None, 0)

    # 变量引用 → 检查是否是形参
    if isinstance(expr, javalang.tree.MemberReference):
        var_name = expr.member
        if var_name in func_params:
            param_idx = func_params.index(var_name)
            if param_idx < len(call_args):
                # 映射到实参，追踪实参
                return _trace_expr(call_args[param_idx], [], vul_lineno, file_path,
                                    repair_functions, controlled_params, depth + 1, max_depth)
        # 函数体内的局部变量 → 在函数体内追踪
        return parameters_back(var_name, _flatten_statements(func_body_stmts), vul_lineno, file_path,
                                repair_functions, controlled_params, depth + 1, max_depth)

    # 方法调用
    if isinstance(expr, javalang.tree.MethodInvocation):
        # 同 function_back_java 但用函数体作为上下文
        func_name = expr.member
        if _is_request_source(func_name):
            return (1, func_name, vul_lineno)

    # 二元运算
    if isinstance(expr, javalang.tree.BinaryOperation):
        left = _trace_return_in_func(expr.operandl, func_body_stmts, func_params, call_args,
                                      vul_lineno, file_path, repair_functions, controlled_params, depth + 1, max_depth)
        if left[0] == 1:
            return left
        right = _trace_return_in_func(expr.operandr, func_body_stmts, func_params, call_args,
                                       vul_lineno, file_path, repair_functions, controlled_params, depth + 1, max_depth)
        if right[0] == 1:
            return right
        return (-1, None, 0)

    return (3, None, 0)


def _judge_from_summary_java(summary, call_node, controlled_params):
    """根据函数摘要判定返回值可控性（Java版）"""
    if controlled_params is None:
        return None

    call_args = call_node.arguments or []

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                if param_idx < len(call_args):
                    arg = call_args[param_idx]
                    arg_name = _get_var_name(arg) or _expr_to_str_java(arg)
                    if _is_controllable_source(arg_name, controlled_params):
                        return (1, arg_name, 0)
                    # 收集变量名返回 deps
                    names = _collect_names_from_node(arg)
                    if names:
                        return ('deps', list(names), 0)

        elif rf.origin_type == "global":
            if _is_controllable_source(rf.origin, controlled_params):
                return (1, rf.origin, 0)

        elif rf.origin_type == "call":
            if _is_request_source(rf.origin):
                return (1, rf.origin, 0)

        elif rf.origin_type == "literal":
            continue

    return None


def _find_sink_branch_java(if_stmt, vul_lineno):
    """判断 sink 在 Java if/else 的哪个分支"""
    if not vul_lineno:
        return 'outside'
    vul_lineno = int(vul_lineno)

    # then 体范围
    then_stmts = _get_block_stmts(if_stmt.then_statement) if if_stmt.then_statement else []
    if then_stmts:
        then_line = _get_stmt_line(then_stmts[0])
        then_end = _get_stmt_line(then_stmts[-1])
        if then_line and then_end and then_line <= vul_lineno <= then_end:
            return 'if'

    # else 体
    if if_stmt.else_statement:
        if isinstance(if_stmt.else_statement, javalang.tree.IfStatement):
            return _find_sink_branch_java(if_stmt.else_statement, vul_lineno)
        else_stmts = _get_block_stmts(if_stmt.else_statement) if if_stmt.else_statement else []
        if else_stmts:
            else_line = _get_stmt_line(else_stmts[0])
            else_end = _get_stmt_line(else_stmts[-1])
            if else_line and else_end and else_line <= vul_lineno <= else_end:
                return 'else'

    return 'outside'


def _get_stmt_line(stmt):
    """获取语句行号"""
    if hasattr(stmt, 'position') and stmt.position:
        return stmt.position[0]
    return None


def _get_block_stmts(stmt):
    """从控制流语句中提取块语句列表"""
    if isinstance(stmt, javalang.tree.BlockStatement):
        return stmt.statements
    if hasattr(stmt, 'body') and isinstance(stmt.body, list):
        return stmt.body
    if hasattr(stmt, 'statement'):
        return [stmt.statement] if stmt.statement else []
    return []


def _init_function_summaries(file_path):
    """初始化 Java 文件的函数摘要"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.function_summary import SummaryCacheManager
        from core.core_engine.java.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, 'pre_result'):
            import os
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'java':
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                            files_dict[fp] = f.read()
                    except Exception:
                        pass
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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
            logger.debug(f"[AST][Java] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Java] 摘要初始化失败: {e}")


def _find_method_at_line(tree, target_line):
    """找到包含目标行号的 MethodDeclaration"""
    target = int(target_line)
    # 收集所有方法并按行号排序
    methods = []
    for path, node in tree.filter(javalang.tree.MethodDeclaration):
        if node.position:
            methods.append(node)
    methods.sort(key=lambda m: m.position.line)

    # 找到目标行所在的方法：target >= start 且 target < next_method.start
    for i, method in enumerate(methods):
        start = method.position.line
        # 用下一个方法的起始行作为当前方法的上界
        if i + 1 < len(methods):
            upper = methods[i + 1].position.line
        else:
            upper = target + 1  # 最后一个方法，只要 >= start 就算
        if start <= target < upper:
            return method

    # Fallback: grep 10行缓冲可能导致行号偏移，扩大搜索范围
    for offset in range(1, 11):
        for direction in (offset, -offset):
            adj_target = target + direction
            if adj_target < 1:
                continue
            for i, method in enumerate(methods):
                start = method.position.line
                if i + 1 < len(methods):
                    upper = methods[i + 1].position.line
                else:
                    upper = adj_target + 1
                if start <= adj_target < upper:
                    return method
    return None


def _collect_controllable_vars(method_node, request_var_names, source_lines=None):
    """
    收集方法体中的可控变量名集合
    可控来源：
    1. HttpServletRequest 参数变量本身
    2. request.getParameter/getHeader/... 赋值的局部变量
    3. 方法参数（如果是 String 类型且在 controlled_params 中）
    """
    controllable = set()

    # request 变量本身可控
    for rvn in request_var_names:
        controllable.add(rvn)

    # 方法参数识别 —— 基于类型和注解
    SPRING_PARAM_ANNOTATIONS = {
        'RequestParam', 'PathVariable', 'RequestBody',
        'RequestHeader', 'CookieValue', 'ModelAttribute',
    }

    JAXRS_PARAM_ANNOTATIONS = {
        'PathParam', 'QueryParam', 'FormParam',
        'HeaderParam', 'BeanParam',
    }

    ALL_PARAM_ANNOTATIONS = SPRING_PARAM_ANNOTATIONS | JAXRS_PARAM_ANNOTATIONS

    if method_node.parameters:
        for param in method_node.parameters:
            param_type = ""
            if hasattr(param, 'type') and param.type:
                param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)

            # 1. HttpServletRequest 等含 Request 的类型 → 可控（Servlet API）
            if 'Request' in param_type:
                controllable.add(param.name)
                logger.debug("[AST][Java] Controllable method param (Request type): {}".format(param.name))
                continue

            # 2. MultipartFile / InputStream 类型 → 可控（文件上传/输入流）
            if 'MultipartFile' in param_type or 'InputStream' in param_type:
                controllable.add(param.name)
                logger.debug("[AST][Java] Controllable method param (File/Stream type): {}".format(param.name))
                continue

            # 3. Principal 类型 → 可控（认证主体可能被伪造）
            if 'Principal' in param_type:
                controllable.add(param.name)
                continue

            # 4. 检查参数注解（Spring / JAX-RS）
            if hasattr(param, 'annotations') and param.annotations:
                for ann in param.annotations:
                    ann_name = ann.name if hasattr(ann, 'name') else str(ann)
                    # 处理全限定名如 org.springframework.web.bind.annotation.RequestParam
                    if '.' in ann_name:
                        ann_name = ann_name.split('.')[-1]
                    if ann_name in ALL_PARAM_ANNOTATIONS:
                        controllable.add(param.name)
                        logger.debug("[AST][Java] Controllable method param (annotation @{}): {}".format(
                            ann_name, param.name))
                        break

    if not method_node.body:
        return controllable

    # 遍历局部变量声明，找 request.getParameter() 等赋值
    for stmt in method_node.body:
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if declarator.initializer:
                    init = declarator.initializer
                    if isinstance(init, javalang.tree.MethodInvocation):
                        # request.getParameter / request.getHeader / request.getInputStream 等
                        if (init.qualifier in request_var_names and
                                init.member in ("getParameter", "getHeader", "getInputStream",
                                                "getReader", "getQueryString", "getCookies",
                                                "getParameterValues", "getParameterMap",
                                                "getPart", "getParts")):
                            controllable.add(declarator.name)
                            logger.debug("[AST][Java] Controllable var: {} from {}.{}()".format(
                                declarator.name, init.qualifier, init.member))

                        # Spring 常见获取输入的方式
                        # 如: params.get("key"), map.get("key") 当 params/map 是 @RequestParam Map 时
                        # 如: body.get("key") 当 body 是 Map 类型来自 @RequestBody 时
                        if init.member == 'get' and init.qualifier in controllable:
                            controllable.add(declarator.name)
                            logger.debug("[AST][Java] Controllable var: {} from {}.get()".format(
                                declarator.name, init.qualifier))

    # 对象级污点传播：多轮传播直到稳定
    # 处理: obj = new SomeClass(controllable_arg) → obj 可控
    # 处理: obj = controllable.method() → obj 可控
    # 处理: obj = other.method(controllable_arg) → obj 可控
    _propagate_object_taint(method_node, controllable, source_lines=source_lines)

    return controllable


def _propagate_object_taint(method_node, controllable, max_rounds=5, source_lines=None):
    """
    对象级污点传播：追踪 new SomeClass(controllable) / controllable.method() 等赋值

    :param method_node: 方法 AST 节点
    :param controllable: 可控变量集合（会被原地修改）
    :param max_rounds: 最大传播轮数
    :param source_lines: 源码行列表（1-indexed），用于 javalang 解析失败时的文本 fallback
    """
    if not method_node.body:
        return

    changed = True
    rounds = 0
    while changed and rounds < max_rounds:
        changed = False
        rounds += 1

        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue

            for declarator in stmt.declarators:
                if not declarator.initializer or declarator.name in controllable:
                    continue

                init = declarator.initializer
                target_var = declarator.name

                # 模式A: obj = new SomeClass(controllable_arg)
                # 如: ObjectInputStream ois = new ObjectInputStream(bytes)
                # 如: URL url = new URL(userInput)
                if isinstance(init, javalang.tree.ClassCreator):
                    if init.arguments:
                        for arg in init.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & controllable:
                                controllable.add(target_var)
                                logger.debug("[AST][Java] Object taint propagation: {} = new {}(...) [from {}]".format(
                                    target_var, init.type.name if init.type else "?", set(refs) & controllable))
                                changed = True
                                break

                # 模式B: x = obj.method(controllable_arg) 或 x = controllable.method()
                elif isinstance(init, javalang.tree.MethodInvocation):
                    # B1: 方法参数包含可控变量
                    if init.arguments:
                        refs = set()
                        for arg in init.arguments:
                            refs.update(_collect_member_references(arg))
                        if refs & controllable:
                            controllable.add(target_var)
                            logger.debug("[AST][Java] Object taint propagation: {} from {}.{}() args".format(
                                target_var, init.qualifier or "?", init.member))
                            changed = True

                    # B2: qualifier 可控 (如 targetUrl.openConnection())
                    if not changed and isinstance(init.qualifier, str) and init.qualifier in controllable:
                        controllable.add(target_var)
                        logger.debug("[AST][Java] Object taint propagation: {} = {}.{})() [qualifier]".format(
                            target_var, init.qualifier, init.member))
                        changed = True

                    # 链式调用 selectors 传播：obj.b().c() → b() 结果可控则 c() 结果也可控
                    if hasattr(init, 'selectors') and init.selectors:
                        prev_result_controllable = target_var in controllable
                        for sel in init.selectors:
                            if isinstance(sel, javalang.tree.MethodInvocation):
                                # 如果上一步结果可控，或者这一步的参数可控
                                sel_refs = set()
                                if sel.arguments:
                                    for arg in sel.arguments:
                                        sel_refs.update(_collect_member_references(arg))
                                if prev_result_controllable or (sel_refs & controllable):
                                    controllable.add(target_var)
                                    prev_result_controllable = True
                                    logger.debug("[AST][Java] Object taint (chain sel): {} is controllable via chain.{}".format(
                                        target_var, sel.member))

                # 模式C: 字符串拼接 x = y + z
                elif isinstance(init, javalang.tree.BinaryOperation):
                    refs = _collect_member_references(init)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式D: 类型转换 x = (Type) y
                elif isinstance(init, javalang.tree.Cast):
                    refs = _collect_member_references(init.expression)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式E: 赋值语句 x = y
                elif isinstance(init, javalang.tree.MemberReference):
                    if init.member in controllable:
                        controllable.add(target_var)
                        changed = True

    # 源码文本 fallback：javalang 无法正确解析链式调用时（如 Base64.getDecoder().decode(data)），
    # 直接检查赋值语句的源码文本中是否包含可控变量名
    # 排除字符串字面量内的匹配（避免 "SELECT * FROM users WHERE name=?" 中的 name 被误判）
    if source_lines and controllable:
        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue
            for declarator in stmt.declarators:
                if declarator.name in controllable or not declarator.initializer:
                    continue
                # 用 AST position 定位到源码行
                lineno = stmt.position.line if stmt.position else 0
                if lineno <= 0 or lineno > len(source_lines):
                    continue
                line_text = source_lines[lineno - 1]
                # 去掉字符串字面量（单引号和双引号内容），防止误判
                code_only = re.sub(r'"[^"]*"', '""', line_text)
                code_only = re.sub(r"'[^']*'", "''", code_only)
                # 检查剩余文本中是否包含任何可控变量名（单词边界匹配）
                for var in list(controllable):
                    if re.search(r'\b' + re.escape(var) + r'\b', code_only):
                        controllable.add(declarator.name)
                        logger.debug("[AST][Java] Source-text fallback propagation: {} (line {} contains '{}')".format(
                            declarator.name, lineno, var))
                        break


def _find_request_var_names(method_node):
    """从方法参数中找到 HttpServletRequest 类型的变量名"""
    request_vars = set()
    if method_node.parameters:
        for param in method_node.parameters:
            if hasattr(param, 'type') and param.type:
                type_name = param.type.name if hasattr(param.type, 'name') else str(param.type)
                if 'Request' in type_name or 'HttpServletRequest' in type_name:
                    request_vars.add(param.name)
    return request_vars


def _find_annotated_param_names(method_node):
    """从方法参数注解中找到被 Spring/JAX-RS 注解标记的参数名"""
    SPRING_ANN = {'RequestParam', 'PathVariable', 'RequestBody',
                  'RequestHeader', 'CookieValue', 'ModelAttribute'}
    JAXRS_ANN = {'PathParam', 'QueryParam', 'FormParam',
                 'HeaderParam', 'BeanParam'}
    ALL_ANN = SPRING_ANN | JAXRS_ANN

    annotated_params = set()
    if method_node.parameters:
        for param in method_node.parameters:
            if hasattr(param, 'annotations') and param.annotations:
                for ann in param.annotations:
                    ann_name = ann.name if hasattr(ann, 'name') else str(ann)
                    if '.' in ann_name:
                        ann_name = ann_name.split('.')[-1]
                    if ann_name in ALL_ANN:
                        annotated_params.add(param.name)
                        break
    return annotated_params


def _is_passthrough_method(method_node, param_name, repair_functions, class_methods=None, depth=0, max_depth=3,
                            global_methods=None):
    """
    检查方法的某个参数是否被直接透传返回（或经安全方法处理后返回）
    
    透传条件：
    1. 方法体有 ReturnStatement，返回的是该参数或其方法调用
    2. 返回链上没有经过修复函数
    
    支持跨文件递归查找：当 return otherMethod(s) 中的 otherMethod 不在当前文件时，
    去 global_methods 中查找。
    
    支持嵌套调用透传：return obj.method(s.trim()) 
    当 s 是参数时，检查 obj.method 的第一个参数是否透传。
    
    :param method_node: 方法 AST 节点
    :param param_name: 参数名
    :param repair_functions: 修复函数列表
    :param class_methods: 同类其他方法的 dict（用于递归分析）
    :param depth: 当前递归深度
    :param max_depth: 最大递归深度
    :param global_methods: 跨文件全局方法映射
    :return: True 表示参数被透传
    """
    if depth >= max_depth or not method_node or not method_node.body:
        return False

    # 查内置知识库：已知方法直接返回透传结果
    method_name = getattr(method_node, 'name', None)
    if method_name:
        knowledge = lookup_builtin(method_name)
        if knowledge:
            if knowledge["safe"] and not knowledge["passthrough"] and not knowledge.get("param_flow"):
                return False  # 安全过滤函数，不透传
            if knowledge["passthrough"] or knowledge.get("param_flow"):
                return True  # 透传参数
            return False  # 不透传

    for stmt in method_node.body:
        if isinstance(stmt, javalang.tree.ReturnStatement) and stmt.expression:
            expr = stmt.expression

            # 直接返回参数引用
            if isinstance(expr, javalang.tree.MemberReference):
                if expr.member == param_name:
                    return True

            # 返回参数的方法调用 (如 s.trim(), s.toLowerCase())
            if isinstance(expr, javalang.tree.MethodInvocation):
                # 检查是否是修复函数
                if expr.member in repair_functions:
                    return False

                # qualifier 是参数名 → 直接透传
                if isinstance(expr.qualifier, str) and expr.qualifier == param_name:
                    return True
                if isinstance(expr.qualifier, javalang.tree.MemberReference):
                    if expr.qualifier.member == param_name:
                        return True

                # 嵌套调用透传：return obj.method(s.trim())
                # 检查参数中是否包含对 param_name 的引用
                called_name = expr.member
                if expr.arguments and depth + 1 < max_depth:
                    # 找到哪些参数位置包含对 param_name 的引用
                    param_has_ref = False
                    for arg in expr.arguments:
                        refs = _collect_member_references(arg)
                        if param_name in refs:
                            param_has_ref = True
                            break
                    
                    if param_has_ref:
                        # 1. 先在同文件方法映射中找
                        found_target = False
                        if class_methods and called_name in class_methods:
                            target_method = class_methods[called_name]
                            if target_method.parameters:
                                target_param_name = target_method.parameters[0].name
                                if _is_passthrough_method(target_method, target_param_name, repair_functions,
                                                          class_methods, depth + 1, max_depth,
                                                          global_methods=global_methods):
                                    return True
                            found_target = True
                        
                        # 2. 去全局映射中找（跨文件递归）
                        if not found_target and global_methods:
                            call_arg_count = len(expr.arguments) if expr.arguments else 0
                            key = (called_name, call_arg_count)
                            if key in global_methods:
                                for remote_tree, remote_method, remote_filepath in global_methods[key]:
                                    if remote_method.parameters:
                                        target_param_name = remote_method.parameters[0].name
                                        remote_cm = _build_class_method_map(remote_tree)
                                        if _is_passthrough_method(remote_method, target_param_name, repair_functions,
                                                                  remote_cm, depth + 1, max_depth,
                                                                  global_methods=global_methods):
                                            return True

    return False


def _build_class_method_map(tree):
    """从 AST 树中构建 类名→方法 的映射"""
    class_methods = {}
    for path, node in tree.filter(javalang.tree.MethodDeclaration):
        class_methods[node.name] = node
    return class_methods


def _build_global_method_map(ast_obj, current_filepath):
    """
    遍历所有 Java 文件的 AST，构建全局方法映射（用于跨文件传播）
    
    返回: {(method_name, param_count): [(tree, method_node, filepath), ...]}
    - method_name: 方法名
    - param_count: 参数数量（用于消歧义）
    - tree: 文件的 AST 树
    - method_node: 方法声明节点
    - filepath: 文件路径
    """
    global_methods = {}
    
    if ast_obj is None or not hasattr(ast_obj, 'pre_result'):
        return global_methods
    
    for filepath, file_data in ast_obj.pre_result.items():
        # 跳过非 Java 文件
        if not filepath.endswith('.java'):
            continue
        
        ast_nodes = file_data.get('ast_nodes')
        if not ast_nodes:
            continue
        
        try:
            for ast_tree in (ast_nodes if isinstance(ast_nodes, list) else [ast_nodes]):
                for _, node in ast_tree.filter(javalang.tree.MethodDeclaration):
                    param_count = len(node.parameters) if node.parameters else 0
                    key = (node.name, param_count)
                    if key not in global_methods:
                        global_methods[key] = []
                    global_methods[key].append((ast_tree, node, filepath))
        except Exception as e:
            logger.warning('[AST][Java] _build_global_method_map failed for {}: {}'.format(filepath, e))
            continue

    return global_methods


def _flatten_statements(body):
    """递归展开方法体中的嵌套控制结构（TryStatement, IfStatement 等），返回扁平语句列表。"""
    if not body:
        return []
    result = []
    for stmt in body:
        result.append(stmt)
        # TryStatement: block, catches, finally_block
        if isinstance(stmt, javalang.tree.TryStatement):
            result.extend(_flatten_statements(stmt.block))
            for catch in (stmt.catches or []):
                result.extend(_flatten_statements(catch.block))
            result.extend(_flatten_statements(stmt.finally_block))
        # IfStatement: then_statement, else_statement
        elif isinstance(stmt, javalang.tree.IfStatement):
            result.extend(_flatten_statements(stmt.then_statement if isinstance(stmt.then_statement, list) else [stmt.then_statement] if stmt.then_statement else []))
            result.extend(_flatten_statements(stmt.else_statement if isinstance(stmt.else_statement, list) else [stmt.else_statement] if stmt.else_statement else []))
        # ForStatement, WhileStatement, DoStatement: body
        elif hasattr(stmt, 'body') and isinstance(getattr(stmt, 'body', None), list):
            result.extend(_flatten_statements(stmt.body))
        # BlockStatement: statements
        elif isinstance(stmt, javalang.tree.BlockStatement):
            result.extend(_flatten_statements(stmt.statements))
    return result


def _check_caller_controllability(current_method, ast_obj, repair_functions, global_methods=None, depth=0, max_depth=3):
    """
    反向调用链分析：检查当前方法的调用者是否传入了可控参数。
    
    当当前方法中没有 request source（controllable 为空）时，
    通过全局方法映射找到所有调用当前方法的地方，检查调用者传的参数是否可控。
    
    支持递归：如果调用者本身也没有 request source，递归检查调用者的调用者。
    
    返回: set of 参数名 → 这些参数被调用者传入了可控数据
    """
    controllable_params = set()
    
    if depth >= max_depth:
        return controllable_params
    
    # 查缓存
    method_key = current_method.name
    cached = _trace_cache.get("__java_caller__", method_key, depth)
    if cached is not None:
        return cached
    
    if ast_obj is None or not hasattr(ast_obj, 'pre_result'):
        return controllable_params
    
    if not current_method.parameters:
        return controllable_params
    
    current_method_name = current_method.name
    
    # 遍历所有文件，找到调用当前方法的地方
    for filepath, file_data in ast_obj.pre_result.items():
        if not filepath.endswith('.java'):
            continue
        
        ast_nodes = file_data.get('ast_nodes')
        if not ast_nodes:
            continue
        
        try:
            # 找到所有方法声明，检查其方法体中是否调用了 current_method_name
            for ast_tree in (ast_nodes if isinstance(ast_nodes, list) else [ast_nodes]):
                for _, caller_method in ast_tree.filter(javalang.tree.MethodDeclaration):
                    if not caller_method.body:
                        continue
                    
                    flat_stmts = _flatten_statements(caller_method.body)
                    for stmt in flat_stmts:
                        call_expr = None
                        
                        # 查找 LocalVariableDeclaration 中的方法调用
                        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                            for declarator in stmt.declarators:
                                if not declarator.initializer:
                                    continue
                                init = declarator.initializer
                                if isinstance(init, javalang.tree.MethodInvocation):
                                    if init.member == current_method_name and init.arguments:
                                        call_expr = init
                        
                        # 查找 ReturnStatement 中的方法调用
                        elif isinstance(stmt, javalang.tree.ReturnStatement) and stmt.expression:
                            expr = stmt.expression
                            if isinstance(expr, javalang.tree.MethodInvocation):
                                if expr.member == current_method_name and expr.arguments:
                                    call_expr = expr
                        
                        # 查找 StatementExpression 中的方法调用（void 方法调用如 deserialize(data)）
                        elif isinstance(stmt, javalang.tree.StatementExpression) and stmt.expression:
                            expr = stmt.expression
                            if isinstance(expr, javalang.tree.MethodInvocation):
                                if expr.member == current_method_name and expr.arguments:
                                    call_expr = expr
                        
                        if call_expr is None:
                            continue
                        
                        # 找到调用！分析调用者方法的可控变量
                        request_vars = _find_request_var_names(caller_method)
                        
                        caller_source_lines = []
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                                caller_source_lines = f.readlines()
                        except Exception:
                            pass
                        
                        caller_controllable = _collect_controllable_vars(
                            caller_method, request_vars, source_lines=caller_source_lines)
                        
                        # 跨方法传播（含跨文件）
                        if global_methods:
                            _propagate_controllable_across_calls(
                                caller_method, ast_tree, caller_controllable, repair_functions,
                                global_methods=global_methods)
                        
                        # 如果调用者也没有可控变量，递归反向检查
                        if not caller_controllable and depth + 1 < max_depth:
                            reverse_params = _check_caller_controllability(
                                caller_method, ast_obj, repair_functions, 
                                global_methods=global_methods, depth=depth+1, max_depth=max_depth)
                            if reverse_params:
                                caller_controllable.update(reverse_params)
                        
                        # 检查调用参数是否可控
                        for arg in call_expr.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & caller_controllable:
                                for param in current_method.parameters:
                                    controllable_params.add(param.name)
                                    logger.debug("[AST][Java] Reverse cross-file (depth={}): param '{}' of {}() is controllable (called from {}:{})".format(
                                        depth, param.name, current_method_name, filepath,
                                        caller_method.position.line if caller_method.position else '?'))
                                # 写入缓存后提前返回
                                _trace_cache.put("__java_caller__", current_method.name, depth, controllable_params)
                                return controllable_params  # 已找到可控来源，提前返回
        except Exception:
            continue
    
    # 写入缓存
    if controllable_params:
        _trace_cache.put("__java_caller__", current_method.name, depth, controllable_params)
    
    return controllable_params


def _propagate_controllable_across_calls(method_node, tree, controllable, repair_functions, 
                                          max_depth=3, global_methods=None):
    """
    跨方法污点传播：分析方法体中的方法调用赋值，追踪可控变量传递
    
    支持同文件和跨文件方法查找。
    
    :param method_node: 当前方法 AST 节点
    :param tree: 整个文件的 AST 树（用于查找被调方法）
    :param controllable: 当前可控变量集合（会被原地修改）
    :param repair_functions: 修复函数列表
    :param max_depth: 传播递归深度上限
    :param global_methods: 跨文件全局方法映射 {(name, param_count): [(tree, node, path), ...]}
    """
    if not method_node.body:
        return

    # 构建同文件的方法映射
    class_methods = _build_class_method_map(tree)

    # 多轮传播，直到不再有新变量加入
    changed = True
    rounds = 0
    while changed and rounds < max_depth:
        changed = False
        rounds += 1

        for stmt in method_node.body:
            if not isinstance(stmt, javalang.tree.LocalVariableDeclaration):
                continue

            for declarator in stmt.declarators:
                if not declarator.initializer:
                    continue

                init = declarator.initializer
                target_var = declarator.name

                # 已经是可控的，跳过
                if target_var in controllable:
                    continue

                # 模式1: String x = someMethod(y) where y is controllable
                if isinstance(init, javalang.tree.MethodInvocation):
                    # 检查参数中是否有可控变量
                    call_args_controllable = False
                    if init.arguments:
                        for arg in init.arguments:
                            refs = _collect_member_references(arg)
                            if set(refs) & controllable:
                                call_args_controllable = True
                                break

                    if call_args_controllable:
                        called_method_name = init.member
                        call_arg_count = len(init.arguments) if init.arguments else 0
                        
                        # 1. 先在同文件中查找
                        found = False
                        if called_method_name in class_methods:
                            called_method = class_methods[called_method_name]
                            if called_method.parameters:
                                for arg in init.arguments:
                                    refs = _collect_member_references(arg)
                                    for ref in refs:
                                        if ref in controllable:
                                            if _is_passthrough_method(called_method, called_method.parameters[0].name,
                                                                     repair_functions, class_methods, 0, max_depth,
                                                                     global_methods=global_methods):
                                                controllable.add(target_var)
                                                logger.debug("[AST][Java] Cross-method propagation: {} → {} via {}()".format(
                                                    ref, target_var, called_method_name))
                                                changed = True
                                                found = True
                                                break
                                    if found:
                                        break

                        # 2. 同文件没找到，去全局映射中查找（跨文件传播）
                        if not found and global_methods:
                            key = (called_method_name, call_arg_count)
                            if key in global_methods:
                                for remote_tree, remote_method, remote_filepath in global_methods[key]:
                                    if remote_method.parameters:
                                        for arg in init.arguments:
                                            refs = _collect_member_references(arg)
                                            for ref in refs:
                                                if ref in controllable:
                                                    # 构建远程文件的方法映射（用于递归查找）
                                                    remote_class_methods = _build_class_method_map(remote_tree)
                                                    if _is_passthrough_method(remote_method, remote_method.parameters[0].name,
                                                                             repair_functions, remote_class_methods, 0, max_depth,
                                                                             global_methods=global_methods):
                                                        controllable.add(target_var)
                                                        logger.debug("[AST][Java] Cross-FILE propagation: {} → {} via {}() (from {})".format(
                                                            ref, target_var, called_method_name, remote_filepath))
                                                        changed = True
                                                        found = True
                                                        break
                                            if found:
                                                break
                                    if found:
                                        break

                # 模式2: String x = y + z (字符串拼接), 其中 y 或 z 可控
                elif isinstance(init, javalang.tree.BinaryOperation):
                    refs = _collect_member_references(init)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        logger.debug("[AST][Java] Propagation via concatenation: {} is controllable".format(target_var))
                        changed = True

                # 模式3: String x = (String) y (类型转换)
                elif isinstance(init, javalang.tree.Cast):
                    refs = _collect_member_references(init.expression)
                    if set(refs) & controllable:
                        controllable.add(target_var)
                        changed = True

                # 模式4: String x = y.toString() / String.valueOf(y)
                elif isinstance(init, javalang.tree.MethodInvocation):
                    if init.member in ('toString', 'valueOf', 'format', 'String'):
                        refs = []
                        if init.qualifier and isinstance(init.qualifier, str):
                            if init.qualifier in controllable:
                                controllable.add(target_var)
                                changed = True
                        if init.arguments:
                            for arg in init.arguments:
                                refs.extend(_collect_member_references(arg))
                        if set(refs) & controllable:
                            controllable.add(target_var)
                            changed = True


def _has_repair_function(expr, repair_functions):
    """检查表达式中是否调用了修复函数"""
    if expr is None or not repair_functions:
        return False

    if isinstance(expr, javalang.tree.MethodInvocation):
        if expr.member in repair_functions:
            return True
        # 检查 qualifier 是否是修复函数的返回值
        if isinstance(expr.qualifier, javalang.tree.MethodInvocation):
            if expr.qualifier.member in repair_functions:
                return True
        # 检查参数
        if expr.arguments:
            for arg in expr.arguments:
                if _has_repair_function(arg, repair_functions):
                    return True

    elif isinstance(expr, javalang.tree.BinaryOperation):
        return _has_repair_function(expr.operandl, repair_functions) or \
               _has_repair_function(expr.operandr, repair_functions)

    elif isinstance(expr, javalang.tree.Cast):
        return _has_repair_function(expr.expression, repair_functions)

    return False


def _analyze_call(sink_name, arguments, lineno, controllable, repair_functions, scan_chain,
                  qualifier=None, is_config_vuln=False):
    """分析敏感函数/构造函数的参数可控性，返回 result dict 或 None
    
    :param qualifier:...[truncated]
    """
    if not arguments:
        # 无参数方法：检查 qualifier 是否可控
        # 如 ois.readObject() → qualifier="ois" → 如果 ois 可控则返回 code=1
        if qualifier and isinstance(qualifier, str) and qualifier in controllable:
            logger.debug("[AST][Java] No-arg method with controllable qualifier: {}.{}()".format(
                qualifier, sink_name))
            return {
                "code": 1,
                "source": [qualifier],
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": qualifier,
                "sink_lineno": lineno,
                "chain": scan_chain + [qualifier, sink_name],
            }
        
        return {
            "code": 3,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": "",
            "sink_lineno": lineno,
            "chain": scan_chain + [sink_name],
        }

    # 提取参数中的所有变量引用
    param_var_refs = []
    literal_values = []
    for arg in arguments:
        refs = _collect_member_references(arg)
        param_var_refs.extend(refs)
        # 提取字面量参数值
        if isinstance(arg, javalang.tree.Literal):
            val = getattr(arg, 'value', None)
            if val is not None:
                literal_values.append(str(val))
    param_var_refs = list(set(param_var_refs))

    # 字面量/常量参数危险行为检测：当所有参数都不是用户可控变量时，
    # 检查是否构成危险配置。这类漏洞不依赖外部输入可控性。
    # 如 setAutoTypeSupport(true) / enableDefaultTyping(NON_FINAL)
    # 注意：仅对规则声明了 is_config_vuln=True 的 sink 生效，避免对普通 sink 误判
    if is_config_vuln:
        if not param_var_refs and literal_values:
            # 字面量参数包含 true — 不安全配置
            for lit in literal_values:
                if lit.lower() == 'true':
                    logger.debug("[AST][Java] Dangerous literal arg in {}: {}({}) — config vulnerability".format(
                        sink_name, sink_name, ', '.join(literal_values)))
                    return {
                        "code": 4,
                        "source": literal_values,
                        "source_lineno": lineno,
                        "sink": sink_name,
                        "sink_param:": str(literal_values),
                        "sink_lineno": lineno,
                        "chain": scan_chain + literal_values + [sink_name],
                    }
        # 枚举/常量参数但无可控变量：如 enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE)
        # param_var_refs 可能包含枚举常量名，但它们不在 controllable 中
        if param_var_refs and not (set(param_var_refs) & controllable):
            # 所有参数引用都不在可控变量集合中 → 固定配置调用
            # 提取参数文本描述
            arg_desc = param_var_refs + literal_values
            logger.debug("[AST][Java] Fixed-config call in {}: {}({}) — config vulnerability".format(
                sink_name, sink_name, ', '.join(arg_desc)))
            return {
                "code": 4,
                "source": arg_desc,
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": str(arg_desc),
                "sink_lineno": lineno,
                "chain": scan_chain + arg_desc + [sink_name],
            }

    # 检查是否有修复函数
    is_repaired = False
    for arg in arguments:
        if _has_repair_function(arg, repair_functions):
            is_repaired = True
            break

    if is_repaired:
        return {
            "code": 2,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + ["repaired", sink_name],
        }

    # 检查参数是否可控
    is_controllable = bool(set(param_var_refs) & controllable)
    if is_controllable:
        source_vars = list(set(param_var_refs) & controllable)
        logger.debug("[AST][Java] Param controllable! vars={} -> {}".format(
            source_vars, sink_name))
        return {
            "code": 1,
            "source": source_vars,
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + source_vars + [sink_name],
        }
    else:
        # 参数不可控，但 qualifier 可控时也报告（对象本身携带可控数据）
        if qualifier and isinstance(qualifier, str) and qualifier in controllable:
            logger.debug("[AST][Java] Param not controllable but qualifier is: {}.{}()".format(
                qualifier, sink_name))
            return {
                "code": 1,
                "source": [qualifier],
                "source_lineno": lineno,
                "sink": sink_name,
                "sink_param:": qualifier,
                "sink_lineno": lineno,
                "chain": scan_chain + [qualifier, sink_name],
            }

        logger.debug("[AST][Java] Param not clearly controllable: {}".format(param_var_refs))
        return {
            "code": 3,
            "source": [],
            "source_lineno": lineno,
            "sink": sink_name,
            "sink_param:": str(param_var_refs),
            "sink_lineno": lineno,
            "chain": scan_chain + [sink_name],
        }


def _find_class_creators_in_body(method_node, target_line, sensitive_func):
    """在方法体中查找匹配的 ClassCreator 节点及其行号"""
    results = []
    if not method_node.body:
        return results
    target = int(target_line)
    for stmt in method_node.body:
        stmt_line = stmt.position.line if stmt.position else 0
        if stmt_line != target:
            continue
        # 从语句中提取 ClassCreator
        if isinstance(stmt, javalang.tree.LocalVariableDeclaration):
            for declarator in stmt.declarators:
                if isinstance(declarator.initializer, javalang.tree.ClassCreator):
                    creator = declarator.initializer
                    type_name = creator.type.name if creator.type else ""
                    if type_name in sensitive_func:
                        results.append((type_name, creator.arguments, stmt_line))
        elif isinstance(stmt, javalang.tree.ReturnStatement):
            if isinstance(stmt.expression, javalang.tree.ClassCreator):
                creator = stmt.expression
                type_name = creator.type.name if creator.type else ""
                if type_name in sensitive_func:
                    results.append((type_name, creator.arguments, stmt_line))
        elif isinstance(stmt, javalang.tree.StatementExpression):
            expr = stmt.expression
            # 直接 new SomeClass(...) 调用（如 new FileInputStream(filename);）
            if isinstance(expr, javalang.tree.ClassCreator):
                creator = expr
                type_name = creator.type.name if creator.type else ""
                if type_name in sensitive_func:
                    results.append((type_name, creator.arguments, stmt_line))
            # 赋值: x = new SomeClass(...)
            elif isinstance(expr, javalang.tree.Assignment):
                if isinstance(expr.value, javalang.tree.ClassCreator):
                    creator = expr.value
                    type_name = creator.type.name if creator.type else ""
                    if type_name in sensitive_func:
                        results.append((type_name, creator.arguments, stmt_line))
    return results


def _build_result(code, scan_chain, cp, source_lines, lineno, file_path,
                   controlled_params, repair_functions, is_config_vuln=False):
    """构建 scan_results 中的单条结果 dict"""
    source_desc = cp if cp else ''
    # 从 source_lines 取 source 行号
    source_lineno = 0
    if source_lines and isinstance(source_desc, str):
        for i, line in enumerate(source_lines):
            if source_desc in line:
                source_lineno = i + 1
                break
    return {
        "code": code,
        "source": [source_desc],
        "source_lineno": source_lineno,
        "sink": '',
        "sink_param:": source_desc,
        "sink_lineno": lineno,
        "chain": scan_chain + [source_desc],
    }


def find_sinks(sink_names, files):
    """
    AST-based sink 查找。遍历所有文件的 AST 节点，查找匹配的函数调用。
    支持直接调用匹配（Java 反射间接调用暂不处理）。

    :param sink_names: list of SinkName(class_, method) from parse_sink_names()
    :param files: 文件路径列表
    :return: list of dict
    """
    from core.utils import SinkName

    results = []

    for file_path in files:
        file_path = _ast_object_singleton.get_path(file_path)
        if not file_path:
            continue
        _nodes = _ast_object_singleton.get_nodes(file_path)
        if not _nodes:
            continue

        # === 第一遍遍历：收集方法引用赋值映射（间接调用） ===
        assignment_map = {}  # 变量名 -> 原始方法名
        try:
            for mref_path, mref_node in _nodes.filter(javalang.tree.MethodReference):
                method_name = mref_node.method.member if hasattr(mref_node.method, 'member') else str(mref_node.method)
                # 查找赋值目标：向上搜索 path 中的 LocalVariableDeclaration
                for ancestor in reversed(mref_path):
                    if isinstance(ancestor, javalang.tree.LocalVariableDeclaration):
                        var_name = ancestor.declarators[0].name
                        assignment_map[var_name] = method_name
                        break

            # 多层间接调用：收集变量到变量的赋值链
            # rt2 = rt → assignment_map['rt2'] = assignment_map.get('rt')
            try:
                for lvd_path, lvd_node in _nodes.filter(javalang.tree.LocalVariableDeclaration):
                    for decl in (lvd_node.declarators or []):
                        if hasattr(decl, 'name') and hasattr(decl, 'initializer') and decl.initializer:
                            init = decl.initializer
                            # init 是 MemberReference 时, member 可能是已有映射的变量名
                            if isinstance(init, javalang.tree.MemberReference):
                                inner_name = init.member
                                if inner_name in assignment_map:
                                    assignment_map[decl.name] = assignment_map[inner_name]
                            # init 是字符串变量名
                            elif isinstance(init, str) and init in assignment_map:
                                assignment_map[decl.name] = assignment_map[init]
            except Exception as e:
                logger.warning('[AST][Java] find_sinks indirect assignment analysis error: {}'.format(e))
        except Exception:
            pass

        # 使用 javalang 的 filter 遍历 MethodInvocation
        try:
            for path, node in _nodes.filter(javalang.tree.MethodInvocation):
                qualifier = node.qualifier or ''
                method_name = node.member
                full_name = '{}.{}'.format(qualifier, method_name) if qualifier else method_name

                for sink in sink_names:
                    if sink.class_ is None:
                        # 模糊匹配：method_name 或 full_name 以 .method 结尾
                        if method_name == sink.method or full_name == sink.method or full_name.endswith('.' + sink.method):
                            lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': full_name,
                                'class_name': qualifier if qualifier else None,
                                'matched_sink': sink,
                            })
                            break
                    else:
                        # 精确匹配：qualifier.method == class_.method
                        if full_name == '{}.{}'.format(sink.class_, sink.method):
                            lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': full_name,
                                'class_name': sink.class_,
                                'matched_sink': sink,
                            })
                            break

            # 搜索 ClassCreator（构造函数调用，如 new ProcessBuilder()）
            for path, node in _nodes.filter(javalang.tree.ClassCreator):
                type_name = node.type.name if node.type and hasattr(node.type, 'name') else ''
                if not type_name:
                    continue

                for sink in sink_names:
                    if sink.class_ is None:
                        if type_name == sink.method:
                            lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': type_name,
                                'class_name': None,
                                'matched_sink': sink,
                            })
                            break
                    else:
                        if type_name == sink.class_ and sink.method == sink.class_:
                            lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': type_name,
                                'class_name': sink.class_,
                                'matched_sink': sink,
                            })
                            break

            # === 间接调用匹配：检查 qualifier 是否是赋值了方法引用的变量 ===
            try:
                for path, node in _nodes.filter(javalang.tree.MethodInvocation):
                    qualifier = node.qualifier or ''
                    # qualifier 可能是字符串（如 'execFunc'）或 MemberReference 对象
                    callee_var = None
                    if isinstance(qualifier, str) and qualifier in assignment_map:
                        callee_var = qualifier
                    elif hasattr(qualifier, 'member') and qualifier.member in assignment_map:
                        callee_var = qualifier.member
                    if callee_var:
                        real_method = assignment_map[callee_var]
                        for sink in sink_names:
                            if real_method == sink.method:
                                lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
                                results.append({
                                    'file_path': file_path,
                                    'lineno': lineno,
                                    'node': node,
                                    'is_indirect': True,
                                    'callee_name': callee_var,
                                    'class_name': None,
                                    'matched_sink': sink,
                                })
                                break
            except Exception as e:
                logger.warning('[AST][Java] find_sinks indirect call analysis error: {}'.format(e))
        except Exception as e:
            logger.warning('[AST][Java] find_sinks file-level error in {}: {}'.format(file_path, e))
            continue

    return results


def _handle_java_indirect_call(_nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path):
    """
    处理 Java 间接调用场景：在 AST 中定位 vul_lineno 处的 MethodInvocation 节点，
    用 indirect_map 确认是间接调用后，提取参数做可控性分析。

    :param _nodes: javalang CompilationUnit AST nodes
    :param vul_lineno: 漏洞行号
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param file_path: 文件路径
    :return: list[dict] 或 None
    """
    global scan_results

    target_line = int(vul_lineno)
    target_node = None
    callee_variable = None

    for path, node in _nodes.filter(javalang.tree.MethodInvocation):
        lineno = node.position[0] if hasattr(node, 'position') and node.position else 0
        if lineno != target_line:
            continue
        # 检查 qualifier 是否在 indirect_map 中（qualifier 可能是字符串或 MemberReference）
        qualifier = node.qualifier or ''
        callee_var = None
        if isinstance(qualifier, str) and qualifier in indirect_map:
            callee_var = qualifier
        elif hasattr(qualifier, 'member') and qualifier.member in indirect_map:
            callee_var = qualifier.member
        if callee_var:
            target_node = node
            callee_variable = callee_var
            break

    if target_node is None:
        return None

    # 提取参数做反向追踪可控性分析
    # 读取源码用于 _build_result
    source_lines = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            source_lines = f.readlines()
    except Exception:
        pass

    # 找到包含目标行的方法
    method = _find_method_at_line(_nodes, target_line)
    if not method or not method.body:
        return None

    method_stmts = list(method.body)

    # 获取方法参数列表
    method_params = []
    method_name = method.name if hasattr(method, 'name') else ''
    if hasattr(method, 'parameters') and method.parameters:
        method_params = [p.name for p in method.parameters]

    # 获取类名
    class_name = ''
    if hasattr(_nodes, 'types') and _nodes.types:
        for type_decl in _nodes.types:
            if hasattr(type_decl, 'body') and type_decl.body:
                for member in type_decl.body:
                    if member is method:
                        class_name = type_decl.name
                        break
            if class_name:
                break

    lineno = target_line

    # 对每个参数进行反向追踪
    for arg in (target_node.arguments or []):
        arg_name = _get_var_name(arg) or _expr_to_str_java(arg)
        if not arg_name:
            continue

        code, cp, expr_lineno = parameters_back(
            arg_name, method_stmts, lineno, file_path,
            repair_functions, controlled_params,
            method_params=method_params, method_name=method_name, class_name=class_name
        )

        if code == 1:
            scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                             lineno, file_path, controlled_params,
                             repair_functions, is_config_vuln=False))
            return scan_results
        elif code == 2:
            scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                             lineno, file_path, controlled_params,
                             repair_functions, is_config_vuln=False))
            return scan_results
        elif code == 5:
            # 封装函数，参数来自形参 → 交给 NewCore 二次扫描
            wrapper_func = cp
            scan_results.append({
                'code': 5,
                'source': (wrapper_func, arg_name, callee_variable),
                'chain': [
                    ('NewFunction', wrapper_func, file_path, method.position.line if hasattr(method, 'position') and method.position else 0),
                    ('sink', callee_variable, file_path, lineno)
                ]
            })
            return scan_results

    # === Fallback: parameters_back 无法判断时，做启发式分析 ===
    # 如果有任何参数不是字面量（Literal/MemberReference 为简单变量引用），
    # 视为可能可控，标记为 code=5 交给 NewCore 二次扫描
    for arg in (target_node.arguments or []):
        if isinstance(arg, javalang.tree.Literal):
            continue
        arg_name = _get_var_name(arg) or _expr_to_str_java(arg)
        if arg_name:
            scan_results.append({
                'code': 1,
                'source': ('Function-param-controllable', arg_name),
                'chain': [
                    ('NewFunction', method_name, file_path, method.position.line if hasattr(method, 'position') and method.position else 0),
                    ('sink', callee_variable, file_path, lineno)
                ]
            })
            return scan_results

    return None


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], is_config_vuln=False, indirect_map=None):
    """
    Java AST scan parser - 反向追踪模式
    从 grep 匹配到的 sink 参数反向追踪数据流，直到碰到 source。
    与 Go/Python/PHP/JS 引擎保持一致的反向追踪模式。
    
    :param sensitive_func: 要检测的敏感函数列表，如 ["executeQuery", "exec"]
    :param vul_lineno: 漏洞函数所在行号（字符串或整数）
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表，如 ["PreparedStatement"]
    :param controlled_params: 可控参数列表
    :param is_config_vuln: 是否是配置类漏洞
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :return: scan_results 列表，每个元素是 {"code": N, "chain": [...], ...}
    """
    global scan_results, is_repair_functions, is_controlled_params, scan_chain
    global _summaries_initialized, _scan_function_stack

    # 清空缓存和状态
    _trace_cache.clear()
    _summaries_initialized = False
    _scan_function_stack = []

    try:
        scan_chain = ["start"]
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params

        if _ast_object_singleton is None:
            logger.debug("[AST][Java] ast_object is None, skip")
            return scan_results

        _nodes = _ast_object_singleton.get_nodes(file_path)

        if not _nodes:
            logger.debug("[AST][Java] No AST nodes for {}".format(file_path))
            return scan_results

        target_line = int(vul_lineno)

        # 初始化函数摘要
        _init_function_summaries(file_path)

        # 间接调用快速路径
        if indirect_map and isinstance(indirect_map, dict):
            indirect_result = _handle_java_indirect_call(
                _nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path
            )
            if indirect_result:
                return indirect_result

        # === Source Discovery 初始化 ===
        global _source_registry
        if _source_registry is None:
            target_dir = os.path.dirname(os.path.abspath(file_path))
            try:
                _source_registry = discover_sources(target_dir, _nodes, file_path, controlled_list=controlled_params)
                if _source_registry.source_members or _source_registry.annotated_param_names:
                    extra_sources = _source_registry.get_all_source_names()
                    controlled_params = list(controlled_params) + extra_sources
                    logger.debug('[AST][Java] Source Discovery injected {} sources'.format(
                        len(extra_sources)))
            except Exception as e:
                logger.debug('[AST][Java] Source Discovery init error: {}'.format(e))

        # 1. 找到包含目标行号的方法
        method = _find_method_at_line(_nodes, target_line)
        if not method:
            logger.debug("[AST][Java] No method found at line {}".format(target_line))
            return scan_results

        # 获取方法所在的类名（用于 code=5 返回限定函数名）
        class_name = ''
        if hasattr(_nodes, 'types') and _nodes.types:
            for type_decl in _nodes.types:
                if hasattr(type_decl, 'body') and type_decl.body:
                    for member in type_decl.body:
                        if member is method:
                            class_name = type_decl.name
                            break
                if class_name:
                    break

        if not method.body:
            return scan_results

        # 读取源码（用于文本 fallback）
        source_lines = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source_lines = f.readlines()
        except Exception:
            pass

        # 获取方法体语句
        method_stmts = list(method.body)

        # 获取方法形参列表（用于 code=5 判断）
        method_params = []
        method_name = method.name if hasattr(method, 'name') else ''
        if hasattr(method, 'parameters') and method.parameters:
            method_params = [p.name for p in method.parameters]

        # 2. 在方法体中找 sink 调用并反向追踪
        # 2a. 搜索 MethodInvocation
        found = False
        for path, node in _nodes.filter(javalang.tree.MethodInvocation):
            if found:
                break
            for mi in _flatten_chained_calls(node):
                if not isinstance(mi, javalang.tree.MethodInvocation):
                    continue
                if mi.member not in sensitive_func:
                    continue

                lineno = mi.position.line if hasattr(mi, 'position') and mi.position else target_line
                if lineno != target_line:
                    continue

                logger.debug("[AST][Java] Found sensitive call: {}() at line {}".format(mi.member, lineno))

                # 对每个参数进行反向追踪
                for arg in (mi.arguments or []):
                    arg_name = _get_var_name(arg) or _expr_to_str_java(arg)
                    if not arg_name:
                        continue

                    code, cp, expr_lineno = parameters_back(
                        arg_name, method_stmts, lineno, file_path,
                        repair_functions, controlled_params,
                        method_params=method_params, method_name=method_name, class_name=class_name
                    )
                    logger.debug("[AST][Java] parameters_back('{}') => code={}, cp={}".format(
                        arg_name, code, cp))

                    if code == -1:
                        # 分支约束阻断：参数不可控
                        scan_results.append({"code": -1, "chain": scan_chain})
                        found = True
                        break
                    elif code == 5:
                        # 封装函数，参数来自形参 → 交给 NewCore 二次扫描
                        wrapper_func = cp  # method_name
                        scan_results.append({
                            'code': 5,
                            'source': (wrapper_func, arg_name, mi.member),
                            'chain': [
                                ('NewFunction', wrapper_func, file_path, method.position.line if hasattr(method, 'position') and method.position else 0),
                                ('sink', mi.member, file_path, lineno)
                            ]
                        })
                        found = True
                        break
                    elif code == 1:
                        scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                         lineno, file_path, controlled_params,
                                         repair_functions, is_config_vuln))
                        found = True
                        break
                    elif code == 2:
                        scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                         lineno, file_path, controlled_params,
                                         repair_functions, is_config_vuln))
                        found = True
                        break
                    elif code == 'deps' and cp:
                        # 依赖调用者变量
                        for dep_name in (cp if isinstance(cp, list) else [cp]):
                            scan_results.append(_build_result(1, scan_chain, dep_name, source_lines,
                                             lineno, file_path, controlled_params,
                                             repair_functions, is_config_vuln))
                            found = True
                            break
                if found:
                    break

        # 2b. 搜索 ClassCreator（构造函数调用）
        if not found:
            creators = _find_class_creators_in_body(method, target_line, sensitive_func)
            for type_name, arguments, lineno in creators:
                logger.debug("[AST][Java] Found sensitive constructor: new {}() at line {}".format(
                    type_name, lineno))
                for arg in (arguments or []):
                    if isinstance(arg, str):
                        arg_name = arg
                    else:
                        arg_name = _get_var_name(arg) or str(arg)
                    if not arg_name:
                        continue

                    code, cp, expr_lineno = parameters_back(
                        arg_name, method_stmts, lineno, file_path,
                        repair_functions, controlled_params,
                        method_params=method_params, method_name=method_name, class_name=class_name
                    )

                    if code == -1:
                        scan_results.append({"code": -1, "chain": scan_chain})
                        found = True
                        break
                    elif code == 5:
                        # 封装函数，参数来自形参 → 交给 NewCore 二次扫描
                        wrapper_func = cp  # method_name
                        scan_results.append({
                            'code': 5,
                            'source': (wrapper_func, arg_name, type_name),
                            'chain': [
                                ('NewFunction', wrapper_func, file_path, method.position.line if hasattr(method, 'position') and method.position else 0),
                                ('sink', type_name, file_path, lineno)
                            ]
                        })
                        found = True
                        break
                    elif code == 1:
                        scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                         lineno, file_path, controlled_params,
                                         repair_functions, is_config_vuln))
                        found = True
                        break
                    elif code == 2:
                        scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                         lineno, file_path, controlled_params,
                                         repair_functions, is_config_vuln))
                        found = True
                        break
                if found:
                    break

        # 2c. 源码文本 fallback：javalang 链式调用 bug 导致 AST 丢失 sink 时
        if not found and source_lines:
            for line_offset in range(0, 15):
                check_line = target_line + line_offset
                if check_line > len(source_lines):
                    break
                source_line = source_lines[check_line - 1]
                for func_name in sensitive_func:
                    pattern = r'(?<!\w)' + re.escape(func_name) + r'\s*\('
                    if re.search(pattern, source_line):
                        arg_match = re.search(
                            re.escape(func_name) + r'\s*\(\s*([^,)]+)', source_line)
                        arg_name = arg_match.group(1).strip() if arg_match else ''
                        logger.debug(
                            "[AST][Java] Source-text fallback: {}() at line {} [arg={}]".format(
                                func_name, check_line, arg_name))

                        code, cp, expr_lineno = parameters_back(
                            arg_name, method_stmts, check_line, file_path,
                            repair_functions, controlled_params,
                            method_params=method_params, method_name=method_name, class_name=class_name
                        )

                        if code == 5:
                            # 封装函数，参数来自形参 → 交给 NewCore 二次扫描
                            wrapper_func = cp  # method_name
                            scan_results.append({
                                'code': 5,
                                'source': (wrapper_func, arg_name, func_name),
                                'chain': [
                                    ('NewFunction', wrapper_func, file_path, method.position.line if hasattr(method, 'position') and method.position else 0),
                                    ('sink', func_name, file_path, check_line)
                                ]
                            })
                            found = True
                            break
                        elif code == 1:
                            scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                             check_line, file_path, controlled_params,
                                             repair_functions, is_config_vuln))
                            found = True
                            break
                        elif code == 2:
                            scan_results.append(_build_result(code, scan_chain, cp, source_lines,
                                             check_line, file_path, controlled_params,
                                             repair_functions, is_config_vuln))
                            found = True
                            break
                if found:
                    break

    except javalang.parser.JavaSyntaxError:
        logger.warning("[AST][Java] Syntax error parsing {}".format(file_path))
    except Exception:
        logger.warning("[AST][Java] Error: {}".format(traceback.format_exc()))

    return scan_results
