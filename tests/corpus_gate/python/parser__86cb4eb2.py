# -*- coding: utf-8 -*-

"""
    parser
    ~~~~~~

    Implements Code Parser

    :author:    BlBana <635373043@qq.com>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
from phply import phpast as php
import re
import os
import asyncio
import traceback
# from asgiref.sync import sync_to_async, async_to_sync

from utils.log import logger
from utils.status import SCAN_ID

from core.pretreatment import ast_object
from core.core_engine.php.builtin_knowledge import KNOWLEDGE as PHP_BUILTIN_KNOWLEDGE
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.php.summary_generator import lookup_summary
from core.core_engine.php.source_discovery import SourceRegistry, discover_sources, extract_method_object_name, get_simple_name

# lphply >= 2.0.0 新增的等价节点类型（字段与原类型完全一致）
_METHOD_CALL_TYPES = (php.MethodCall, getattr(php, 'NullsafeMethodCall', php.MethodCall))
_OBJECT_PROPERTY_TYPES = (php.ObjectProperty, getattr(php, 'NullsafeProperty', php.ObjectProperty))
_FUNCTION_CALL_TYPES = (php.FunctionCall, php.MethodCall, php.StaticMethodCall,
                        getattr(php, 'NullsafeMethodCall', php.MethodCall))

from web.index.models import NewEvilFunc

with_line = True
scan_results = []  # 结果存放列表初始化
is_repair_functions = []  # 修复函数初始化
is_controlled_params = []
scan_chain = []  # 回溯链变量
scan_function_stack = []  # 函数回溯栈，用于避免 A->B->A 这类互相递归导致的无限回溯
_trace_cache = TraceCache("php")
_summaries_initialized = False
_file_summaries = {}
all_nodes = []
_source_registry = None  # Source Discovery 注册表，在 scan_parser 首次调用时初始化
BASE_FUNCTIONCALL_LIST = ['FunctionCall', 'MethodCall', 'StaticMethodCall', 'ObjectProperty', 'NullsafeMethodCall', 'NullsafeProperty']
SPECIAL_FUNCTIONCALL_LIST = ['Eval', 'Echo', 'Print', 'Return', 'Break', 'Include',
                         'Require', 'Exit', 'Throw', 'Unset', 'Continue', 'Yield', 'Silence']

FUNCTIONCALL_LIST = BASE_FUNCTIONCALL_LIST + SPECIAL_FUNCTIONCALL_LIST
# 针对部分函数仅分析特定参数，避免盲目分析全部参数导致误报
# 下标从 0 开始
FUNCTIONCALL_PARAM_WHITELIST = {
    'array_map': [0],
}


def export(items):
    result = []
    if items:
        for item in items:
            if hasattr(item, 'generic'):
                item = item.generic(with_lineno=with_line)
            result.append(item)
    return result


def trim(params):
    result = []

    for param in params:
        if param:
            result.append(param)

    return result


def export_list(params, export_params):
    """
    将params中嵌套的多个列表，导出为一个列表
    :param params:
    :param export_params:
    :return:
    """
    for param in params:
        if isinstance(param, list):
            export_params = export_list(param, export_params)

        else:
            export_params.append(param)

    return export_params


def get_all_params(nodes):  # 用来获取调用函数的参数列表，nodes为参数列表
    """
    获取函数结构的所有参数
    :param nodes:
    :return:
    """
    params = []
    export_params = []  # 定义空列表，用来给export_list中使用
    for node in nodes:
        if isinstance(node.node, php.FunctionCall):  # 函数参数来自另一个函数的返回值
            params = get_all_params(node.node.params)

        else:
            if isinstance(node.node, php.Variable):
                params.append(node.node.name)

            if isinstance(node.node, php.BinaryOp):
                params = get_binaryop_params(node.node)
                params = export_list(params, export_params)

            if isinstance(node.node, php.ArrayOffset):
                param = get_node_name(node.node.node)
                params.append(param)

            if isinstance(node.node, php.Cast):
                param = get_cast_params(node.node.expr)
                params.append(param)

            if isinstance(node.node, php.Silence):
                param = get_silence_params(node.node)
                params.append(param)

    return params


def get_functioncall_params_by_index(node):
    """
    根据函数名选择需要参与回溯的参数。
    默认返回全部参数；命中白名单时仅返回指定下标对应参数。
    """
    function_name = get_node_name(node)
    raw_params = node.params

    if function_name in FUNCTIONCALL_PARAM_WHITELIST:
        selected_params = []
        for index in FUNCTIONCALL_PARAM_WHITELIST[function_name]:
            if 0 <= index < len(raw_params):
                selected_params.append(raw_params[index])
        return selected_params

    return raw_params


def get_all_functioncall_params(node):
    """
    获取特殊类型的函数调用参数
    :param node:
    :return:
    """
    node_typename = node.__class__.__name__
    return_params = []

    if node_typename in SPECIAL_FUNCTIONCALL_LIST:
        if node_typename in ['Empty', 'Eval', 'Include', 'Require', 'Exit', 'Silence']:
            return_params.append(node.expr)

        elif node_typename in ['Echo', 'Unset', 'IsSet']:
            for p in node.nodes:
                return_params.append(p)
        else:
            return_params.append(node.node)

    elif node_typename in BASE_FUNCTIONCALL_LIST:
        for p in node.params:
            return_params.append(p.node)

    return return_params


def get_silence_params(node):
    """
    用来提取Silence类型中的参数
    :param node:
    :return:
    """
    param = []
    if isinstance(node.expr, php.Variable):
        param = get_node_name(node.expr)

    if isinstance(node.expr, php.FunctionCall):
        param.append(node.expr)

    if isinstance(node.expr, php.Eval):
        param.append(node.expr)

    if isinstance(node.expr, php.Assignment):
        param.append(node.expr)

    return param


def get_cast_params(node):
    """
    用来提取Cast类型中的参数
    :param node:
    :return:
    """
    param = []
    if isinstance(node, php.Silence):
        param = get_node_name(node.expr)

    return param


def get_binaryop_params(node, real_back=False):  # 当为BinaryOp类型时，分别对left和right进行处理，取出需要的变量
    """
    用来提取Binaryop中的参数
    :param real_back: 
    :param node:
    :return:           
    """
    # logger.debug('[AST] Binaryop --> {node}'.format(node=node))
    params = []
    buffer_ = []

    if isinstance(node.left, php.Variable):
        if real_back:
            params.append(node.left)
        else:
            params.append(node.left.name)
    else:
        params = get_binaryop_deep_params(node.left, params, real_back)

    if isinstance(node.right, php.Variable):
        if real_back:
            params.append(node.right)
        else:
            params.append(node.right.name)
    else:
        params = get_binaryop_deep_params(node.right, params, real_back)

    params = export_list(params, buffer_)
    return params


def get_binaryop_deep_params(node, params, real_back=False):  # 取出right，left不为变量时，对象结构中的变量
    """
    取出深层的变量名
    :param real_back: 
    :param node: node为上一步中的node.left或者node.right节点
    :param params:
    :return:
    """
    if isinstance(node, php.ArrayOffset):  # node为数组，取出数组变量名
        param = get_node_name(node.node)
        params.append(param)

    if isinstance(node, php.BinaryOp):  # node为BinaryOp，递归取出其中变量
        param = get_binaryop_params(node, real_back=real_back)
        params.append(param)

    if isinstance(node, php.FunctionCall):  # node为FunctionCall，递归取出其中变量名
        params = get_all_params(node.params)

    if isinstance(node, _METHOD_CALL_TYPES):  # 方法调用（$obj->method()），递归提取参数
        params = get_all_params(node.params)

    if isinstance(node, php.StaticMethodCall):  # 静态方法调用（Class::method()），递归提取参数
        params = get_all_params(node.params)

    if isinstance(node, _OBJECT_PROPERTY_TYPES):  # 对象属性（$obj->prop），提取对象变量名
        param = get_node_name(node.node)
        params.append(param)

    if isinstance(node, php.Constant):
        params.append(node)

    if type(node) is str:
        params.append(node)

    return params


def get_array_name(nodes):
    """
    获取字典、数组元素
    :param nodes:
    :return:
    """
    params = []

    for node in nodes:
        value = get_node_name(node)

        if type(value) is list:
            params.extend(trim(value))
        else:
            params.append(value)

    return params


def get_expr_name(node):  # expr为'expr'中的值
    """
    获取赋值表达式的表达式部分中的参数名-->返回用来进行回溯
    :param node:
    :return:
    """
    param_lineno = 0
    is_re = False
    if isinstance(node, php.ArrayOffset):  # 当赋值表达式为数组
        param_expr = get_node_name(node.node)  # 返回数组名
        param_lineno = node.node.lineno

    elif isinstance(node, php.Array):  # 当赋值表达式为字典
        param_expr = get_array_name(node.nodes)  # 返回数组名
        param_lineno = node.lineno

    elif isinstance(node, php.Variable):  # 当赋值表达式为变量
        param_expr = node.name  # 返回变量名
        param_lineno = node.lineno

    elif isinstance(node, php.FunctionCall):  # 当赋值表达式为函数
        param_expr = get_all_params(node.params)  # 返回函数参数列表
        param_lineno = node.lineno
        is_re = is_repair(node.name)  # 调用了函数，判断调用的函数是否为修复函数

    elif isinstance(node, php.BinaryOp):  # 当赋值表达式为BinaryOp
        param_expr = get_binaryop_params(node)
        param_lineno = node.lineno

    elif isinstance(node, _METHOD_CALL_TYPES):  # 当赋值表达式为类方法时
        param_expr = get_all_params(node.params)  # 返回该方法参数列表
        param_lineno = node.lineno

    elif isinstance(node, php.ArrayElement):  # 字典的键值对
        params = []
        params.append(get_node_name(node.key))
        params.append(get_node_name(node.value))

        param_expr = params
        param_lineno = node.lineno
    else:
        param_expr = node

    return param_expr, param_lineno, is_re


def get_node_name(node):  # node为'node'中的元组
    """
    获取Variable类型节点的name
    :param node:
    :return:
    """
    if isinstance(node, php.Variable):
        return node.name  # 返回此节点中的变量名

    if isinstance(node, _METHOD_CALL_TYPES) or isinstance(node, php.FunctionCall):
        return node.name

    if isinstance(node, _OBJECT_PROPERTY_TYPES):
        return node

    if isinstance(node, php.ArrayOffset):
        return get_node_name(node.node)

    if isinstance(node, php.ArrayElement):  # 字典的键值对
        params = []
        params.append(get_node_name(node.key))
        params.append(get_node_name(node.value))

        param_expr = params
        return param_expr

    return node


def is_same_array_index(left_index, right_index):
    """
    判断两个数组下标节点是否指向同一 key。
    这里只做保守匹配：名称/字面量一致才视为同一 key。
    """
    left_name = get_node_name(left_index)
    right_name = get_node_name(right_index)
    return left_name == right_name


def build_ast_param(param_expr):
    """
    将表达式构造成可继续回溯的参数节点。
    仅将字符串变量名（以 $ 开头）转换为 php.Variable，
    其余字面量字符串与 AST 节点保持原样，避免把常量字符串误当变量。
    """
    if isinstance(param_expr, str) and param_expr.startswith('$'):
        return php.Variable(param_expr)
    return param_expr


def get_filename(node, file_path):  # 获取filename
    """
    获取
    :param node: 
    :param file_path: 
    :return: 
    """
    filename = node.expr
    filenames = []
    if isinstance(filename, php.BinaryOp):
        filenames = get_binaryop_params(filename)

    elif type(filename) is str:
        filenames = [filename]

    for i in range(len(filenames)):
        if isinstance(filenames[i], php.Constant):
            constant_node = filenames[i]
            constant_node_name = constant_node.name

            # 尝试做一些处理针对右值非常量的问题
            define_value = ast_object.get_define(constant_node_name)

            # define 右值可能不是纯字符串，例如 BinaryOp('.', $prefix, 'users')。
            # 将其尽可能展开为字符串片段列表，避免后续 join 时出现类型错误。
            if isinstance(define_value, php.BinaryOp):
                filenames[i] = get_binaryop_params(define_value)
            elif isinstance(define_value, php.Variable):
                filenames[i] = define_value.name
            elif isinstance(define_value, php.Constant):
                nested_define = ast_object.get_define(define_value.name)
                if isinstance(nested_define, php.BinaryOp):
                    filenames[i] = get_binaryop_params(nested_define)
                elif isinstance(nested_define, php.Variable):
                    filenames[i] = nested_define.name
                else:
                    filenames[i] = nested_define
            else:
                filenames[i] = define_value

    return export_list(filenames, [])


def is_repair(expr):
    """
    判断赋值表达式是否出现过滤函数，如果已经过滤，停止污点回溯，判定漏洞已修复
    :param expr: 赋值表达式
    :return:
    """
    is_re = False  # 是否修复，默认值是未修复
    global is_repair_functions

    if expr in is_repair_functions:
        logger.debug("[AST] function {} in is_repair_functions, The vulnerability does not exist ".format(expr))
        is_re = True
    return is_re


def is_sink_function(param_expr, function_params):
    """
    判断自定义函数的入参-->判断此函数是否是危险函数
    :param param_expr:
    :param function_params:
    :return:
    """
    is_co = -1
    cp = None
    if function_params is not None:
        for function_param in function_params:
            if param_expr == function_param:
                is_co = 2
                cp = function_param
                logger.debug('[AST] is_sink_function --> {function_param}'.format(function_param=cp))
    return is_co, cp


def is_controllable(expr, flag=None):  # 获取表达式中的变量，看是否在用户可控变量列表中
    """
    判断赋值表达式是否是用户可控的
    :param expr:
    :return:
    """
    controlled_params = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_FILES',
        # '$_SERVER', # 暂时去掉了，误报率太高了
        '$HTTP_POST_FILES',
        '$HTTP_COOKIE_VARS',
        '$HTTP_REQUEST_VARS',
        '$HTTP_POST_VARS',
        '$HTTP_RAW_POST_DATA',
        '$HTTP_GET_VARS'
    ]

    # 传入合并
    controlled_params += is_controlled_params

    if isinstance(expr, php.ArrayOffset):
        array_name = get_node_name(expr.node)

        if array_name in controlled_params:
            # $_FILES special case: 'tmp_name' and 'error' are server-generated,
            # not user-controlled. Only 'name', 'type', 'size' are attacker-controlled.
            if array_name in ('$_FILES', '$HTTP_POST_FILES'):
                dim_key = get_node_name(expr.expr)
                dim_key_str = str(dim_key).strip("'\"") if dim_key else ''
                if dim_key_str in ('tmp_name', 'error'):
                    logger.debug('[AST] $_FILES dim {} is server-generated, not controllable'.format(dim_key_str))
                    return -1, php.Variable(array_name)
            logger.debug('[AST] is_controllable --> {expr}'.format(expr=array_name))
            if flag:
                return 1, array_name
            return 1, php.Variable(array_name)

    if isinstance(expr, _OBJECT_PROPERTY_TYPES):
        return 3, expr

    if isinstance(expr, php.New) or isinstance(expr, _FUNCTION_CALL_TYPES):
        # 一个新的问题，输入可能不来自全局变量，可能来自函数，加入一次check

        # check is_repair
        if is_repair(expr.name):
            return 2, expr

        if expr.name in is_controlled_params:
            logger.debug('[AST] is_controllable --> {expr}'.format(expr=expr.name))
            return 1, expr

        return 3, expr

    if isinstance(expr, php.Variable):
        expr = expr.name

    if isinstance(expr, php.Cast):
        expr = expr.expr.name

    if expr in controlled_params:  # 当为可控变量时 返回1
        logger.debug('[AST] is_controllable --> {expr}'.format(expr=expr))
        if flag:
            return 1, expr
        return 1, php.Variable(expr)

    try:
        if expr.startswith("$"):
            if flag:
                return 3, expr
            return 3, php.Variable(expr)
    except AttributeError:
        pass
    except:
        raise

    return -1, php.Variable(expr)


# def function_deep_back(param, nodes, function_params):  # 回溯函数定义位置
#     """
#     递归回溯函数定义位置，传入param类型不同
#     :param param:
#     :param nodes:
#     :return:
#     """
# function_name = param.name

# is_co = 3
# cp = param
# expr_lineno = 0

# print nodes

# for node in nodes[::-1]:
#     if isinstance(node, php.Function):
#         if node.name == function_name:
#             function_nodes = node.nodes
#
#             # 进入递归函数内语句
#             for function_node in function_nodes:
#                 if isinstance(function_node, php.Return):
#                     return_node = function_node.node
#                     return_param = return_node.node
#                     is_co, cp, expr_lineno = parameters_back(return_param, function_nodes, function_params)
#
# return is_co, cp, expr_lineno


def _collect_var_names(node):
    """从 AST 节点中递归收集所有变量名（字符串形式 '$xxx'）。"""
    names = set()
    if isinstance(node, php.Variable):
        names.add(node.name)
    elif isinstance(node, php.BinaryOp):
        names.update(_collect_var_names(node.left))
        names.update(_collect_var_names(node.right))
    elif isinstance(node, php.FunctionCall) or isinstance(node, _METHOD_CALL_TYPES):
        if hasattr(node, 'params'):
            for p in node.params:
                if hasattr(p, 'node'):
                    names.update(_collect_var_names(p.node))
                elif hasattr(p, 'value'):
                    names.update(_collect_var_names(p.value))
    elif isinstance(node, php.ArrayOffset):
        names.update(_collect_var_names(node.node))
    elif isinstance(node, php.Assignment):
        names.update(_collect_var_names(node.expr))
    elif isinstance(node, php.Cast):
        names.update(_collect_var_names(node.expr))
    elif isinstance(node, php.Silence):
        names.update(_collect_var_names(node.expr))
    elif isinstance(node, php.TernaryOp):
        names.update(_collect_var_names(node.expr))
        names.update(_collect_var_names(node.iftrue))
        names.update(_collect_var_names(node.iffalse))
    return names


def _judge_from_summary_php(summary, call_node):
    """根据函数摘要判定返回值可控性（PHP版）

    返回: (is_co, cp, expr_lineno) 三元组或 None
    """
    actual_params = call_node.params if hasattr(call_node, 'params') else []

    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                if param_idx < len(actual_params):
                    ap = actual_params[param_idx]
                    actual_expr = ap.node if hasattr(ap, 'node') else ap
                    co, _ = is_controllable(actual_expr)
                    if co == 1:
                        return (1, rf.origin, 0)
                    arg_var_names = list(_collect_var_names(actual_expr))
                    if arg_var_names:
                        return ('deps', arg_var_names, 0)

        elif rf.origin_type == "global":
            origin = rf.origin
            co, _ = is_controllable(origin)
            if co == 1:
                return (1, origin, 0)

        elif rf.origin_type == "call":
            origin = rf.origin
            # Check if the return wraps a known repair/sanitizer function
            # (e.g., html_output returns htmlentities($str)). If so, the
            # return value is sanitized → code 2.
            if is_repair(origin):
                logger.debug("[AST][PHP] Summary: {} wraps repair function {}, sanitized".format(
                    summary.name, origin))
                return (2, call_node, 0)
            # Recursively check if the called function's summary also wraps a repair.
            # Handles multi-level wrappers: Format::input → Format::htmlchars → htmlspecialchars
            from core.core_engine.php.summary_generator import lookup_summary as _lookup
            nested_summary = _lookup(origin)
            if nested_summary and nested_summary.return_flow:
                for nested_rf in nested_summary.return_flow:
                    if nested_rf.origin_type == "call" and is_repair(nested_rf.origin):
                        logger.debug("[AST][PHP] Summary: {} → {} → repair {}, sanitized".format(
                            summary.name, origin, nested_rf.origin))
                        return (2, call_node, 0)
            co, _ = is_controllable(origin)
            if co == 1:
                return (1, origin, 0)

        elif rf.origin_type == "literal":
            continue

    return None


def function_back(param, nodes, function_params, vul_function=None, file_path=None, isback=None,
                  parent_node=None):  # 回溯函数定义位置
    """
    递归回溯函数定义位置，使用 deps 机制避免循环递归。

    核心原则：函数体是封闭作用域，只通过形参→实参映射判断可控性。
    不在函数体内再调 parameters_back（避免和调用者的赋值行冲突导致循环）。

    返回值:
        (1, cp, expr_lineno) — 返回值直接可控
        (2, cp, expr_lineno) — 返回值经过修复函数处理
        (3, cp, expr_lineno) — 未确认
        (-1, cp, expr_lineno) — 不可控
        ('deps', [变量名列表], expr_lineno) — 返回值依赖调用者变量，由 parameters_back 继续向上追踪

    :param parent_node: 
    :param isback: 
    :param file_path: 
    :param function_params: 
    :param vul_function: 
    :param param: 函数调用节点（FunctionCall / MethodCall / StaticMethodCall）
    :param nodes: 
    :return: 
    """
    function_name = param.name

    is_co = 3
    cp = param
    expr_lineno = 0

    global scan_function_stack
    if function_name in scan_function_stack:
        logger.info("[AST] Recursive function trace detected: {}, skip to avoid endless loop.".format(
            " -> ".join(scan_function_stack + [function_name])))
        return -1, cp, expr_lineno

    scan_function_stack.append(function_name)

    try:
        # ---- array_map 特殊处理：callback 为已知安全函数时返回值安全 ----
        if function_name == 'array_map':
            actual_params = param.params if hasattr(param, 'params') else []
            if actual_params:
                callback_arg = actual_params[0]
                callback_expr = callback_arg.node if hasattr(callback_arg, 'node') else callback_arg
                callback_name = get_node_name(callback_expr) if hasattr(callback_expr, '__class__') else str(callback_expr)
                # callback_name may include quotes from string literal, strip them
                if callback_name:
                    callback_name = callback_name.strip("'\"")
                if callback_name and is_repair(callback_name):
                    logger.debug("[AST][PHP] array_map callback {} is repair function, return safe".format(callback_name))
                    return -1, param, 0

        # ---- 查内置知识库 ----
        knowledge = _trace_cache.lookup_builtin(function_name)
        if knowledge:
            if knowledge.get("safe") and not knowledge.get("passthrough"):
                logger.debug("[AST][PHP] Builtin knowledge: {} is safe, skip analysis".format(function_name))
                return -1, param, 0
            passthrough = knowledge.get("passthrough", [])
            if passthrough:
                # 从 param.params（实参列表）中提取对应位置的变量名
                deps = []
                actual_params = param.params if hasattr(param, 'params') else []
                for arg_idx in passthrough:
                    if actual_params and arg_idx < len(actual_params):
                        arg = actual_params[arg_idx]
                        if hasattr(arg, 'node'):
                            arg_name = get_node_name(arg.node)
                        else:
                            arg_name = get_node_name(arg) if hasattr(arg, '__class__') else str(arg)
                        if arg_name:
                            deps.append(arg_name)
                if deps:
                    logger.debug("[AST][PHP] Builtin knowledge: {} passthrough → deps: {}".format(function_name, deps))
                    return 'deps', deps, getattr(param, 'lineno', 0)
            # 知识库有记录但没有 passthrough 且 safe=False → 不透传不可控
            return -1, param, 0

        # ---- 检查 Source Discovery ----
        if _source_registry is not None:
            # 检查框架方法调用: $request->input() 等
            if isinstance(param, _METHOD_CALL_TYPES) and _source_registry.framework:
                obj_name = extract_method_object_name(param.node)
                if obj_name:
                    method_name = get_simple_name(param.name)
                    if method_name and _source_registry.is_framework_request_method(obj_name, method_name):
                        logger.debug("[AST][PHP] Source Discovery: framework method {0}()->{1} is controllable".format(
                            obj_name, method_name))
                        return 1, param, getattr(param, 'lineno', 0)

            # 检查用户自定义 source producer 函数 和 框架全局函数
            func_name_sd = get_simple_name(param.name)
            if func_name_sd and _source_registry.is_source_producer(func_name_sd):
                logger.debug("[AST][PHP] Source Discovery: {0} is a source producer".format(func_name_sd))
                return 1, param, getattr(param, 'lineno', 0)

        # ---- 查函数摘要 ----
        callee_summary = lookup_summary(function_name)
        if callee_summary and callee_summary.return_flow:
            result = _judge_from_summary_php(callee_summary, param)
            if result is not None:
                return result

        for node in nodes[::-1]:
            # ---- 普通函数 ----
            if isinstance(node, php.Function):
                if node.name == function_name:
                    called_func = node          # 函数定义节点
                    function_body = node.nodes  # 函数体语句列表
                    result = _analyze_return_deps(
                        called_func, function_body, param,
                        file_path=file_path, isback=isback)
                    return result

            # ---- 类方法 ----
            if isinstance(node, php.Class):
                class_nodes = node.nodes
                for class_node in class_nodes:
                    if isinstance(class_node, php.Method) and class_node.name == function_name:
                        called_func = class_node          # 方法定义节点
                        method_body = class_node.nodes     # 方法体语句列表
                        result = _analyze_return_deps(
                            called_func, method_body, param,
                            file_path=file_path, isback=isback)
                        return result
    finally:
        if scan_function_stack and scan_function_stack[-1] == function_name:
            scan_function_stack.pop()
        else:
            try:
                scan_function_stack.remove(function_name)
            except ValueError:
                pass

    return is_co, cp, expr_lineno


def _analyze_return_deps(called_func, function_body, call_node,
                         file_path=None, isback=None):
    """
    分析函数/方法的返回值依赖哪些形参，通过形参→实参映射得到调用者变量名列表。

    不在函数体内调用 parameters_back，避免循环递归。

    :param called_func:  函数/方法定义节点（php.Function 或 php.Method）
    :param function_body: 函数体语句列表 (called_func.nodes)
    :param call_node:    调用处的 FunctionCall / MethodCall 节点（含实参 param.params）
    :return: 同 function_back 的返回值格式
    """
    # ---- 1. 建立形参→实参映射 ----
    # called_func.params = [FormalParameter('$a', ...), ...]
    # call_node.params   = [Parameter(Variable('$x'), ...), ...]
    formal_params = called_func.params if hasattr(called_func, 'params') else []
    actual_params = call_node.params if hasattr(call_node, 'params') else []

    # 形参名列表：['$a', '$b', ...]
    formal_param_names = []
    for fp in formal_params:
        if hasattr(fp, 'name'):
            formal_param_names.append(fp.name)
        elif isinstance(fp, str):
            formal_param_names.append(fp)

    # arg_map: 形参名 → 实参 AST 节点
    arg_map = {}
    for i, name in enumerate(formal_param_names):
        if i < len(actual_params):
            ap = actual_params[i]
            # Parameter 节点的 .node 才是实际表达式
            if hasattr(ap, 'node'):
                arg_map[name] = ap.node
            elif hasattr(ap, 'value'):
                arg_map[name] = ap.value
            else:
                arg_map[name] = ap

    # 收集实参中引用的变量名（用于 fallback deps）
    caller_var_names = set()
    for ap in actual_params:
        actual_expr = ap.node if hasattr(ap, 'node') else (ap.value if hasattr(ap, 'value') else ap)
        for vn in _collect_var_names(actual_expr):
            caller_var_names.add(vn)

    # ---- 2. 收集可控形参（实参直接可控的形参） ----
    controllable_formal = set()
    for name, actual_expr in arg_map.items():
        co, _ = is_controllable(actual_expr)
        if co == 1:
            controllable_formal.add(name)

    # ---- 3. 函数体内赋值链传播：右部引用可控变量 → 左部也标记可控 ----
    controllable_local = set(controllable_formal)
    for _ in range(3):  # 迭代传播，最多 3 轮
        changed = False
        for func_node in function_body:
            if isinstance(func_node, php.Assignment):
                lhs_name = get_node_name(func_node.node) if hasattr(func_node, 'node') else None
                if lhs_name and lhs_name not in controllable_local:
                    rhs_names = _collect_var_names(func_node.expr)
                    if rhs_names & controllable_local:
                        controllable_local.add(lhs_name)
                        changed = True
        if not changed:
            break

    # ---- 4. 查找 return 语句并分析依赖 ----
    for func_node in function_body:
        if isinstance(func_node, php.Return):
            return_expr = func_node.node
            if return_expr is None:
                continue
            expr_lineno = func_node.lineno if hasattr(func_node, 'lineno') else 0

            # 4a. 检查返回值表达式本身是否直接可控
            co, cp_val = is_controllable(return_expr)
            if co == 1:
                logger.debug("[AST][PHP] Function {} returns controllable source directly".format(
                    called_func.name if hasattr(called_func, 'name') else call_node.name))
                return 1, cp_val, expr_lineno

            # 4b. 如果返回值是函数调用，检查是否为修复函数
            if isinstance(return_expr, (php.FunctionCall,)) or isinstance(return_expr, _METHOD_CALL_TYPES):
                if is_repair(return_expr.name):
                    return 2, return_expr, expr_lineno

            # 4c. 收集返回值表达式中引用的变量名
            return_names = _collect_var_names(return_expr)

            # 检查是否包含可控局部变量（形参或赋值链传播结果）
            matched = return_names & controllable_local
            if matched:
                deps = set()
                for var_name in matched:
                    if var_name in arg_map:
                        # 形参直接出现在返回值中 → 取对应实参的变量名
                        actual_expr = arg_map[var_name]
                        co2, cp2 = is_controllable(actual_expr)
                        if co2 == 1:
                            return 1, cp2, expr_lineno
                        # 从实参表达式中收集变量名
                        deps.update(_collect_var_names(actual_expr))
                    else:
                        # 局部变量间接传播 → 继续从返回值表达式中收集变量名
                        deps.update(return_names)
                if deps:
                    logger.debug("[AST][PHP] Function {} return depends on caller vars: {}".format(
                        call_node.name, deps))
                    return 'deps', list(deps), expr_lineno

            # 4d. fallback: 文本匹配形参名出现在返回值中
            try:
                return_str = str(return_expr)
            except Exception:
                return_str = ''
            for param_name, actual_expr in arg_map.items():
                co3, cp3 = is_controllable(actual_expr)
                if co3 == 1:
                    if param_name in return_str or param_name in return_names:
                        logger.debug("[AST][PHP] Function {} returns controllable param {} (text match)".format(
                            call_node.name, param_name))
                        return 1, cp3, expr_lineno

    # ---- 5. 返回值没有明确可控来源，但有未确认的调用者变量 ----
    if caller_var_names:
        logger.debug("[AST][PHP] Function {} return may depend on caller vars: {}".format(
            call_node.name, caller_var_names))
        return 'deps', list(caller_var_names), 0

    return 3, call_node, 0


def array_back(param, nodes, vul_function=None, file_path=None, isback=None):  # 回溯数组定义赋值
    """
    递归回溯数组赋值定义
    :param isback: 
    :param file_path: 
    :param vul_function: 
    :param param: 
    :param nodes: 
    :return: 
    """
    param_name = get_node_name(param.node)
    param_expr = param.expr

    # print(param_name)
    # print(param_expr)

    is_co, cp = is_controllable(param)
    expr_lineno = param.lineno

    if is_co == 1:
        return is_co, cp, expr_lineno

    is_co = 3
    cp = param

    for node in nodes[::-1]:
        if isinstance(node, php.Assignment):
            param_node_name = get_node_name(node.node)
            param_node = node.node
            param_node_expr = node.expr

            # 仅当左值与当前追踪的数组元素为同一 key 时，才继续沿右值回溯。
            if isinstance(param_node, php.ArrayOffset) and param_node_name == param_name:
                if not is_same_array_index(param_node.expr, param_expr):
                    continue

                if isinstance(param_node_expr, php.ArrayOffset):  # 如果赋值值仍然是数组，先经过判断在进入递归
                    is_co, cp = is_controllable(param_node_expr.node.name)

                    if is_co != 1:
                        is_co, cp, expr_lineno = array_back(param_node_expr, nodes, file_path=file_path,
                                                            isback=isback)
                else:
                    is_co, cp = is_controllable(param_node_expr)

                    if is_co != 1 and is_co != -1:
                        next_param = build_ast_param(param_node_expr)
                        is_co, cp, expr_lineno = parameters_back(next_param, nodes, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback)

            # $arr = ['k' => xxx] 这类一次性数组赋值
            if isinstance(param_node, php.Variable) and param_node_name == param_name:
                if isinstance(param_node_expr, php.Array):
                    for p_node in node.expr.nodes:
                        if is_same_array_index(p_node.key, param_expr):
                            if isinstance(p_node.value, php.ArrayOffset):  # 如果赋值值仍然是数组，先经过判断在进入递归
                                is_co, cp = is_controllable(p_node.value.node.name)

                                if is_co != 1:
                                    is_co, cp, expr_lineno = array_back(p_node.value, nodes, file_path=file_path,
                                                                        isback=isback)

                            else:
                                n_node = build_ast_param(p_node.value)
                                is_co, cp, expr_lineno = parameters_back(n_node, nodes, vul_function=vul_function,
                                                                         file_path=file_path,
                                                                         isback=isback)

    return is_co, cp, expr_lineno


def class_back(param, node, lineno, vul_function=None, file_path=None, isback=None, parent_node=None):
    """
    回溯类中变量
    :param parent_node: 
    :param isback: 
    :param file_path: 
    :param vul_function: 
    :param param: 
    :param node: 
    :param lineno: 
    :return: 
    """
    class_name = node.name
    class_nodes = node.nodes

    logger.debug("[AST] param {} in class {}, start into class...".format(param, class_name))

    vul_nodes = []
    for class_node in class_nodes:
        if class_node.lineno < int(lineno):
            vul_nodes.append(class_node)

    is_co, cp, expr_lineno = parameters_back(param, vul_nodes, lineno=lineno, function_flag=1,
                                             vul_function=vul_function, file_path=file_path,
                                             isback=isback, parent_node=parent_node)

    if is_co == 1 or is_co == -1:  # 可控或者不可控，直接返回
        return is_co, cp, expr_lineno

    elif is_co == 3:
        for class_node in class_nodes:
            if isinstance(class_node, php.Method) and class_node.name == '__construct':
                class_node_params = class_node.params
                constructs_nodes = class_node.nodes

                # 递归析构函数
                is_co, cp, expr_lineno = parameters_back(param, constructs_nodes, function_params=class_node_params,
                                                         lineno=lineno, function_flag=1, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback)

                if is_co == 3:
                    # 回溯输入参数
                    for param in class_node_params:
                        if param.name == cp.name:
                            logger.info(
                                "[Deep AST] Now vulnerability function in class from class {}() param {}".format(
                                    class_name, cp.name))

                            is_co = 4
                            cp = tuple([node, param, class_node_params, vul_function])
                            return is_co, cp, 0

    return is_co, cp, expr_lineno


def new_class_back(param, nodes, vul_function=None, file_path=None, isback=None):
    """
    分析新建的class，自动进入tostring函数
    :param isback: 
    :param file_path: 
    :param vul_function: 
    :param param: 
    :param nodes: 
    :return: 
    """
    new_expr = param.name if hasattr(param, 'name') else param

    if hasattr(new_expr, "name"):
        param_name = get_node_name(new_expr)
    else:
        param_name = new_expr

    is_co = -1
    cp = param
    expr_lineno = 0

    for node in nodes:
        if isinstance(node, php.Class) and param_name == node.name:
            class_nodes = node.nodes

            for class_node in class_nodes:
                if isinstance(class_node, php.Method) and class_node.name == '__toString':
                    tostring_nodes = class_node.nodes
                    logger.debug("[AST] try to analysize class {}() function tostring...".format(param_name))

                    for tostring_node in tostring_nodes:
                        if isinstance(tostring_node, php.Return):
                            return_param = tostring_node.node
                            is_co, cp, expr_lineno = parameters_back(return_param, tostring_nodes,
                                                                     vul_function=vul_function, file_path=file_path,
                                                                     isback=isback)
                            return is_co, cp, expr_lineno

        else:
            is_co = 3
            cp = param

    return is_co, cp, expr_lineno


def parameters_back(param, nodes, function_params=None, lineno=0,
                    function_flag=0, vul_function=None, file_path=None,
                    isback=None, parent_node=None):
    """
    parameters_back 入口（带运行时缓存）。
    缓存查询命中则直接返回；否则调用 _parameters_back_impl，并在确定性结果时写入缓存。
    """
    # 计算 cache key
    if hasattr(param, "name"):
        _pname = get_node_name(param)
    else:
        _pname = param

    # 查缓存
    if lineno and file_path:
        cached = _trace_cache.get(file_path, str(_pname), int(lineno))
        if cached is not None:
            return cached

    # 调用实际实现
    result = _parameters_back_impl(param, nodes, function_params, lineno,
                                    function_flag, vul_function, file_path,
                                    isback, parent_node)
    is_co = result[0]

    # 写入缓存：仅缓存确定性结果（-1=不可控, 1=可控, 2=已修复）
    if lineno and file_path and is_co in (-1, 1, 2):
        _trace_cache.put(file_path, str(_pname), int(lineno), result)

    return result


def _get_body_nodes(node):
    """从 if/elseif/else body 节点提取语句列表"""
    if isinstance(node, php.Block):
        return node.nodes or []
    elif node is not None:
        return [node]
    return []


def _get_max_lineno(nodes):
    """递归获取节点列表中所有节点的最大行号（包括嵌套子节点）"""
    _ATTRS = frozenset(('nodes', 'expr', 'node', 'elseifs', 'else_',
                        'params', 'key', 'value', 'arguments',
                        'iftrue', 'iffalse', 'left', 'right',
                        'condition', 'consequent', 'alternate'))
    max_lineno = 0

    def _walk(node):
        nonlocal max_lineno
        if node is None:
            return
        if isinstance(node, list):
            for n in node:
                _walk(n)
            return
        if hasattr(node, 'lineno') and node.lineno:
            max_lineno = max(max_lineno, int(node.lineno))
        for attr in _ATTRS:
            child = getattr(node, attr, None)
            if child is not None:
                _walk(child)

    _walk(nodes)
    return max_lineno


def _find_sink_branch(if_node, lineno):
    """
    判断 lineno（sink行号）位于 if/else 的哪个分支。

    phply AST 行号规则（已验证）：
    - If.lineno: if 关键字行号
    - ElseIf.lineno: elseif 关键字行号
    - Else.lineno: else 关键字行号

    返回: 'if', 'elseif_N', 'else', 'outside'
    """
    if not lineno:
        return 'outside'

    lineno = int(lineno)

    # 收集各分支的 (起始行号, 类型, 索引)
    boundaries = [(if_node.lineno, 'if', None)]
    for i, ei in enumerate(if_node.elseifs or []):
        boundaries.append((ei.lineno, 'elseif', i))
    if if_node.else_:
        boundaries.append((if_node.else_.lineno, 'else', None))

    # 按行号排序
    boundaries.sort(key=lambda x: x[0])

    # 计算每个分支的行号范围
    for idx, (start, btype, bindex) in enumerate(boundaries):
        if idx + 1 < len(boundaries):
            end = boundaries[idx + 1][0] - 1
        else:
            if btype == 'if':
                body_nodes = _get_body_nodes(if_node.node)
            elif btype == 'elseif':
                body_nodes = _get_body_nodes(if_node.elseifs[bindex].node)
            elif btype == 'else':
                body_nodes = _get_body_nodes(if_node.else_.node) if if_node.else_ else []
            else:
                body_nodes = []

            if body_nodes:
                end = _get_max_lineno(body_nodes)
            else:
                end = start

        if start <= lineno <= end:
            if btype == 'elseif':
                return f'elseif_{bindex}'
            return btype

    return 'outside'



# 类型验证函数 — 条件为 true 时参数被约束为安全类型
_TYPE_VALIDATION_FUNCS = frozenset({
    'is_numeric', 'is_int', 'is_integer', 'is_float', 'is_double',
    'ctype_digit', 'ctype_alnum', 'ctype_alpha', 'ctype_xdigit',
})


def _extract_func_name(name_node):
    """从 FunctionCall.name 节点提取函数名字符串"""
    if isinstance(name_node, str):
        return name_node
    return None


def _extract_regex_pattern(arg_node):
    """从 preg_match 的第一个参数提取正则模式字符串"""
    if isinstance(arg_node, php.String):
        return arg_node.value
    return None


def _is_strict_regex(pattern):
    """
    判断正则是否为严格全匹配模式（安全）。
    条件：以 ^ 开头、以 $ 结尾、中间不含任意字符匹配（. 或 .* 或 .+）。
    """
    if not pattern or len(pattern) < 4:
        return False
    if not pattern.startswith('^') or not pattern.endswith('$'):
        return False
    body = pattern[1:-1]
    # 不含 .（任意字符匹配），但允许 \.（转义的点）
    stripped = body.replace('\\.', '')
    if '.' in stripped:
        return False
    return True


def extract_constraints_from_php_expr(expr):
    """
    从 PHP 条件表达式中提取 BranchConstraint 列表。

    phply AST 中：
    - isset($var)           -> IsSet 节点
    - empty($var)           -> Empty 节点
    - !isset($var)          -> UnaryOp(op='!', expr=IsSet(...))
    - !empty($var)          -> UnaryOp(op='!', expr=Empty(...))
    - $var === value        -> BinaryOp(op='===')
    - $a && $b              -> BinaryOp(op='&&')
    - $a || $b              -> BinaryOp(op='||')
    - is_numeric($var)      -> FunctionCall('is_numeric', [...])
    - preg_match('/^...$/', $var) -> FunctionCall('preg_match', [...])
    """
    if expr is None:
        return []

    constraints = []

    if isinstance(expr, php.IsSet):
        # isset($var) 或 isset($_GET['id'])
        op = 'isset'
        for node in (expr.nodes or []):
            var_name = _extract_var_name(node)
            if var_name:
                constraints.append(BranchConstraint(var_name=var_name, op=op))

    elif isinstance(expr, php.Empty):
        # empty($var)
        op = '!isset'
        var_name = _extract_var_name(expr.expr)
        if var_name:
            constraints.append(BranchConstraint(var_name=var_name, op=op))

    elif isinstance(expr, php.UnaryOp) and expr.op == '!':
        # !isset($x) -> UnaryOp(op='!', expr=IsSet(...))
        # !empty($x) -> UnaryOp(op='!', expr=Empty(...))
        inner = expr.expr
        if isinstance(inner, php.IsSet):
            for node in (inner.nodes or []):
                var_name = _extract_var_name(node)
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='!isset'))
        elif isinstance(inner, php.Empty):
            var_name = _extract_var_name(inner.expr)
            if var_name:
                constraints.append(BranchConstraint(var_name=var_name, op='isset'))

    elif isinstance(expr, php.FunctionCall):
        func_name = _extract_func_name(expr.name)
        if func_name in _TYPE_VALIDATION_FUNCS:
            for arg in (expr.params or []):
                var_name = _extract_var_name(arg)
                if var_name:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='type_validated',
                        value=func_name
                    ))
        elif func_name == 'preg_match':
            if expr.params and len(expr.params) >= 2:
                pattern = _extract_regex_pattern(expr.params[0])
                if pattern and _is_strict_regex(pattern):
                    var_name = _extract_var_name(expr.params[1])
                    if var_name:
                        constraints.append(BranchConstraint(
                            var_name=var_name, op='regex_validated',
                            value=pattern
                        ))
        elif func_name == 'in_array':
            # in_array($needle, $haystack) — $needle is constrained to
            # values present in $haystack.  Treat as whitelist validation.
            if expr.params and len(expr.params) >= 2:
                var_name = _extract_var_name(expr.params[0])
                if var_name:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='in_array',
                        value=None,
                    ))

    elif isinstance(expr, php.BinaryOp):
        if expr.op == '&&':
            # 逻辑 AND：两个约束都要满足
            left = extract_constraints_from_php_expr(expr.left)
            right = extract_constraints_from_php_expr(expr.right)
            constraints = left + right
        elif expr.op == '||':
            # 检查是否为同一变量的枚举：$a == "x" || $a == "y" → $a in ["x", "y"]
            left = extract_constraints_from_php_expr(expr.left)
            right = extract_constraints_from_php_expr(expr.right)
            # 只在两边都是 == 且针对同一变量时合并为 in 约束
            if (len(left) == 1 and len(right) == 1
                    and left[0].op in ('==', '===') and right[0].op in ('==', '===')
                    and left[0].var_name == right[0].var_name):
                values = []
                if left[0].value is not None:
                    values.append(left[0].value)
                if right[0].value is not None:
                    values.append(right[0].value)
                if values:
                    constraints.append(BranchConstraint(
                        var_name=left[0].var_name, op='in', value=values))
            # 否则忽略（不能同时保证 OR 条件）
        elif expr.op in ('==', '===', '!=', '!=='):
            # 比较运算：$var == value
            var_name = _extract_var_name(expr.left)
            if var_name:
                value = _extract_literal_value(expr.right)
                constraints.append(BranchConstraint(var_name=var_name, op=expr.op, value=value))

    return constraints


def _extract_var_name(node):
    """
    从 AST 节点中提取变量名（字符串形式）。
    支持 Variable, Parameter, ArrayOffset 等常见形式。
    返回 None 表示无法提取。
    """
    if node is None:
        return None
    if isinstance(node, php.Parameter):
        # phply 函数参数被包装为 Parameter 节点，实际参数在 .node 中
        node = node.node
    if isinstance(node, php.Variable):
        name = node.name
        if isinstance(name, str):
            return name
    if isinstance(node, php.ArrayOffset):
        # 如 $_GET['id'] -> 提取为 "$_GET" (忽略 key)
        array_name = get_node_name(node.node)
        if isinstance(array_name, str):
            return array_name
    return None


def _extract_literal_value(node):
    """
    从 AST 节点中提取字面量值。
    支持 Constant, string/number 字面量。
    返回 None 表示不是字面量。
    """
    if node is None:
        return None
    if isinstance(node, php.Constant):
        # php.Constant: node.name 可能是字符串值本身（去掉引号）
        val = node.name
        if isinstance(val, str):
            return val
    if isinstance(node, str):
        return node
    if isinstance(node, (int, float)):
        return node
    return None


def _parameters_back_impl(param, nodes, function_params=None, lineno=0,
                    function_flag=0, vul_function=None, file_path=None,
                    isback=None, parent_node=None):  # 用来得到回溯过程中的被赋值的变量是否与敏感函数变量相等,param是当前需要跟踪的污点
    """
    递归回溯敏感函数的赋值流程，param为跟踪的污点，当找到param来源时-->分析复制表达式-->获取新污点；否则递归下一个节点
    :param parent_node: 父节点 ，为了处理无法确定当前节点位置的问题, 如果是0则是最基础列表
    :param file_path: 
    :param vul_function: 
    :param param:
    :param nodes:
    :param function_params:
    :param lineno
    :param function_flag: 是否在函数、方法内的标志位
    :param isback: 是否需要返回该值
    :return:
    """
    global scan_chain

    expr_lineno = 0  # source所在行号
    if hasattr(param, "name"):
        # param_name = param.name
        param_name = get_node_name(param)
    else:
        param_name = param

    is_co, cp = is_controllable(param)

    if not nodes and type(nodes) is bool:
        logger.warning("[AST] AST analysis error, return back.")
        return is_co, cp, expr_lineno

    if isinstance(param, _FUNCTION_CALL_TYPES) and is_co != 1:  # 当污点为寻找函数时，递归进入寻找函数
        logger.debug("[AST] AST analysis for FunctionCall or MethodCall {} in line {}".format(param.name, param.lineno))
        is_co, cp, expr_lineno = function_back(param, nodes, function_params, file_path=file_path, isback=isback)
        # deps 机制：函数返回值依赖调用者变量，跳过当前节点继续向上追踪
        if isinstance(is_co, str) and is_co == 'deps' and isinstance(cp, list):
            for dep_var in cp:
                if hasattr(dep_var, 'name'):
                    dep_name = get_node_name(dep_var)
                else:
                    dep_name = str(dep_var)
                # 从 nodes[:-1] 继续追踪依赖变量
                is_co2, cp2, expr_lineno2 = parameters_back(build_ast_param(dep_name), nodes[:-1], function_params, lineno,
                                                              function_flag=function_flag, vul_function=vul_function,
                                                              file_path=file_path, isback=isback, parent_node=0)
                if is_co2 == 1:
                    return is_co2, cp2, expr_lineno2
            # 所有依赖变量都没找到可控来源
            return 3, param, expr_lineno
        return is_co, cp, expr_lineno

    if isinstance(param, php.ArrayOffset):  # 当污点为数组时，递归进入寻找数组声明或赋值
        logger.debug("[AST] AST analysis for ArrayOffset in line {}".format(param.lineno))
        is_co, cp, expr_lineno = array_back(param, nodes, vul_function=vul_function, file_path=file_path, isback=isback)
        if is_co in [-1, 1, 2]:
            return is_co, cp, expr_lineno

    if isinstance(param, php.Include) or isinstance(param, php.Require):
        # include/require 也可能作为赋值右值或 return 值参与数据流，继续回溯其参数表达式
        logger.debug("[AST] AST analysis for Include/Require in line {}".format(param.lineno))
        param = param.expr
        if hasattr(param, "name"):
            param_name = get_node_name(param)
        else:
            param_name = param
        is_co, cp = is_controllable(param)

    if isinstance(param, php.New) or (
                hasattr(param, "name") and isinstance(param.name, php.New)):  # 当污点为新建类事，进入类中tostring函数分析
        logger.debug("[AST] AST analysis for New Class {} in line {}".format(param.name, param.lineno))
        is_co, cp, expr_lineno = new_class_back(param, nodes, file_path=file_path,
                                                isback=isback)
        return is_co, cp, expr_lineno

    if len(nodes) != 0 and is_co not in [-1, 1, 2]:
        node = nodes[-1]

        # temp var
        _is_co = 0
        _cp = None

        if not node:
            logger.warning("[AST] dataflow analysize error.")
            return is_co, cp, expr_lineno

        # 加入扫描范围check, 如果当前行数大于目标行数，直接跳过(等于会不会有问题呢？)
        if node.lineno >= int(lineno) and int(lineno) != 0:
            return parameters_back(param, nodes[:-1], function_params, lineno,
                                   function_flag=0, vul_function=vul_function,
                                   file_path=file_path,
                                   isback=isback, parent_node=0)

        if isinstance(node, php.Assignment) and param_name == get_node_name(node.node):  # 回溯的过程中，对出现赋值情况的节点进行跟踪
            param_node = get_node_name(node.node)  # param_node为被赋值的变量
            param_expr, expr_lineno, is_re = get_expr_name(node.expr)  # param_expr为赋值表达式,param_expr为变量或者列表

            if param_name == param_node and is_re is True:
                is_co = 2
                cp = param
                return is_co, cp, expr_lineno

            if param_name == param_node and not isinstance(param_expr, list) and not isinstance(param_expr, php.TernaryOp):  # 找到变量的来源，开始继续分析变量的赋值表达式是否可控
                logger.debug(
                    "[AST] Find {}={} in line {}, start ast for param {}".format(param_name, param_expr, expr_lineno,
                                                                                 param_expr))

                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, param_expr)
                scan_chain.append(('Assignment', code, file_path, node.lineno))

                is_co, cp = is_controllable(param_expr)  # 开始判断变量是否可控

                if is_co != 1 and is_co != 3:
                    is_co, cp = is_sink_function(param_expr, function_params)

                if is_co == -1 and isback is True:
                    cp = param_expr

                if is_co in [-1, 1, 2]:  # 目标确定直接返回
                    return is_co, cp, expr_lineno

                if isinstance(node.expr, php.ArrayOffset):
                    param = node.expr
                else:
                    param = build_ast_param(param_expr)  # 每次找到一个污点的来源时，开始跟踪新污点，覆盖旧污点
                    param_name = get_node_name(param)

            if param_name == param_node and isinstance(param_expr, php.TernaryOp):
                terna1 = param_expr.iftrue
                terna2 = param_expr.iffalse
                param_ex = param_expr.expr
                logger.debug("[AST] Find {} from TernaryOp from ?{}:{} in line {}.".format(param_name, terna1, terna2,
                                                                                           node.lineno))

                file_path = os.path.normpath(file_path)
                code = "{}={}?{}:{}".format(param_name, param_ex, terna1, terna2)
                scan_chain.append(('TernaryOp', code, file_path, node.lineno))

                # 分支约束追踪
                constraints = extract_constraints_from_php_expr(param_ex)
                true_names = _collect_var_names(terna1)
                false_names = _collect_var_names(terna2)
                for c in constraints:
                    if c.op in ('==', '===', 'in', 'type_validated', 'regex_validated', 'in_array'):
                        if c.var_name in true_names and c.var_name not in false_names:
                            # 约束变量只在 true 分支 → true 路径中 var == fixed → 阻断
                            logger.info("[AST] Ternary constraint BLOCKS: {} {} {}".format(c.var_name, c.op, c.value))
                            return -1, param, 0
                        elif c.var_name in false_names and c.var_name not in true_names:
                            # 约束变量只在 false 分支 → false 路径中 var != fixed → 不阻断，追踪 false 分支
                            param = terna2
                            break
                else:
                    # 无法判断变量在哪个分支 → 回退到原始启发式
                    is_co, cp = is_controllable(terna1)
                    if is_co == 1:
                        param = terna1
                    else:
                        is_co2, cp = is_controllable(terna2)

                        if is_co2 == 1:
                            param = terna2

                        else:
                            if is_co == -1:
                                param = terna2
                            else:
                                param = terna1

            if param_name == param_node and isinstance(node.expr, php.FunctionCall):  # 当变量来源是函数时，处理函数内容
                function_name = node.expr.name

                # 由于函数式编程的关系，为了不在函数回溯中走入歧途，这里优先检查一次函数名是否和可控函数相等
                is_co, cp = is_controllable(function_name)
                if is_co == 1:
                    logger.debug("[AST] Function {} is controllable.".format(function_name))

                    file_path = os.path.normpath(file_path)
                    code = "{}={}, {} is controllable.".format(param_name, function_name, function_name)
                    scan_chain.append(('Finished', code, file_path, node.lineno))

                    return is_co, cp, expr_lineno

                logger.debug(
                    "[AST] Find {} from FunctionCall for {} in line {}, start ast in function {}".format(param_name,
                                                                                                         function_name,
                                                                                                         node.lineno,
                                                                                                         function_name))
                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, node.expr)
                scan_chain.append(('FunctionCall', code, file_path, node.lineno))

                # 因为没办法解决内置函数的问题，所以尝试引入内置函数列表，如果在其中，则先跳过
                if function_name in PHP_BUILTIN_KNOWLEDGE:
                    logger.debug("[AST] function {} in php defined function list, continue...".format(function_name))

                else:
                    param = node.expr  # 如果没找到函数定义，则将函数作为变量回溯
                    is_co = 3

                    # 尝试寻找函数定义， 看上去应该是冗余代码，因为function call本身就会有处理
                    # for node in nodes[::-1]:
                    #     if isinstance(node, php.Function):
                    #         if node.name == function_name:
                    #             function_nodes = node.nodes
                    #
                    #             # 进入递归函数内语句
                    #             for function_node in function_nodes:
                    #                 if isinstance(function_node, php.Return):
                    #                     return_node = function_node.node
                    #                     return_param = return_node.node
                    #                     is_co, cp, expr_lineno = parameters_back(return_param, function_nodes,
                    #                                                              function_params, lineno, function_flag=1,
                    #                                                              vul_function=vul_function,
                    #                                                              file_path=file_path,
                    #                                                              isback=isback,
                    #                                                              parent_node=node)

            if param_name == param_node and isinstance(node.expr, _METHOD_CALL_TYPES):
                # 当右值为方法调用时，暂时按照和function类似的分析方式

                class_node = node.expr.node.name
                class_method_name = node.expr.name
                class_method_params = node.expr.params

                logger.debug("[AST] Find {} from MethodCall from {}->{} in line {}.".format(param_name, class_node, class_method_name, node.lineno))

                file_path = os.path.normpath(file_path)
                code = "{}={}->{}".format(param_name, class_node, class_method_name)
                scan_chain.append(('MethodCall', code, file_path, node.lineno))

                # 将右值置为methodcall
                param = node.expr
                is_co = 3

            if param_name == param_node and (isinstance(node.expr, php.Include) or isinstance(node.expr, php.Require)):
                logger.debug("[AST] Find {} from Include/Require in line {}.".format(param_name, node.lineno))

                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, node.expr)
                scan_chain.append(('Include', code, file_path, node.lineno))

                param = node.expr.expr
                if hasattr(param, "name"):
                    param_name = get_node_name(param)
                else:
                    param_name = param
                is_co, cp = is_controllable(param)

                if is_co in [-1, 1, 2]:
                    return is_co, cp, expr_lineno

            if param_name == param_node and isinstance(param_expr, list):

                # 这里检测的是函数参数列表...如果为空不一定不可控？
                if len(param_expr) <= 0 and not (isinstance(node.expr, php.FunctionCall) or isinstance(node.expr, _METHOD_CALL_TYPES)):
                    is_co = -1
                    cp = param
                    return is_co, cp, 0

                logger.debug(
                    "[AST] Find {} from list for {} in line {}, start ast for list {}".format(param_name,
                                                                                              param_expr,
                                                                                              node.lineno,
                                                                                              param_expr))
                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, param_expr)
                scan_chain.append(('ListAssignment', code, file_path, node.lineno))

                # 如果目标参数就在列表中，不能直接跳过，需要继续分析列表中的其他变量来源
                if param_name in param_expr:
                    logger.debug("[AST] param {} in list {}, trace other params...".format(param_name, param_expr))

                    fallback_cp = None
                    for p in param_expr:
                        # 跳过被赋值变量自身，避免在自拼接场景下提前中断
                        if p == param_name:
                            continue

                        is_co, cp = is_controllable(p)
                        if is_co == 1:
                            param = p
                            return is_co, cp, expr_lineno

                        if is_co == -1:
                            continue

                        file_path = os.path.normpath(file_path)
                        code = "find param {}".format(p)
                        scan_chain.append(('NewFind', code, file_path, node.lineno))

                        _is_co, _cp, expr_lineno = parameters_back(php.Variable(p), nodes[:-1], function_params, lineno,
                                                                   function_flag=1, vul_function=vul_function,
                                                                   file_path=file_path,
                                                                   isback=isback)
                        if _is_co == 1:
                            is_co = _is_co
                            cp = _cp
                            break

                        if _is_co in [-1, 3] and isinstance(p, str) and p.startswith('$'):
                            fallback_cp = _cp if _is_co == 3 else build_ast_param(p)

                    if is_co != 1:
                        is_co = 3
                        cp = fallback_cp if fallback_cp is not None else param

                else:
                    fallback_cp = None
                    for expr in param_expr:
                        param = expr
                        is_co, cp = is_controllable(expr)

                        if is_co == 1:
                            return is_co, cp, expr_lineno

                        if is_co == -1:
                            continue

                        file_path = os.path.normpath(file_path)
                        code = "find param {}".format(param)
                        scan_chain.append(('NewFind', code, file_path, node.lineno))

                        param = php.Variable(param)
                        _is_co, _cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                   function_flag=1, vul_function=vul_function,
                                                                   file_path=file_path,
                                                                   isback=isback)

                        if _is_co == 1:  # 当参数可控时，值赋给is_co 和 cp，有一个参数可控，则认定这个函数可能可控
                            is_co = _is_co
                            cp = _cp
                            break
                        else:
                            # 当前分支中未找到来源时，变量可能定义在外层作用域（如 if/else 外层赋值）
                            # 透传该变量给上层继续回溯，避免在分支内直接丢失数据流
                            if _is_co in [-1, 3] and isinstance(expr, str) and expr.startswith('$'):
                                fallback_cp = _cp if _is_co == 3 else build_ast_param(expr)
                                continue

                            file_path = os.path.normpath(file_path)
                            code = "param {} find fail. continue".format(param)
                            scan_chain.append(('FindEnd', code, file_path, node.lineno))

                            logger.debug("[AST] Uncontrollable Param {}. continue ast.".format(param))
                            continue

                    if fallback_cp is not None:
                        is_co = 3
                        cp = fallback_cp
                        param = cp

        elif isinstance(node, php.Function) or isinstance(node, php.Method):
            function_nodes = node.nodes
            function_lineno = node.lineno
            function_params = node.params
            vul_nodes = []

            # 如果仅仅是函数定义，如果上一次赋值语句不在函数内，那么不应进去函数里分析，应该直接跳过这部分
            # test1 尝试使用行数叠加的方式
            # 目前测试结果中，这里会出现严重的bug
            # if function_flag == 0 and not isinstance(parent_node, php.Function):
            #     is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
            #                                              function_flag=0, vul_function=vul_function,
            #                                              file_path=file_path,
            #                                              isback=isback, parent_node=parent_node)
            #     return is_co, cp, expr_lineno

            # 在这里想一个解决办法，如果当前父节点为0
            # 然后最后一个为函数节点，那么如果其中的最后一行代码行数小于目标行数，则不进入
            max_lineno_in_func = _get_max_lineno(function_nodes)
            if not function_nodes or max_lineno_in_func < int(lineno):
                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, parent_node=0)
                return is_co, cp, expr_lineno

            logger.debug(
                "[AST] param {} line {} in function {} line {}, start ast in function".format(param_name,
                                                                                              lineno,
                                                                                              node.name,
                                                                                              function_lineno))

            file_path = os.path.normpath(file_path)
            code = "param {} in function {}".format(param_name, node.name)
            scan_chain.append(('Function', code, file_path, node.lineno))

            for function_node in function_nodes:
                if function_node is not None and int(function_lineno) <= function_node.lineno <= int(lineno):
                    vul_nodes.append(function_node)

            if len(vul_nodes) > 0:
                is_co, cp, expr_lineno = parameters_back(param, vul_nodes, function_params, lineno,
                                                         function_flag=1, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, parent_node=None)
                function_flag = 0

                if is_co == 5:
                    logger.debug("[AST] param {} declared as global in function {}, trace from outer scope.".format(
                        param_name, node.name))

                    file_path = os.path.normpath(file_path)
                    code = "param {} declared by global in function {}".format(param_name, node.name)
                    scan_chain.append(('Global', code, file_path, node.lineno))

                    is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                             function_flag=0, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=isback, parent_node=0)
                    return is_co, cp, expr_lineno

                if is_co == 3:  # 出现新的敏感函数，重新生成新的漏洞结构，进入新的遍历结构

                    # 检查函数是不是魔术方法
                    if node.name in PHP_BUILTIN_KNOWLEDGE:
                        logger.debug("[AST] param {} found in php magic funtion {}, continue.".format(param_name, node.name))

                    else:
                        for node_param in node.params:
                            if hasattr(node_param, 'name') and node_param.name == cp.name:
                                logger.debug(
                                    "[AST] param {} line {} in function_params, start new rule for function {}".format(
                                        param_name, node.lineno, node.name))

                                file_path = os.path.normpath(file_path)
                                code = "param {} in NewFunction {}".format(param_name, node.name)
                                scan_chain.append(('NewFunction', code, file_path, node.lineno))

                                if vul_function is None or node.name != vul_function:
                                    logger.info(
                                        "[Deep AST] Now vulnerability function from function {}() param {}".format(node.name,
                                                                                                                   cp.name))

                                    is_co = 4
                                    cp = tuple([node, param, vul_function])
                                    return is_co, cp, 0
                                else:
                                    logger.info(
                                        "[Deep AST] Recursive problems may exist in the code, exit the new rules generated..."
                                    )
                                    # 无法解决递归，直接退出
                                    is_co = -1
                                    return is_co, cp, 0

                    # 从函数中出来的变量，如果参数列表中没有，也不能继续递归
                    is_co = -1

                    file_path = os.path.normpath(file_path)
                    code = "param {} does not found in function {}".format(param_name, node.name)
                    scan_chain.append(('EndFunction', code, file_path, node.lineno))

                    return is_co, cp, expr_lineno

            if is_co in [-1, 1, 2]:  # 目标确定直接返回
                return is_co, cp, expr_lineno

        elif isinstance(node, php.Class):
            is_co, cp, expr_lineno = class_back(param, node, lineno, vul_function=vul_function, file_path=file_path,
                                                isback=isback, parent_node=node)

            if is_co in [-1, 1, 2]:  # 目标确定直接返回
                return is_co, cp, expr_lineno
            else:
                param = cp

        elif isinstance(node, php.If):
            logger.debug(
                "[AST] param {} line {} in if/else, start ast in if/else".format(param_name, node.lineno))

            # 1. 判断 sink 在哪个分支
            sink_branch = _find_sink_branch(node, lineno)
            logger.debug("[AST] sink_branch={} for param {} lineno {}".format(sink_branch, param_name, lineno))

            # 2. 提取当前分支的条件约束并确定分支体
            if sink_branch == 'if':
                constraints = extract_constraints_from_php_expr(node.expr)
                body_nodes = _get_body_nodes(node.node)
            elif sink_branch.startswith('elseif_'):
                ei_idx = int(sink_branch.split('_')[1])
                ei_node = node.elseifs[ei_idx]
                constraints = extract_constraints_from_php_expr(ei_node.expr)
                body_nodes = _get_body_nodes(ei_node.node)
            elif sink_branch == 'else':
                constraints = [c.negate() for c in extract_constraints_from_php_expr(node.expr)]
                body_nodes = _get_body_nodes(node.else_.node) if node.else_ else []
            else:
                # sink 在 if/else 之外 → 遍历所有分支找变量重赋值
                _is_co = 0
                _cp = None
                if_nodes = _get_body_nodes(node.node)
                is_co, cp, expr_lineno = parameters_back(param, if_nodes, function_params, lineno,
                                                         function_flag=function_flag, vul_function=vul_function,
                                                         file_path=file_path, isback=isback, parent_node=node)
                if is_co == 3:
                    _is_co = is_co
                    _cp = cp
                if is_co != 1 and node.elseifs:
                    for node_elseifs_node in node.elseifs:
                        elif_nodes = _get_body_nodes(node_elseifs_node.node)
                        is_co, cp, expr_lineno = parameters_back(param, elif_nodes, function_params, lineno,
                                                                 function_flag=function_flag, vul_function=vul_function,
                                                                 file_path=file_path, isback=isback, parent_node=node)
                    if _is_co != 3 and is_co == 3:
                        _is_co = is_co
                        _cp = cp
                if is_co != 1 and node.else_ and node.else_ is not None:
                    else_nodes = _get_body_nodes(node.else_.node) if node.else_ else []
                    is_co, cp, expr_lineno = parameters_back(param, else_nodes, function_params, lineno,
                                                             function_flag=function_flag, vul_function=vul_function,
                                                             file_path=file_path, isback=isback, parent_node=node)
                    if _is_co != 3 and is_co == 3:
                        _is_co = is_co
                        _cp = cp
                if _is_co == 3 and _cp != param:
                    is_co = _is_co
                    cp = _cp
                    param = _cp
                    file_path = os.path.normpath(file_path)
                    code = "New {} param back from if/else".format(param)
                    scan_chain.append(('NewIFBack', code, file_path, node.lineno))
                # outside 情况已处理完，fall through 到 L1902 的 is_co==1 return 检查

            # 3. 立即检查约束（仅在 sink 在具体分支内时执行，即 sink_branch != 'outside'）
            if sink_branch != 'outside':
                for c in constraints:
                    if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated', 'in_array'):
                        # 等值/白名单约束：变量被限定，不可控
                        logger.info("[AST] Branch constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                        return -1, param, 0

                # 4. 不等约束不阻断，继续回溯分支体
                is_co, cp, expr_lineno = parameters_back(param, body_nodes, function_params, lineno,
                                                         function_flag=function_flag, vul_function=vul_function,
                                                         file_path=file_path, isback=isback, parent_node=node)

                # 分支体内发现新追踪变量时，更新 param 以便外层继续追踪
                if is_co == 3 and cp != param:
                    param = cp

            if is_co == 1:  # 目标确定直接返回
                return is_co, cp, expr_lineno

            # If 处理未得到确定结果，继续外层回溯
            return parameters_back(param, nodes[:-1], function_params, lineno,
                                    function_flag=function_flag, vul_function=vul_function,
                                    file_path=file_path, isback=isback, parent_node=0)

        elif isinstance(node, php.While) or isinstance(node, php.DoWhile):
            logger.debug(
                "[AST] param {} line {} in while, start ast in while".format(param_name, node.lineno))

            if isinstance(node.node, php.Block):
                while_nodes = node.node.nodes
            elif node.node is not None:
                while_nodes = [node.node]
            else:
                while_nodes = []

            # while 循环条件等值约束检查：如果 while 条件中 param_name 有 == 约束，且 sink 在 while 体内 → 阻断
            if while_nodes and lineno:
                _lineno = int(lineno)
                body_start = while_nodes[0].lineno
                body_end = while_nodes[-1].lineno
                if body_start and body_end and body_start <= _lineno <= body_end:
                    constraints = extract_constraints_from_php_expr(node.expr)
                    for c in constraints:
                        if c.var_name == param_name and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated', 'in_array'):
                            logger.info("[AST] While constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                            return -1, param, 0

            is_co, cp, expr_lineno = parameters_back(param, while_nodes, function_params, lineno,
                                                     function_flag=1, vul_function=vul_function, file_path=file_path,
                                                     isback=isback, parent_node=node)

            if is_co in [-1, 1, 2]:  # 目标确定直接返回
                return is_co, cp, expr_lineno

            if is_co == 3 and cp != param:
                # 如果不等于，说明在if/else块中产生了变化
                param = cp

                file_path = os.path.normpath(file_path)
                code = "New {} param back from while".format(param)
                scan_chain.append(('NewWhileBack', code, file_path, node.lineno))

        elif isinstance(node, php.Switch):
            logger.debug(
                "[AST] param {} line {} in Switch, checking branch constraint".format(param_name, node.lineno))

            # 判断 sink 是否在非 default case 中
            sink_in_non_default = False
            case_nodes = node.nodes
            for i, case_node in enumerate(case_nodes):
                if getattr(case_node, 'expr', None) is not None:  # 非 default case
                    case_start = case_node.lineno
                    case_end = case_nodes[i + 1].lineno if i + 1 < len(case_nodes) else case_start + 50
                    if case_start <= lineno <= case_end:
                        sink_in_non_default = True
                        break

            if sink_in_non_default:
                # sink 在非 default case 中 → switch expr == case_value → 阻断
                logger.info("[AST] Switch constraint BLOCKS: sink in non-default case (line {})".format(lineno))
                return -1, param, 0

            # sink 在 default case 或不在任何 case 中 → 跳过 switch 节点，继续外层回溯
            return parameters_back(param, nodes[:-1], function_params, lineno,
                                    function_flag=function_flag, vul_function=vul_function,
                                    file_path=file_path, isback=isback, parent_node=node)

        elif isinstance(node, php.Try):
            logger.debug(
                "[AST] param {} line {} in Try, start ast in Try node".format(param_name, node.lineno))

            try_nodes = node.nodes
            catch_nodes = node.catches
            finally_nodes = getattr(node, 'finally')

            # ast in try
            if finally_nodes is not None:
                # finally 是一定会执行的, 且顺序执行, 所以先分析finally
                logger.debug("[AST] param {} line {} in new branch for finnally".format(param, finally_nodes.lineno))

                is_co, cp, expr_lineno = parameters_back(param, finally_nodes.nodes, function_params, lineno,
                                                         function_flag=1, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, parent_node=node)

                if is_co in [-1, 1, 2]:  # 目标确定直接返回
                    return is_co, cp, expr_lineno

            # try catch 暂时被认定为分支性质，因为很难确定报错的位置，所以暂时为互不干扰
            logger.debug(
                "[AST] param {} line {} in Try, start ast in Try node".format(cp, node.lineno))

            is_co, cp, expr_lineno = parameters_back(cp, try_nodes, function_params, lineno,
                                                     function_flag=1, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, parent_node=node)

            # 如果是3 应该传递cp
            if is_co == 3:
                _is_co = is_co
                _cp = cp

            if is_co != 1 and catch_nodes is not None:

                for catch_node in catch_nodes:
                    logger.debug("[AST] param {} line {} in new branch for catch".format(cp, catch_node.lineno))

                    is_co, cp, expr_lineno = parameters_back(cp, catch_node.nodes, function_params, lineno,
                                                             function_flag=1, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=isback, parent_node=node)

                    if is_co == 1:  # 目标确定直接返回
                        return is_co, cp, expr_lineno

            if _is_co == 3 and _cp != param:
                # 如果不等于，说明在if/else块中产生了变化
                is_co = _is_co
                cp = _cp
                param = _cp

                file_path = os.path.normpath(file_path)
                code = "New {} param back from Try".format(param)
                scan_chain.append(('NewTryBack', code, file_path, node.lineno))

        elif isinstance(node, php.For):
            for_nodes = node.node.nodes
            for_node_lineno = node.node.lineno

            logger.debug(
                "[AST] param {} line {} in for, start ast in for".format(param_name, for_node_lineno))

            is_co, cp, expr_lineno = parameters_back(param, for_nodes, function_params, lineno,
                                                     function_flag=1, vul_function=vul_function, file_path=file_path,
                                                     isback=isback, parent_node=node)
            function_flag = 0

            if is_co in [-1, 1, 2]:  # 目标确定直接返回
                return is_co, cp, expr_lineno

            if _is_co == 3 and cp != param:
                # 如果不等于，说明在if/else块中产生了变化
                param = _cp

                file_path = os.path.normpath(file_path)
                code = "New {} param back from For".format(param)
                scan_chain.append(('NewForBack', code, file_path, node.lineno))

        elif isinstance(node, php.Foreach):
            if param_name == node.valvar.name.name:
                if isinstance(node.expr, php.ArrayOffset):
                    param_expr = node.expr.node
                else:
                    param_expr = node.expr
                expr_lineno = node.lineno
                # 找到变量的来源，开始继续分析变量的赋值表达式是否可控
                logger.debug(
                    "[AST] Find foreach {} as {} in line {}, start ast for param {}".format(param_expr, param_name, expr_lineno,param_expr))

                file_path = os.path.normpath(file_path)
                code = "foreach ({} as {})".format(param_expr, param_name)
                scan_chain.append(('Foreach', code, file_path, node.lineno))
                param = build_ast_param(param_expr)  # 每次找到一个污点的来源时，开始跟踪新污点，覆盖旧污点
                param_name = get_node_name(param) if hasattr(param, 'name') else param
            else:
                foreach_nodes = node.node.nodes
                foreach_node_lineno = node.node.lineno
                logger.debug("[AST] Find foreach, start ast in foreach")

                is_co, cp, expr_lineno = parameters_back(param, foreach_nodes, function_params, lineno,
                                                         function_flag=1, vul_function=vul_function, file_path=file_path,
                                                         isback=isback, parent_node=node)
                function_flag = 0
                if is_co == 3:
                    _is_co = is_co
                    _cp = cp
                    if hasattr(cp, 'name') and cp.name == node.valvar.name.name:
                        if isinstance(node.expr, php.ArrayOffset):
                            param_expr = node.expr.node
                        else:
                            param_expr = node.expr

                        file_path = os.path.normpath(file_path)
                        code = "foreach ({} as {})".format(param_expr, cp.name)
                        scan_chain.append(('Foreach', code, file_path, node.lineno))

                        param = build_ast_param(param_expr)
                        param_name = get_node_name(param) if hasattr(param, 'name') else param
                        _is_co = 0
                        _cp = param

                if is_co in [-1, 1, 2]:  # 目标确定直接返回
                    return is_co, cp, expr_lineno

                if _is_co == 3 and cp != param:
                    param = _cp

                    file_path = os.path.normpath(file_path)
                    code = "New {} param back from Foreach".format(param)
                    scan_chain.append(('NewForBack', code, file_path, node.lineno))

        elif isinstance(node, php.AssignOp):
            # assignop 为 .= +=
            if node.op == ".=" and param_name == get_node_name(node.left):
                param_node = get_node_name(node.left)  # param_node为被赋值的变量
                param_expr, expr_lineno, is_re = get_expr_name(node.right)  # param_expr为赋值表达式,param_expr为变量或者列表

                if param_name == param_node and is_re is True:
                    is_co = 2
                    cp = param
                    return is_co, cp, expr_lineno

                if not isinstance(param_expr, list):
                    logger.debug(
                        "[AST] Find {}.={} in line {}, start ast for param {}".format(param_name, param_expr,
                                                                                      expr_lineno,
                                                                                      param_expr))

                    file_path = os.path.normpath(file_path)
                    code = "{}.={}".format(param_name, param_expr)
                    scan_chain.append(('AssignmentOp', code, file_path, node.lineno))

                    is_co, cp = is_controllable(param_expr)  # 开始判断变量是否可控

                    if is_co != 1 and is_co != 3:
                        is_co, cp = is_sink_function(param_expr, function_params)

                    if is_co == -1 and isback is True:
                        cp = param_expr

                    if is_co in [-1, 1, 2]:  # 目标确定直接返回
                        return is_co, cp, expr_lineno

                    if isinstance(node.expr, php.ArrayOffset):
                        param = node.expr
                    else:
                        param = build_ast_param(param_expr)  # 每次找到一个污点的来源时，开始跟踪新污点，覆盖旧污点
                        param_name = get_node_name(param)

                elif isinstance(param_expr, list):

                    logger.debug(
                        "[AST] Find {} from list for {} in line {}, start ast for list {}".format(param_name,
                                                                                                  param_expr,
                                                                                                  node.lineno,
                                                                                                  param_expr))
                    file_path = os.path.normpath(file_path)
                    code = "{}.={}".format(param_name, param_expr)
                    scan_chain.append(('ListAssignmentOp', code, file_path, node.lineno))

                    # 如果目标参数就在列表中，继续分析列表中的其他变量来源
                    if param_name in param_expr:
                        logger.debug("[AST] param {} in list {}, trace other params...".format(param_name, param_expr))

                        fallback_cp = None
                        for expr in param_expr:
                            # 跳过被赋值变量自身，避免在自拼接场景下提前中断
                            if expr == param_name:
                                continue

                            is_co, cp = is_controllable(expr)

                            if is_co == 1:
                                return is_co, cp, expr_lineno

                            if is_co == -1:
                                continue

                            file_path = os.path.normpath(file_path)
                            code = "find param {}".format(expr)
                            scan_chain.append(('NewFind', code, file_path, node.lineno))

                            _is_co, _cp, expr_lineno = parameters_back(php.Variable(expr), nodes[:-1], function_params, lineno,
                                                                       function_flag=1, vul_function=vul_function,
                                                                       file_path=file_path,
                                                                       isback=isback)

                            if _is_co == 1:
                                is_co = _is_co
                                cp = _cp
                                break

                            if _is_co in [-1, 3] and isinstance(expr, str) and expr.startswith('$'):
                                fallback_cp = _cp if _is_co == 3 else build_ast_param(expr)

                        if is_co != 1:
                            is_co = 3
                            cp = fallback_cp if fallback_cp is not None else param

                    else:
                        for expr in param_expr:
                            param = expr
                            is_co, cp = is_controllable(expr)

                            if is_co == 1:
                                return is_co, cp, expr_lineno

                            if is_co == -1:
                                continue

                            file_path = os.path.normpath(file_path)
                            code = "find param {}".format(param)
                            scan_chain.append(('NewFind', code, file_path, node.lineno))

                            param = php.Variable(param)
                            _is_co, _cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                       function_flag=1, vul_function=vul_function,
                                                                       file_path=file_path,
                                                                       isback=isback)

                            if _is_co == 1:  # 当参数可控时，值赋给is_co 和 cp，有一个参数可控，则认定这个函数可能可控
                                is_co = _is_co
                                cp = _cp
                                break
                            else:
                                file_path = os.path.normpath(file_path)
                                code = "param {} find fail. continue".format(param)
                                scan_chain.append(('FindEnd', code, file_path, node.lineno))

                                logger.debug("[AST] Uncontrollable  Param {}. continue ast.")
                                continue

        elif isinstance(node, php.Global):
            global_params = []
            for global_node in node.nodes:
                global_name = get_node_name(global_node)
                if global_name is not None:
                    global_params.append(global_name)

            if param_name in global_params:
                logger.debug("[AST] Find global {} in line {}, trace in outer scope.".format(param_name, node.lineno))
                return 5, param, node.lineno

        if is_co == 3 or int(lineno) == node.lineno:  # 当is_co为True时找到可控，停止递归
            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, parent_node=0)  # 找到可控的输入时，停止递归

    elif len(nodes) == 0 and function_params is not None:  # 当敏感函数在函数中时，function_params不为空，这时应进入自定义敏感函数逻辑
        for function_param in function_params:
            if function_param == param:
                logger.debug(
                    "[AST] param {} in function_params, start new rule".format(param_name))
                is_co = 2
                cp = function_param

    return is_co, cp, expr_lineno


def deep_parameters_back(param, back_node, function_params, count, file_path, lineno=0, vul_function=None,
                         isback=False):
    """
    深度递归遍历
    :param isback: 是否返回
    :param vul_function: 
    :param lineno: 
    :param param: 
    :param back_node:
    :param function_params: 
    :param file_path: 
    :return: 
    """
    count += 1
    padding = {}

    is_co, cp, expr_lineno = parameters_back(param, back_node, function_params, lineno, vul_function=vul_function,
                                             file_path=file_path, isback=isback, parent_node=0)

    if count > 20:
        logger.warning("[Deep AST] depth too big, auto exit...")
        return is_co, cp, expr_lineno

    if is_co == 3 and back_node and type(back_node) is not bool:
        logger.debug("[Deep AST] try to find include, start deep AST for {}".format(cp))

        for node in back_node[::-1]:
            if isinstance(node, php.Include):
                # 拼接路径需要专门处理，暂时先这样
                # 针对全局变量采用搜索的办法，首先拼接变量
                if isinstance(node.expr, php.BinaryOp):
                    # 遍历下来然后逐个处理
                    params = get_binaryop_params(node.expr, real_back=True)
                    # params = export_list(params, export_params=[])

                    for param in params:
                        # 主要解决两个问题，一个是全局define，一个是变量
                        if isinstance(param, php.Variable):
                            logger.debug(
                                "[AST][INCLUDE] The include file name has an unknown parameter {}.".format(param))

                            file_path = os.path.normpath(file_path)
                            code = "find {} in Include path {}".format(param, file_path)
                            scan_chain.append(('IncludePath', code, file_path, node.lineno))

                            is_co, ccp, expr_lineno = deep_parameters_back(param, back_node[:back_node.index(node)],
                                                                           function_params, count,
                                                                           file_path, lineno, vul_function=vul_function,
                                                                           isback=True)

                            if is_co == -1:
                                padding[get_node_name(param)] = ccp

                # 拼接路径
                filename = get_filename(node, file_path)

                # 替换处理
                if isinstance(filename, list):
                    for i in filename:
                        if i in padding:
                            filename[filename.index(i)] = padding[i]

                    filename = "".join(filename)

                file_path_list = re.split(r"[\/\\]", file_path)
                file_path_list.pop()
                file_path_list.append(filename)
                if "not_found" in filename:
                    continue
                file_path_name = "/".join(file_path_list)

                try:
                    logger.debug("[Deep AST] open new file {file_path}".format(file_path=file_path_name))

                    all_nodes = ast_object.get_nodes(file_path_name)

                except Exception as e:
                    logger.warning("[Deep AST] error to open new file...continue")
                    continue

                node = cp

                file_path = os.path.normpath(file_path)
                code = "find {} in Include {}".format(node, file_path_name)
                scan_chain.append(('Include', code, file_path, node.lineno))

                is_co, cp, expr_lineno = deep_parameters_back(node, all_nodes, function_params, count, file_path_name,
                                                              lineno, vul_function=vul_function, isback=isback)
                if is_co == -1 or is_co == 1:
                    break

    return is_co, cp, expr_lineno


def get_function_node(nodes, s_lineno, e_lineno):
    """
    获取node列表中的指定行的node
    :param nodes: 
    :param s_lineno: 
    :param e_lineno: 
    :return: 
    """
    result = []

    for node in nodes:
        if node.lineno == e_lineno:
            result.append(node)
            break
        if node.lineno == s_lineno:
            result.append(node)
    return result


def get_function_params(nodes):
    """
    获取用户自定义函数的所有入参
    :param nodes: 自定义函数的参数部分
    :return: 以列表的形式返回所有的入参
    """
    params = []
    for node in nodes:

        if isinstance(node, php.FormalParameter):
            params.append(node.name)

    return params


def anlysis_params(param, file_path, vul_lineno, vul_function=None, repair_functions=None, controlled_params=None,
                   isexternal=False):
    """
    在cast调用时做中转数据预处理
    :param repair_functions: 
    :param vul_function: 
    :param lineno: 
    :param param: 
    :param isexternal: 是否外部调用
    :param file_path: 
    :return: 
    """
    global is_repair_functions, is_controlled_params, scan_chain, scan_function_stack
    count = 0
    function_params = None
    if repair_functions is not None:
        is_repair_functions = repair_functions

    if controlled_params is not None:
        is_controlled_params = controlled_params

    if type(param) is str and "->" in param:
        param_left = php.Variable(param.split("->")[0])
        param_right = param.split("->")[1]
        param = php.ObjectProperty(param_left, param_right)

    if isexternal:
        scan_chain = ['start']
        scan_function_stack = []

    all_nodes = ast_object.get_nodes(file_path)

    # 做一次处理，解决Variable(Variable('$id'))的问题
    while isinstance(param, php.Variable):
        param = param.name

    # 这里需要重新梳理参数的判断问题
    if type(param) is str:
        if not param.startswith("$"):
            is_co = -1
            cp = param
            expr_lineno = vul_lineno
            return is_co, cp, expr_lineno, scan_chain
    
        param = php.Variable(param)

    logger.debug("[AST] AST to find param {}".format(param))

    file_path = os.path.normpath(file_path)
    code = "find param {}".format(param)
    scan_chain.append(('NewFind', code, file_path, vul_lineno))

    vul_nodes = []
    for node in all_nodes:
        if node is not None and node.lineno <= int(vul_lineno):
            vul_nodes.append(node)

    is_co, cp, expr_lineno = deep_parameters_back(param, vul_nodes, function_params, count, file_path, vul_lineno,
                                                  vul_function=vul_function)

    return is_co, cp, expr_lineno, scan_chain


def anlysis_function(node, back_node, vul_function, function_params, vul_lineno, file_path=None):
    """
    对用户自定义的函数进行分析-->获取函数入参-->入参用经过赋值流程，进入sink函数-->此自定义函数为危险函数
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param function_params:
    :param vul_lineno:
    :return:
    """
    global scan_results
    try:
        node_typename = node.__class__.__name__

        if node_typename in BASE_FUNCTIONCALL_LIST:
            function_name = node.name
            # 对 StaticMethodCall / MethodCall 拼接完整限定名（Class::method / $obj->method）
            # 用于匹配 EXTRA_SINKS 等带类名前缀的 vul_function
            if node_typename == 'StaticMethodCall':
                cls_name = getattr(node, 'class_', None)
                if cls_name and function_name:
                    function_name = '{}::{}'.format(cls_name, function_name)
            elif node_typename == 'MethodCall' and hasattr(node, 'expr'):
                expr_text = getattr(node.expr, 'name', str(getattr(node.expr, 'value', None)))
                if expr_text and function_name:
                    function_name = '{}->{}'.format(expr_text, function_name)
        else:
            function_name = node_typename.lower()

        if int(node.lineno) == int(vul_lineno):
            if function_name == vul_function:  # 函数体中存在敏感函数，开始对敏感函数前的代码进行检测

                function_params = get_all_functioncall_params(node)

                for param in function_params:
                    param_node_typename = param.__class__.__name__

                    if isinstance(param, php.Variable):
                        analysis_variable_node(param, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(param, php.FunctionCall):
                        analysis_functioncall_node(param, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                    if isinstance(param, php.BinaryOp):
                        analysis_binaryop_node(param, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(param, php.ArrayOffset):
                        analysis_arrayoffset_node(param, vul_function, vul_lineno)

                    if isinstance(param, php.Assignment):
                        if isinstance(param.node, php.Variable):
                            analysis_variable_node(param.node, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.expr, _FUNCTION_CALL_TYPES):
                            analysis_functioncall_node(param.expr, back_node, vul_function, vul_lineno, function_params,
                                                       file_path=file_path)

                        if isinstance(param.expr, php.Variable):
                            analysis_variable_node(param.expr, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.expr, php.BinaryOp):
                            analysis_binaryop_node(param.expr, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.expr, php.ArrayOffset):
                            analysis_arrayoffset_node(param.expr, vul_function, vul_lineno)

                        if isinstance(param.expr, php.TernaryOp):
                            analysis_ternaryop_node(param.expr, back_node, vul_function, vul_lineno, function_params,
                                                    file_path=file_path)

                    if isinstance(param, php.AssignOp):
                        if isinstance(param.left, php.Variable):
                            analysis_variable_node(param.left, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.right, _FUNCTION_CALL_TYPES):
                            analysis_functioncall_node(param.right, back_node, vul_function, vul_lineno, function_params,
                                                       file_path=file_path)

                        if isinstance(param.right, php.Variable):
                            analysis_variable_node(param.right, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.right, php.BinaryOp):
                            analysis_binaryop_node(param.right, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                        if isinstance(param.right, php.ArrayOffset):
                            analysis_arrayoffset_node(param.right, vul_function, vul_lineno)

                        if isinstance(param.right, php.TernaryOp):
                            analysis_ternaryop_node(param.right, back_node, vul_function, vul_lineno, function_params,
                                                    file_path=file_path)

                    if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
                        analysis_special_functioncall_node(param, back_node, vul_function, vul_lineno, function_params,
                                                           file_path=file_path)

            elif node_typename in SPECIAL_FUNCTIONCALL_LIST:
                # 如果在目标同行，但是当前node函数名不是目标函数名，则递归再进一次

                function_params = get_all_functioncall_params(node)

                for param in function_params:
                    param_node_typename = param.__class__.__name__

                    if param_node_typename in FUNCTIONCALL_LIST:

                        anlysis_function(param, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

    except Exception as e:
        logger.debug(traceback.format_exc())


def analysis_functioncall(node, back_node, vul_function, vul_lineno):
    """
    调用FunctionCall-->判断调用Function是否敏感-->get params获取所有参数-->开始递归判断
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno
    :return:
    """
    global scan_results
    try:
        if node.name == vul_function and int(node.lineno) == int(vul_lineno):  # 定位到敏感函数
            for param in node.params:
                param_node_typename = param.__class__.__name__

                if isinstance(param.node, php.Variable):
                    analysis_variable_node(param.node, back_node, vul_function, vul_lineno)

                if isinstance(param.node, php.FunctionCall):
                    analysis_functioncall_node(param.node, back_node, vul_function, vul_lineno)

                if isinstance(param.node, php.BinaryOp):
                    analysis_binaryop_node(param.node, back_node, vul_function, vul_lineno)

                if isinstance(param.node, php.ArrayOffset):
                    analysis_arrayoffset_node(param.node, vul_function, vul_lineno)

                if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
                    analysis_special_functioncall_node(param, back_node, vul_function, vul_lineno)

    except Exception as e:
        logger.debug(e)


def analysis_binaryop_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理BinaryOp类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    params = get_binaryop_params(node)
    params = export_list(params, export_params=[])

    for param in params:
        param = php.Variable(param)
        param_lineno = node.lineno
        # is_co, cp, expr_lineno = parameters_back(param, back_node, function_params)

        if file_path is not None:
            is_co, cp, expr_lineno, chain = anlysis_params(param, file_path, param_lineno, vul_function=vul_function)
        else:
            count = 0
            is_co, cp, expr_lineno = deep_parameters_back(node, back_node, function_params, count, file_path,
                                                          vul_function=vul_function)

        set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_objectproperry_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理_objectproperry类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))

    param = node
    param_lineno = node.lineno

    # is_co, cp, expr_lineno = parameters_back(param, back_node, function_params)
    if file_path is not None:
        # with open(file_path, 'r') as fi:
        # fi = codecs.open(file_path, 'r', encoding='utf-8', errors='ignore')
        # code_content = fi.read()

        is_co, cp, expr_lineno, chain = anlysis_params(param, file_path, param_lineno, vul_function=vul_function)
    else:
        count = 0
        is_co, cp, expr_lineno = deep_parameters_back(node, back_node, function_params, count,
                                                      vul_function=vul_function)

    set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_arrayoffset_node(node, vul_function, vul_lineno):
    """
    处理ArrayOffset类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param node:
    :param vul_function:
    :param vul_lineno:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    param = get_node_name(node.node)
    expr_lineno = node.lineno
    is_co, cp = is_controllable(param)

    set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_functioncall_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理FunctionCall类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    params = get_all_params(get_functioncall_params_by_index(node))
    function_name = get_node_name(node)

    if is_repair(function_name):
        logger.info("[AST] Function {} is repair func. fail control back.".format(function_name))
        return False

    # 如果危险函数参数本身是可控函数调用（例如 system(input('get.id'))），
    # 直接按可控处理，避免继续回溯 input 的字面量参数导致漏报。
    is_co, cp = is_controllable(function_name)
    if is_co == 1:
        expr_lineno = node.lineno
        set_scan_results(is_co, cp, expr_lineno, vul_function, node, vul_lineno)
        return True

    for param in params:
        param = php.Variable(param)
        param_lineno = node.lineno

        if file_path is not None:
            is_co, cp, expr_lineno, chain = anlysis_params(param, file_path, param_lineno, vul_function=vul_function)
        else:
            count = 0
            is_co, cp, expr_lineno = deep_parameters_back(node, back_node, function_params, count, file_path,
                                                          vul_function=vul_function)

        set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_special_functioncall_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理FunctionCall类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param file_path:
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    function_params = get_all_functioncall_params(node)
    function_name = node.__class__.__name__

    if is_repair(function_name):
        logger.info("[AST] Function {} is repair func. fail control back.".format(function_name))
        return False

    for param in function_params:
        param_lineno = node.lineno

        if file_path is not None:
            is_co, cp, expr_lineno, chain = anlysis_params(param, file_path, param_lineno, vul_function=vul_function)
        else:
            count = 0
            is_co, cp, expr_lineno = deep_parameters_back(node, back_node, function_params, count, file_path,
                                                          vul_function=vul_function)

        set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_variable_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理Variable类型节点-->取出参数-->回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    param = get_node_name(node)
    param_lineno = node.lineno

    if file_path is not None:
        is_co, cp, expr_lineno, chain = anlysis_params(param, file_path, param_lineno, vul_function=vul_function)
    else:
        count = 0
        is_co, cp, expr_lineno = deep_parameters_back(node, back_node, function_params, count, file_path,
                                                      vul_function=vul_function)

    set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_ternaryop_node(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None,
                            repair_functions=[]):
    """
    处理三元提交判断语句，回溯双变量
    :param node: 
    :param back_node: 
    :param vul_function: 
    :param vul_lineno: 
    :param function_params: 
    :param file_path: 
    :return: 
    """
    logger.debug('[AST] vul_function:{v}'.format(v=vul_function))
    param = node.expr
    node1 = node.iftrue
    node2 = node.iffalse

    if type(node1) is int:
        node1 = php.Variable(node1)

    if type(node2) is int:
        node2 = php.Variable(node2)

    logger.debug('[AST] vul_param1: {}, vul_param2: {}'.format(node1, node2))

    count = 0
    is_co, cp, expr_lineno = deep_parameters_back(node1, back_node, function_params, count, file_path)
    set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)

    is_co, cp, expr_lineno = deep_parameters_back(node2, back_node, function_params, count, file_path)
    set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)


def analysis_if_else(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    nodes = []
    if isinstance(node.node, php.Block):  # if语句中的sink点以及变量
        analysis(node.node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)
    else:
        analysis([node.node], vul_function, back_node, vul_lineno, file_path, function_params)

    if node.else_ is not None:  # else语句中的sink点以及变量
        if isinstance(node.else_.node, php.Block):
            analysis(node.else_.node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)
        else:
            analysis([node.node], vul_function, back_node, vul_lineno, file_path, function_params)

    if len(node.elseifs) != 0:  # elseif语句中的sink点以及变量
        for i_node in node.elseifs:
            if i_node.node is not None:
                if isinstance(i_node.node, php.Block):
                    analysis(i_node.node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

                else:
                    nodes.append(i_node.node)
                    analysis(nodes, vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_try(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    # for try
    analysis(node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

    if node.catches is not None:
        for catch in node.catches:
            analysis(catch.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

    if getattr(node, 'finally') is not None:
        analysis(getattr(node, 'finally').nodes, vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_echo_print(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理echo/print类型节点-->判断节点类型-->不同If分支回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    global scan_results

    if int(vul_lineno) == int(node.lineno):
        if isinstance(node, php.Print):
            param_node_typename = node.node.__class__.__name__

            if isinstance(node.node, _FUNCTION_CALL_TYPES):
                analysis_functioncall_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                           file_path=file_path)

            if isinstance(node.node, php.Variable) and vul_function == 'print':  # 直接输出变量信息
                analysis_variable_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                       file_path=file_path)

            if isinstance(node.node, php.BinaryOp) and vul_function == 'print':
                analysis_binaryop_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                       file_path=file_path)

            if isinstance(node.node, php.ArrayOffset) and vul_function == 'print':
                analysis_arrayoffset_node(node.node, vul_function, vul_lineno)

            if isinstance(node.node, php.TernaryOp) and vul_function == 'print':
                analysis_ternaryop_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                        file_path=file_path)

            if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
                analysis_special_functioncall_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

        elif isinstance(node, php.Echo):
            for k_node in node.nodes:
                param_node_typename = k_node.__class__.__name__

                if isinstance(k_node, _FUNCTION_CALL_TYPES):
                    # 判断节点中是否有函数调用节点
                    analysis_functioncall_node(k_node, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)  # 将含有函数调用的节点进行分析

                if isinstance(k_node, php.Variable) and vul_function == 'echo':
                    analysis_variable_node(k_node, back_node, vul_function, vul_lineno, function_params,
                                           file_path=file_path)

                if isinstance(k_node, php.BinaryOp) and vul_function == 'echo':
                    analysis_binaryop_node(k_node, back_node, vul_function, vul_lineno, function_params,
                                           file_path=file_path)

                if isinstance(k_node, php.ArrayOffset) and vul_function == 'echo':
                    analysis_arrayoffset_node(k_node, vul_function, vul_lineno)

                if isinstance(k_node, php.TernaryOp) and vul_function == 'echo':
                    analysis_ternaryop_node(k_node, back_node, vul_function, vul_lineno, function_params,
                                            file_path=file_path)

                if isinstance(k_node, php.Assignment) and vul_function == 'echo':
                    analysis_variable_node(k_node.node, back_node, vul_function, vul_lineno, function_params,
                                           file_path=file_path)
                    if isinstance(k_node.expr, _FUNCTION_CALL_TYPES):
                        analysis_functioncall_node(k_node.expr, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                    if isinstance(k_node.expr, php.Variable):
                        analysis_variable_node(k_node.expr, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(k_node.expr, php.BinaryOp):
                        analysis_binaryop_node(k_node.expr, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(k_node.expr, php.ArrayOffset):
                        analysis_arrayoffset_node(k_node.expr, vul_function, vul_lineno)

                    if isinstance(k_node.expr, php.TernaryOp):
                        analysis_ternaryop_node(k_node.expr, back_node, vul_function, vul_lineno, function_params,
                                                file_path=file_path)

                if isinstance(k_node, php.AssignOp) and vul_function == 'echo':
                    analysis_variable_node(k_node.left, back_node, vul_function, vul_lineno, function_params,
                                           file_path=file_path)
                    if isinstance(k_node.right, _FUNCTION_CALL_TYPES):
                        analysis_functioncall_node(k_node.right, back_node, vul_function, vul_lineno, function_params,
                                                   file_path=file_path)

                    if isinstance(k_node.right, php.Variable):
                        analysis_variable_node(k_node.right, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(k_node.right, php.BinaryOp):
                        analysis_binaryop_node(k_node.right, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)

                    if isinstance(k_node.right, php.ArrayOffset):
                        analysis_arrayoffset_node(k_node.right, vul_function, vul_lineno)

                    if isinstance(k_node.right, php.TernaryOp):
                        analysis_ternaryop_node(k_node.right, back_node, vul_function, vul_lineno, function_params,
                                                file_path=file_path)

                if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
                    analysis_special_functioncall_node(k_node, back_node, vul_function, vul_lineno, function_params,
                                                       file_path=file_path)


def analysis_return(node, back_node, vul_function, vul_lineno, function_params=None, file_path=None):
    """
    处理return节点
    :param file_path: 
    :param node:
    :param back_node:
    :param vul_function:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    global scan_results

    if int(vul_lineno) == int(node.lineno) and isinstance(node, php.Return):
        param_node_typename = node.node.__class__.__name__

        if isinstance(node.node, _FUNCTION_CALL_TYPES):
            analysis_functioncall_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                       file_path=file_path)

        if isinstance(node.node, php.Variable):  # 直接输出变量信息
            analysis_variable_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                   file_path=file_path)

        if isinstance(node.node, php.BinaryOp):
            analysis_binaryop_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                   file_path=file_path)

        if isinstance(node.node, php.ArrayOffset):
            analysis_arrayoffset_node(node.node, vul_function, vul_lineno)

        if isinstance(node.node, php.TernaryOp):
            analysis_ternaryop_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                    file_path=file_path)

        if isinstance(node.node, php.Silence):
            nodes = get_silence_params(node.node)
            analysis(nodes, vul_function, back_node, vul_lineno, file_path)

        if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
            analysis_special_functioncall_node(node.node, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)


def analysis_eval(node, vul_function, back_node, vul_lineno, function_params=None, file_path=None):
    """
    处理eval类型节点-->判断节点类型-->不同If分支回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param vul_function:
    :param back_node:
    :param vul_lineno:
    :param function_params:
    :return:
    """
    global scan_results

    if vul_function == 'eval' and int(node.lineno) == int(vul_lineno):
        param_node_typename = node.expr.__class__.__name__

        if isinstance(node.expr, php.Variable):
            analysis_variable_node(node.expr, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        if isinstance(node.expr, _FUNCTION_CALL_TYPES):
            analysis_functioncall_node(node.expr, back_node, vul_function, vul_lineno, function_params,
                                       file_path=file_path)

        if isinstance(node.expr, php.BinaryOp):
            analysis_binaryop_node(node.expr, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        if isinstance(node.expr, php.ArrayOffset):
            analysis_arrayoffset_node(node.expr, vul_function, vul_lineno)

        if isinstance(node.expr, _OBJECT_PROPERTY_TYPES):
            nodes = get_silence_params(node.expr)
            analysis(nodes, vul_function, back_node, vul_lineno, file_path)

        if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
            analysis_special_functioncall_node(node.expr, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)


def analysis_file_inclusion(node, vul_function, back_node, vul_lineno, function_params=None, file_path=None):
    """
    处理include/require类型节点-->判断节点类型-->不同If分支回溯判断参数是否可控-->输出结果
    :param file_path: 
    :param node:
    :param vul_function:
    :param back_node:
    :param vul_lineno:
    :param function_params:
    :return:    
    """
    global scan_results
    include_fs = ['include', 'include_once', 'require', 'require_once']

    if vul_function in include_fs and int(node.lineno) == int(vul_lineno):
        logger.debug('[AST-INCLUDE] {l}-->{r}'.format(l=vul_function, r=vul_lineno))
        param_node_typename = node.expr.__class__.__name__

        if isinstance(node.expr, php.Variable):
            analysis_variable_node(node.expr, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        if isinstance(node.expr, _FUNCTION_CALL_TYPES):
            analysis_functioncall_node(node.expr, back_node, vul_function, vul_lineno, function_params,
                                       file_path=file_path)

        if isinstance(node.expr, php.BinaryOp):
            analysis_binaryop_node(node.expr, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        if isinstance(node.expr, php.ArrayOffset):
            analysis_arrayoffset_node(node.expr, vul_function, vul_lineno)

        if isinstance(node.expr, _OBJECT_PROPERTY_TYPES):
            analysis_objectproperry_node(node.expr, back_node, vul_function, vul_lineno, function_params,
                                         file_path=file_path)

        if param_node_typename in SPECIAL_FUNCTIONCALL_LIST:
            analysis_special_functioncall_node(node.expr, back_node, vul_function, vul_lineno, function_params,
                                               file_path=file_path)


def set_scan_results(is_co, cp, expr_lineno, sink, param, vul_lineno):
    """
    获取结果信息-->输出结果
    :param is_co:
    :param cp:
    :param expr_lineno:
    :param sink:
    :param param:
    :param vul_lineno:
    :return:
    """
    results = []
    global scan_results, scan_chain

    result = {
        'code': is_co,
        'source': cp,
        'source_lineno': expr_lineno,
        'sink': sink,
        'sink_param:': param,
        'sink_lineno': vul_lineno,
        "chain": scan_chain,
    }
    if result['code'] > 0:  # 1/2/3/4（含 NewFunction 信号）
        results.append(result)
        scan_results += results
    elif result['code'] == -1:
        # 分支约束阻断：仅在没有其他结果时保留
        if not scan_results:
            results.append(result)
            scan_results += results


def analysis(nodes, vul_function, back_node, vul_lineno, file_path=None, function_params=None):
    """
    调用FunctionCall-->analysis_functioncall分析调用函数是否敏感
    :param nodes: 所有节点
    :param vul_function: 要判断的敏感函数名
    :param back_node: 各种语法结构里面的语句
    :param vul_lineo: 漏洞函数所在行号
    :param function_params: 自定义函数的所有参数列表
    :param file_path: 当前分析文件的地址
    :return:
    """
    if not nodes or not isinstance(nodes, list):
        return
    buffer_ = []

    for node in nodes:

        if not node:
            continue

        # 检查line范围，以快速锁定参数
        if vul_lineno < node.lineno:
            break

        node_typename = node.__class__.__name__

        if isinstance(node, _FUNCTION_CALL_TYPES) or node_typename in SPECIAL_FUNCTIONCALL_LIST:
            # 函数直接调用，不进行赋值
            anlysis_function(node, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

        elif isinstance(node, php.Assignment):  # 函数调用在赋值表达式中
            if isinstance(node.expr, _FUNCTION_CALL_TYPES):
                anlysis_function(node.expr, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

            if isinstance(node.expr, php.Eval):
                analysis_eval(node.expr, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

            if isinstance(node.expr, php.Silence):
                buffer_.append(node.expr)
                analysis(buffer_, vul_function, back_node, vul_lineno, file_path, function_params)

        elif isinstance(node, php.Return):
            analysis_return(node, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.Print) or isinstance(node, php.Echo):
            analysis_echo_print(node, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.Silence):
            nodes = get_silence_params(node)
            analysis(nodes, vul_function, back_node, vul_lineno, file_path)

        elif isinstance(node, php.AssignOp):
            if isinstance(node.right, _FUNCTION_CALL_TYPES):
                anlysis_function(node.right, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

            if isinstance(node.right, php.Eval):
                analysis_eval(node.right, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

            if isinstance(node.right, php.Silence):
                buffer_.append(node.right)
                analysis(buffer_, vul_function, back_node, vul_lineno, file_path, function_params)

        elif isinstance(node, php.BinaryOp):
            if isinstance(node.left, _FUNCTION_CALL_TYPES):
                anlysis_function(node.left, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

            if isinstance(node.left, php.Eval):
                analysis_eval(node.left, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

            if isinstance(node.left, php.Silence):
                buffer_.append(node.left)
                analysis(buffer_, vul_function, back_node, vul_lineno, file_path, function_params)

            if isinstance(node.right, _FUNCTION_CALL_TYPES):
                anlysis_function(node.right, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

            if isinstance(node.right, php.Eval):
                analysis_eval(node.right, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

            if isinstance(node.right, php.Silence):
                buffer_.append(node.right)
                analysis(buffer_, vul_function, back_node, vul_lineno, file_path, function_params)

        elif isinstance(node, php.Eval):
            analysis_eval(node, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.Include) or isinstance(node, php.Require):
            analysis_file_inclusion(node, vul_function, back_node, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.If):  # 函数调用在if-else语句中时
            analysis_if_else(node, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.While) or isinstance(node, php.DoWhile) or isinstance(node, php.For) or isinstance(node, php.Foreach):  # 函数调用在循环中
            if isinstance(node.node, php.Block):
                analysis(node.node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

        elif isinstance(node, php.Switch):
            for case in node.nodes:
                analysis(case.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

        elif isinstance(node, php.Try):
            analysis_try(node, back_node, vul_function, vul_lineno, function_params, file_path=file_path)

        elif isinstance(node, php.Function) or isinstance(node, php.Method):
            function_body = []
            function_params = get_function_params(node.params)
            analysis(node.nodes, vul_function, function_body, vul_lineno, function_params=function_params,
                     file_path=file_path)

        elif isinstance(node, php.Class) or isinstance(node, php.Trait):
            analysis(node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)

        elif node_typename in FUNCTIONCALL_LIST:
            anlysis_function(node, back_node, vul_function, function_params, vul_lineno, file_path=file_path)

        back_node.append(node)

    # ---- 闭包体递归搜索 ----
    # 顶层 analysis 找不到 sink 时，搜索 Closure/匿名函数 内部
    # 框架路由中的闭包（如 Route::get('/path', function() { ... })）是最常见的场景
    if not scan_results:
        _search_closures_for_analysis(nodes, vul_function, back_node, vul_lineno, file_path, function_params)


def _search_closures_for_analysis(nodes, vul_function, back_node, vul_lineno, file_path, function_params):
    """在 AST 节点中搜索 Closure，对其 body 运行 analysis()"""
    if scan_results:
        return
    for node in nodes:
        if not node or scan_results:
            continue
        # 检查函数调用的参数中是否有 Closure（如 Route::get('/path', function() { ... })）
        if hasattr(node, 'params'):
            for param in node.params:
                if isinstance(param, php.Closure):
                    _try_analyze_closure_body(param, vul_function, back_node, vul_lineno, file_path, function_params)
                    if scan_results:
                        return
        # 检查 Assignment 表达式中的 Closure（如 $fn = function() { ... }）
        if isinstance(node, php.Assignment) and hasattr(node, 'expr'):
            _try_analyze_closure_body(node.expr, vul_function, back_node, vul_lineno, file_path, function_params)
            if scan_results:
                return
        # 递归搜索嵌套节点（如 if/while 中的 Closure）
        if isinstance(node, php.If):
            _search_closures_for_analysis(node.node.nodes if hasattr(node.node, 'nodes') and node.node.nodes else [], vul_function, back_node, vul_lineno, file_path, function_params)
            if hasattr(node, 'elseifs'):
                for elif_block in node.elseifs:
                    _search_closures_for_analysis(elif_block.nodes if hasattr(elif_block, 'nodes') and elif_block.nodes else [], vul_function, back_node, vul_lineno, file_path, function_params)
            if hasattr(node, 'else_') and node.else_:
                _search_closures_for_analysis(node.else_.nodes if hasattr(node.else_, 'nodes') and node.else_.nodes else [], vul_function, back_node, vul_lineno, file_path, function_params)
        elif isinstance(node, (php.While, php.DoWhile, php.For, php.Foreach)):
            if hasattr(node, 'node') and hasattr(node.node, 'nodes'):
                _search_closures_for_analysis(node.node.nodes, vul_function, back_node, vul_lineno, file_path, function_params)


def _try_analyze_closure_body(closure_node, vul_function, back_node, vul_lineno, file_path, function_params):
    """如果 closure 的行号范围包含 vul_lineno，对其 body statements 运行 analysis()"""
    if scan_results:
        return
    if not isinstance(closure_node, php.Closure):
        return
    start = int(getattr(closure_node, 'lineno', 0))
    end = int(getattr(closure_node, 'end_lineno', start))
    if start <= int(vul_lineno) <= end:
        body = getattr(closure_node, 'nodes', None)
        if body:
            # 闭包参数作为 function_params 传入，使闭包参数被识别为局部变量
            closure_params = get_function_params(closure_node.params) if hasattr(closure_node, 'params') else None
            analysis(body, vul_function, back_node, vul_lineno, file_path,
                     function_params=closure_params or function_params)


def _init_function_summaries(file_path):
    """初始化 PHP 文件的函数摘要"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.function_summary import SummaryCacheManager
        from core.core_engine.php.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = ast_object
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, 'pre_result'):
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'php':
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
            logger.debug(f"[AST][PHP] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][PHP] 摘要初始化失败: {e}")


def _walk_php_ast_nodes(node, callback):
    """
    递归遍历 PHP AST 子树，对每个节点调用 callback(node)。

    PHP AST (lphply) 的子节点结构：
    - Block.nodes: 子语句列表
    - If.node: Block, If.else_: Else, Else.node: Block
    - Function.nodes/params, Echo.nodes
    - 各节点 fields 属性包含字段名列表
    """
    callback(node)

    # 优先处理已知的容器属性
    if hasattr(node, 'nodes') and isinstance(node.nodes, list):
        for child in node.nodes:
            if hasattr(child, 'lineno'):
                _walk_php_ast_nodes(child, callback)
    if hasattr(node, 'params') and isinstance(node.params, list):
        for child in node.params:
            if hasattr(child, 'lineno'):
                _walk_php_ast_nodes(child, callback)
    if hasattr(node, 'else_') and node.else_ is not None:
        _walk_php_ast_nodes(node.else_, callback)

    # 通用递归：遍历 fields 中值为节点或列表的属性
    if hasattr(node, 'fields') and isinstance(node.fields, list):
        for field_name in node.fields:
            if field_name in ('nodes', 'params', 'else_', 'fields'):
                continue
            try:
                child = getattr(node, field_name, None)
            except Exception:
                continue
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    if hasattr(item, 'lineno'):
                        _walk_php_ast_nodes(item, callback)
            elif hasattr(child, 'lineno'):
                _walk_php_ast_nodes(child, callback)


def find_sinks(sink_names, files):
    """
    AST-based sink 查找。遍历所有文件的 AST 节点，查找匹配的函数调用。
    支持直接调用匹配、间接调用检测和多层间接调用追踪（var_to_sink）。

    :param sink_names: list of SinkName(class_, method) from parse_sink_names()
    :param files: 文件路径列表
    :return: list of dict, 每项包含:
        - 'file_path': 文件路径
        - 'lineno': 行号
        - 'node': AST 调用节点
        - 'is_indirect': bool, 是否为间接调用
        - 'callee_name': str, 被调用函数名/方法名
        - 'class_name': str or None, 类名/对象名
        - 'matched_sink': SinkName or None, 匹配到的 sink 定义
        - 'callback_callee': Variable or None, 回调参数中的 callee
    """
    results = []

    # 构建 sink method 集合，用于快速判断字符串值是否为 sink
    sink_method_set = {s.method for s in sink_names}

    for file_path in files:
        # 将文件路径规范化为 pretreatment 中使用的完整路径
        file_path = ast_object.get_path(file_path)
        if not file_path:
            continue
        all_nodes = ast_object.get_nodes(file_path)
        if not all_nodes:
            continue

        # 第一遍：构建 var_to_sink_str 字典，追踪函数名赋值链
        var_to_sink_str = {}

        def _build_var_to_sink(node):
            if isinstance(node, php.Assignment):
                if isinstance(node.node, php.Variable):
                    left_name = node.node.name  # e.g. '$fn'
                    right = node.expr
                    if isinstance(right, php.Variable):
                        # $b = $a → 如果 $a 在映射中，继承
                        if right.name in var_to_sink_str:
                            var_to_sink_str[left_name] = var_to_sink_str[right.name]
                    elif isinstance(right, str):
                        # $fn = 'system' → 记录字符串值（去掉引号）
                        val = right.strip("'\"")
                        if val in sink_method_set:
                            var_to_sink_str[left_name] = val

        for top_node in all_nodes:
            _walk_php_ast_nodes(top_node, _build_var_to_sink)

        # 第二遍：匹配调用节点，使用 var_to_sink_str 解析间接调用
        def _on_call_node(node):
            if not isinstance(node, _FUNCTION_CALL_TYPES):
                return

            matched = _match_call_node(node, sink_names, var_to_sink_str)
            if matched:
                results.append({
                    'file_path': file_path,
                    'lineno': node.lineno,
                    'node': node,
                    'is_indirect': matched['is_indirect'],
                    'callee_name': matched['callee_name'],
                    'class_name': matched['class_name'],
                    'matched_sink': matched['matched_sink'],
                    'callback_callee': matched['callback_callee'],
                })

        for top_node in all_nodes:
            _walk_php_ast_nodes(top_node, _on_call_node)

    return results


def _match_call_node(node, sink_names, var_to_sink_str=None):
    """
    匹配单个调用节点与 sink_names 列表。

    :param node: FunctionCall / MethodCall / StaticMethodCall 节点
    :param sink_names: list of SinkName
    :param var_to_sink_str: dict {变量名: sink函数名字符串}，用于多层间接调用追踪
    :return: dict with match info, or None if no match
    """
    if var_to_sink_str is None:
        var_to_sink_str = {}

    is_indirect = False
    callee_name = None
    class_name = None
    callback_callee = None
    var_sink_match = None  # var_to_sink 解析出的匹配结果

    if isinstance(node, php.FunctionCall):
        if isinstance(node.name, str):
            callee_name = node.name
        elif isinstance(node.name, php.Variable):
            is_indirect = True
            callee_name = node.name.name

    elif isinstance(node, php.MethodCall):
        if isinstance(node.name, str):
            callee_name = node.name
        elif isinstance(node.name, php.Variable):
            is_indirect = True
            callee_name = node.name.name

        obj = node.node
        if isinstance(obj, php.Variable):
            class_name = obj.name
        elif hasattr(obj, 'name'):
            class_name = obj.name

    elif isinstance(node, php.StaticMethodCall):
        callee_name = node.name
        class_name = node.class_

    else:
        return None

    if not callee_name:
        return None

    # 多层间接调用追踪：检查 var_to_sink_str 解析变量对应的 sink
    if isinstance(node, php.FunctionCall) and isinstance(node.name, php.Variable):
        var_name = node.name.name  # e.g. '$b'
        if var_name in var_to_sink_str:
            sink_func_name = var_to_sink_str[var_name]
            for sink in sink_names:
                if sink.class_ is None and sink_func_name == sink.method:
                    var_sink_match = sink
                    break
    elif isinstance(node, php.MethodCall) and isinstance(node.name, php.Variable):
        var_name = node.name.name  # e.g. '$method'
        if var_name in var_to_sink_str:
            sink_func_name = var_to_sink_str[var_name]
            for sink in sink_names:
                if sink.class_ is None and sink_func_name == sink.method:
                    var_sink_match = sink
                    break

    # 回调间接调用检测 (call_user_func($func, $arg) 等)
    if not is_indirect and isinstance(node, php.FunctionCall) and isinstance(node.name, str):
        callback_funcs = {'call_user_func', 'call_user_func_array', 'array_map',
                          'usort', 'uasort', 'uksort', 'array_filter',
                          'array_walk', 'array_walk_recursive',
                          'register_shutdown_function', 'register_tick_function'}
        if node.name in callback_funcs and node.params:
            first_param = node.params[0]
            param_expr = first_param.node if hasattr(first_param, 'node') else first_param
            if isinstance(param_expr, php.Variable):
                is_indirect = True
                callback_callee = param_expr
            elif isinstance(param_expr, str):
                # 字符串字面量回调: call_user_func('system', $cmd)
                # 标记为间接调用，callback_callee 记录字符串值
                # scanner.py 会用 callback_callee 构造 indirect_map
                callback_func_name = param_expr.strip("'\"")
                if callback_func_name and any(s.method == callback_func_name for s in sink_names):
                    is_indirect = True
                    callback_callee = callback_func_name  # 字符串值（如 'system'）

    # var_to_sink 匹配优先返回：变量通过赋值链解析到具体 sink
    if var_sink_match:
        return {
            'is_indirect': True,
            'callee_name': callee_name,
            'class_name': class_name,
            'matched_sink': var_sink_match,
            'callback_callee': None,
        }

    # 匹配 sink_names
    for sink in sink_names:
        if is_indirect and not callback_callee:
            # 纯间接调用 $func() 或 $obj->$method()
            return {
                'is_indirect': True,
                'callee_name': callee_name,
                'class_name': class_name,
                'matched_sink': sink,
                'callback_callee': None,
            }

        if callback_callee:
            return {
                'is_indirect': True,
                'callee_name': callee_name,
                'class_name': class_name,
                'matched_sink': sink,
                'callback_callee': callback_callee,
            }

        if callee_name == sink.method:
            if sink.class_ is None:
                return {
                    'is_indirect': False,
                    'callee_name': callee_name,
                    'class_name': class_name,
                    'matched_sink': sink,
                    'callback_callee': None,
                }
            else:
                if class_name and class_name == sink.class_:
                    return {
                        'is_indirect': False,
                        'callee_name': callee_name,
                        'class_name': class_name,
                        'matched_sink': sink,
                        'callback_callee': None,
                    }

    return None


def _handle_indirect_call(all_nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path):
    """
    处理间接调用场景：在 AST 中定位 vul_lineno 处的 FunctionCall 节点，
    用 indirect_map 确认是间接调用后，提取参数做可控性分析。

    :param all_nodes: AST 节点列表（顶层）
    :param vul_lineno: 漏洞行号
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param file_path: 文件路径
    :return: list[dict] scan_results 格式的结果列表，或 None
    """
    global scan_results

    target_node = None

    def _find_at_line(node):
        nonlocal target_node
        if target_node is not None:
            return
        if not isinstance(node, _FUNCTION_CALL_TYPES):
            return
        if int(node.lineno) != int(vul_lineno):
            return
        if isinstance(node.name, php.Variable):
            var_name = node.name.name  # e.g. '$func'
            if var_name in indirect_map:
                target_node = node
        elif isinstance(node.name, str) and node.name in indirect_map:
            # 字符串 callee 间接调用: call_user_func('system', $cmd)
            target_node = node

    for top_node in all_nodes:
        _walk_php_ast_nodes(top_node, _find_at_line)
        if target_node is not None:
            break

    if target_node is None:
        return None

    # 提取参数做可控性分析
    func_params = get_all_functioncall_params(target_node)
    saved_results = list(scan_results)
    scan_results.clear()

    for param in func_params:
        if isinstance(param, php.Variable):
            back_node = []
            analysis_variable_node(param, back_node, None, vul_lineno, func_params, file_path=file_path)
            if scan_results:
                return scan_results

    scan_results.clear()
    scan_results.extend(saved_results)
    return None


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], svid=0, indirect_map=None):
    """
    开始检测函数
    :param svid:
    :param controlled_params:
    :param repair_functions:
    :param sensitive_func: 要检测的敏感函数,传入的为函数列表
    :param vul_lineno: 漏洞函数所在行号
    :param file_path: 文件路径
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :return:
    """
    try:
        global scan_results, is_repair_functions, is_controlled_params, scan_chain, _summaries_initialized

        _summaries_initialized = False
        _init_function_summaries(file_path)

        scan_chain = ['start']
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params
        _trace_cache.clear()
        all_nodes = ast_object.get_nodes(file_path)
        if not all_nodes or not isinstance(all_nodes, list):
            return []

        # Source Discovery: 首次调用时初始化
        global _source_registry
        if _source_registry is None:
            target_dir = ast_object.target_directory if hasattr(ast_object, 'target_directory') else ''
            if target_dir:
                _source_registry = discover_sources(target_dir, ast_object, controlled_list=controlled_params)

        # 间接调用快速路径
        if indirect_map and isinstance(indirect_map, dict):
            indirect_result = _handle_indirect_call(
                all_nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path
            )
            if indirect_result:
                return indirect_result

        for func in sensitive_func:  # 循环判断代码中是否存在敏感函数，若存在，递归判断参数是否可控;对文件内容循环判断多次
            back_node = []

            analysis(all_nodes, func, back_node, int(vul_lineno), file_path, function_params=None)

            # 如果检测到一次，那么就可以退出了
            if len(scan_results) > 0:

                # 记录newcore
                # if scan_results[0]['code'] == 4:
                #     nf = sync_to_async(NewEvilFunc(svid=svid, scan_task_id=SCAN_ID, func_name=scan_results[0]['source'][0].name,
                #                                    origin_func_name=func).save)
                #     nf()

                logger.debug("[AST] Scan parser end for {}".format(scan_results))
                break

    except Exception as e:
        logger.warning('[AST] [ERROR]:{e}'.format(e=traceback.format_exc()))

    return scan_results
