#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2019/7/5 17:37
# @Author  : LoRexxar
# @File    : parser.py
# @Contact : lorexxar@gmail.com


import os
import sys
import traceback

from esprima import nodes as jsnodes
from esprima.parser import SourceLocation, Position

from utils.log import logger
from core.pretreatment import ast_object

from core.core_engine.javascript.builtin_knowledge import KNOWLEDGE as JS_BUILTIN_KNOWLEDGE
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.javascript.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.javascript.summary_generator import lookup_summary
from core.core_engine.javascript.source_discovery import SourceRegistry, discover_sources

default_controlled_params = [
    'location.hash',
    'document.cookie',
    'location.search',
    'location.href',
    'window.name',

    # for chrome ext
    'chrome.tabs.query',
    'chrome.tabs.get',
    'chrome.tabs.getCurrent',
    'chrome.tabs.getSelected',
    'chrome.tabs.getAllInWindow',
    'chrome.runtime.onMessage.addListener',
    'chrome.runtime.onConnect.addListener',
    'chrome.runtime.onMessageExternal.addListener',
    'chrome.runtime.onConnectExternal.addListener',

    # for chrome
    'chrome.cookies.get',
    'chrome.cookies.getAll',

    # new api
    '.addEventListener',
    # 'location',

    # ===== Node.js: Express/Connect =====
    'req.query',
    'req.body',
    'req.params',
    'req.headers',
    'req.cookies',
    'req.files',
    'req.query.',
    'req.body.',
    'req.params.',
    'req.headers.',
    'req.cookies.',

    # ===== Node.js: Koa =====
    'ctx.query',
    'ctx.params',
    'ctx.request.body',
    'ctx.request.query',
    'ctx.request.header',
    'ctx.request.headers',
    'ctx.query.',
    'ctx.params.',
    'ctx.request.body.',
    'ctx.request.query.',

    # ===== Node.js: Hapi =====
    'request.query',
    'request.params',
    'request.payload',
    'request.headers',

    # ===== Node.js: Fastify =====
    'request.query',
    'request.body',
    'request.params',
    'request.headers',

    # ===== Node.js: process =====
    'process.env',
    # process.argv removed: CLI-only, not web-controllable

    # ===== Node.js: 原生 http =====
    'req.url',
    'req.method',
    'req.headers',
]

special_eval_function = [
    "eval",
    "setTimeout",
]

scan_results = []  # 结果存放列表初始化
is_repair_functions = []  # 修复函数初始化
is_controlled_params = []
scan_chain = []  # 回溯链变量

_trace_cache = TraceCache("javascript")
_source_registry = None

_summaries_initialized = False
_file_summaries = {}

# Class 属性映射：this.xxx = value，用于跨方法的 this 属性追踪
_this_prop_map = {}

# Class 方法参数映射：{method_name: {param_index: prop_name}}
# 当检测到 instance.method(arg) 调用时，把 arg 存入 _this_prop_map[prop_name]
_class_method_param_map = {}


def _resolve_js_module_path(module_path_str, base_dir):
    """解析 JS 模块路径字符串为实际文件路径

    支持相对路径 (./utils, ../helper) 的解析，不追踪 node_modules。
    返回 os.path.normpath(路径) 或 None。
    """
    # 不追踪 node_modules / @scope/pkg / 纯包名
    if not module_path_str.startswith('.') and not module_path_str.startswith('/'):
        return None

    full_path = os.path.join(base_dir, module_path_str)

    # 已有 .js 后缀直接用
    if full_path.endswith('.js'):
        if os.path.isfile(full_path):
            return os.path.normpath(full_path)
        return None

    # 尝试 .js 后缀
    candidate = full_path + '.js'
    if os.path.isfile(candidate):
        return os.path.normpath(candidate)

    # 尝试 /index.js
    candidate = os.path.join(full_path, 'index.js')
    if os.path.isfile(candidate):
        return os.path.normpath(candidate)

    return None


def _parse_js_imports(all_nodes, file_path):
    """解析 esprima AST 中的 require/import 语句

    参数:
        all_nodes: esprima 解析后的 AST 根节点（Program 节点）
        file_path: 当前文件路径

    返回:
        { imported_name: module_file_path } 映射
    """
    import_map = {}
    base_dir = os.path.dirname(file_path)

    def _collect(node):
        node_type = getattr(node, 'type', None)

        # ESM: import { run } from './utils'
        if node_type == 'ImportDeclaration':
            source = getattr(node, 'source', None)
            if source and getattr(source, 'type', None) in ('Literal', 'StringLiteral') and isinstance(source.value, str):
                module_path = _resolve_js_module_path(source.value, base_dir)
                if module_path:
                    for spec in (node.specifiers or []):
                        spec_type = getattr(spec, 'type', None)
                        if spec_type in ('ImportSpecifier', 'ImportDefaultSpecifier', 'ImportNamespaceSpecifier'):
                            local_name = getattr(spec.local, 'name', None)
                            if local_name:
                                import_map[local_name] = module_path
            return

        # CommonJS: const/let/var x = require('./utils')
        if node_type == 'VariableDeclaration':
            for declarator in (node.declarations or []):
                if getattr(declarator, 'type', None) != 'VariableDeclarator':
                    continue
                init = getattr(declarator, 'init', None)
                if init is None:
                    continue

                # 提取 require() 的字符串参数
                require_arg = None
                init_type = getattr(init, 'type', None)

                if init_type == 'CallExpression':
                    callee = getattr(init, 'callee', None)
                    if (getattr(callee, 'type', None) == 'Identifier' and
                            getattr(callee, 'name', None) == 'require'):
                        args = getattr(init, 'arguments', [])
                        if (args and getattr(args[0], 'type', None) in ('Literal', 'StringLiteral') and
                                isinstance(args[0].value, str)):
                            require_arg = args[0].value

                elif init_type == 'MemberExpression':
                    # const fn = require('./utils').run
                    obj = getattr(init, 'object', None)
                    if obj and getattr(obj, 'type', None) == 'CallExpression':
                        callee = getattr(obj, 'callee', None)
                        if (getattr(callee, 'type', None) == 'Identifier' and
                                getattr(callee, 'name', None) == 'require'):
                            args = getattr(obj, 'arguments', [])
                            if (args and getattr(args[0], 'type', None) in ('Literal', 'StringLiteral') and
                                    isinstance(args[0].value, str)):
                                require_arg = args[0].value

                if require_arg is None:
                    continue

                module_path = _resolve_js_module_path(require_arg, base_dir)
                if module_path is None:
                    continue

                # 提取变量名
                var_id = declarator.id
                var_id_type = getattr(var_id, 'type', None)

                if var_id_type == 'Identifier':
                    import_map[var_id.name] = module_path
                elif var_id_type == 'ObjectPattern':
                    for prop in (getattr(var_id, 'properties', None) or []):
                        key = getattr(prop, 'key', None)
                        if key and getattr(key, 'type', None) == 'Identifier':
                            import_map[key.name] = module_path

    _walk_ast_nodes(all_nodes, _collect)
    return import_map


def _build_js_func_index(all_nodes, file_path):
    """构建单个文件的函数索引

    参数:
        all_nodes: esprima AST 根节点（Program 节点或 body 列表）
        file_path: 当前文件路径

    返回:
        {func_name: [func_node]} 字典
    """
    func_index = {}

    def _add_func(name, node):
        if name:
            func_index.setdefault(name, []).append(node)

    # 获取顶层节点列表
    if hasattr(all_nodes, 'type') and all_nodes.type == 'Program':
        top_nodes = all_nodes.body or []
    elif isinstance(all_nodes, list):
        top_nodes = all_nodes
    else:
        return func_index

    for node in top_nodes:
        if not hasattr(node, 'type'):
            continue
        node_type = node.type

        # a) FunctionDeclaration
        if node_type == 'FunctionDeclaration':
            if hasattr(node, 'id') and node.id:
                func_name = get_member_data(node.id)
                _add_func(func_name, node)
            continue

        # b) VariableDeclarator + FunctionExpression/ArrowFunctionExpression
        if node_type == 'VariableDeclaration':
            for declarator in (node.declarations or []):
                if getattr(declarator, 'type', None) != 'VariableDeclarator':
                    continue
                init = getattr(declarator, 'init', None)
                if init is None:
                    continue
                init_type = getattr(init, 'type', None)
                if init_type not in ('FunctionExpression', 'ArrowFunctionExpression'):
                    continue
                var_id = getattr(declarator, 'id', None)
                if var_id and getattr(var_id, 'type', None) == 'Identifier':
                    _add_func(var_id.name, declarator)
            continue

        # c) ExpressionStatement 层级的处理
        if node_type == 'ExpressionStatement':
            expr = getattr(node, 'expression', None)
            if expr is None or getattr(expr, 'type', None) != 'AssignmentExpression':
                continue

            left = expr.left
            right = expr.right
            left_type = getattr(left, 'type', None)
            right_type = getattr(right, 'type', None)

            is_func = right_type in ('FunctionExpression', 'ArrowFunctionExpression')

            # c) 简单赋值: run = function() { ... }
            if is_func and left_type == 'Identifier':
                _add_func(left.name, expr)

            # d) module.exports.run / exports.run
            elif is_func and left_type == 'MemberExpression':
                full_name = get_member_data(left)
                # 提取最后一段作为函数名
                short_name = full_name.rsplit('.', 1)[-1] if '.' in full_name else full_name
                _add_func(short_name, expr)
                _add_func(full_name, expr)

            # e) module.exports = { run(cmd) { ... } } ObjectExpression
            elif getattr(right, 'type', None) == 'ObjectExpression':
                for prop in (getattr(right, 'properties', None) or []):
                    prop_type = getattr(prop, 'type', None)
                    is_method = False

                    if prop_type == 'ObjectMethod':
                        is_method = True
                    elif prop_type in ('Property',):
                        prop_val = getattr(prop, 'value', None)
                        if prop_val and getattr(prop_val, 'type', None) in (
                                'FunctionExpression', 'ArrowFunctionExpression'):
                            is_method = True

                    if is_method:
                        prop_key = getattr(prop, 'key', None)
                        if prop_key:
                            method_name = get_member_data(prop_key)
                            _add_func(method_name, prop)

    return func_index


def _find_js_func_def(func_name, import_map, ast_object_global):
    """在跨文件场景中查找被 import 模块的函数定义

    参数:
        func_name: 要查找的函数名字符串
        import_map: _parse_js_imports() 返回的 {name: file_path} 映射
        ast_object_global: 全局 ast_object（用于 ast_object.get_nodes()）

    返回:
        找到的 func_node 或 None
    """
    if not func_name or not import_map:
        return None

    # 尝试从 import_map 中找到对应的模块文件
    imported_path = None
    local_func_name = func_name

    # 1. 直接匹配 func_name
    if func_name in import_map:
        imported_path = import_map[func_name]
    else:
        # 2. 尝试匹配前缀：例如 utils.run → 查找 utils 对应的模块
        #    然后在模块中查找 run 函数
        parts = func_name.rsplit('.', 1)
        if len(parts) == 2:
            obj_name, method_name = parts
            if obj_name in import_map:
                imported_path = import_map[obj_name]
                local_func_name = method_name

    if imported_path is None:
        return None

    # 获取被 import 文件的 AST
    try:
        result = ast_object_global.get_nodes(imported_path, lan='javascript')
    except Exception:
        return None

    if result is None:
        return None

    # 获取 AST body
    if hasattr(result, 'body'):
        all_nodes = result
    else:
        return None

    # 构建函数索引并查找
    func_index = _build_js_func_index(all_nodes, imported_path)

    # 查找函数：尝试多种名字
    for name in (local_func_name, func_name):
        if name in func_index:
            return func_index[name][0]

    return None


def _try_cross_file_trace_js(all_nodes, vul_lineno, sensitive_func, file_path,
                             import_map, controlled_params=None):
    """跨文件追踪：当单文件扫描未找到漏洞时，检查目标行调用的函数是否来自其他文件的 import，
    如果是，在被 import 文件中查找函数定义，检查内部是否调用了敏感 sink，并判断调用处实参是否可控。

    参数:
        all_nodes: 当前文件的 AST 节点列表（esprima Program.body）
        vul_lineno: 漏洞行号
        sensitive_func: 规则敏感函数列表（函数名字符串列表）
        file_path: 当前文件路径
        import_map: _parse_js_imports() 返回的 {name: file_path} 映射
        controlled_params: 可控参数列表（默认 None）

    返回:
        [{...}] — 找到漏洞，与 scan_results 格式一致
        None — 无法跨文件追踪
    """
    # 读取源文件行内容
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_lines = f.readlines()
    except Exception:
        source_lines = []

    # 第1步：找到目标行的所有 CallExpression
    target_calls = []
    def _collect_calls(node):
        if hasattr(node, 'type') and node.type == 'CallExpression':
            if hasattr(node, 'loc') and node.loc and node.loc.start.line == vul_lineno:
                callee_name, _ = _extract_call_name_js(node)
                if callee_name:
                    target_calls.append((callee_name, node))
    for n in all_nodes:
        _walk_ast_nodes(n, _collect_calls)

    if not target_calls:
        return None

    # 第2步：对每个调用检查是否来自 import_map
    for callee_name, call_node in target_calls:
        imported_path = None
        local_func_name = callee_name

        # 直接匹配
        if callee_name in import_map:
            imported_path = import_map[callee_name]
        else:
            # 前缀匹配：callee_name.split('.')[0] in import_map
            parts = callee_name.split('.', 1)
            if len(parts) == 2 and parts[0] in import_map:
                imported_path = import_map[parts[0]]
                local_func_name = parts[1]

        if not imported_path:
            continue

        # 第3步：在被 import 文件中查找函数定义
        try:
            module_nodes = ast_object.get_nodes(imported_path, lan='javascript')
        except Exception:
            continue
        if module_nodes is None or not hasattr(module_nodes, 'body'):
            continue

        func_index = _build_js_func_index(module_nodes, imported_path)
        func_def = None
        for name in (local_func_name, callee_name):
            if name in func_index:
                func_def = func_index[name][0]
                break
        if not func_def:
            return None

        # 第4步：检查函数内部是否有敏感 sink
        func_body_nodes = []
        func_type = getattr(func_def, 'type', None)
        if func_type in ('FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'):
            func_body = getattr(func_def, 'body', None)
            if func_body:
                if hasattr(func_body, 'body'):
                    func_body_nodes = func_body.body
                elif isinstance(func_body, list):
                    func_body_nodes = func_body
        elif func_type in ('ObjectMethod', 'Property'):
            func_value = getattr(func_def, 'value', None)
            if func_value:
                func_value_body = getattr(func_value, 'body', None)
                if func_value_body:
                    if hasattr(func_value_body, 'body'):
                        func_body_nodes = func_value_body.body
                    elif isinstance(func_value_body, list):
                        func_body_nodes = func_value_body

        if not func_body_nodes:
            return None

        inner_sink_found = False
        def _check_inner_sink(node):
            nonlocal inner_sink_found
            if inner_sink_found:
                return
            if not hasattr(node, 'type') or node.type != 'CallExpression':
                return
            inner_name, _ = _extract_call_name_js(node)
            if not inner_name:
                return
            for sf in sensitive_func:
                if inner_name == sf or inner_name.endswith('.' + sf):
                    inner_sink_found = True
                    return
            knowledge = lookup_builtin(inner_name)
            if knowledge and not knowledge.get("safe") and knowledge.get("passthrough"):
                inner_sink_found = True
                return

        for body_node in func_body_nodes:
            _walk_ast_nodes(body_node, _check_inner_sink)

        if not inner_sink_found:
            return None

        # 第5步：检查调用处实参是否可控
        call_args = getattr(call_node, 'arguments', []) or []
        for arg in call_args:
            # 直接检查可控性
            is_co, cp = is_controllable(arg)
            if is_co == 1:
                source_line_content = source_lines[vul_lineno - 1].strip() if vul_lineno <= len(source_lines) else callee_name
                return [{
                    "code": 1,
                    "chain": ["{}:{}".format(vul_lineno, source_line_content)],
                    "source": cp
                }]

            # Identifier 类型，调用 parameters_back 反向追踪
            if hasattr(arg, 'type') and arg.type == 'Identifier':
                is_co2, cp2, expr_lineno2 = parameters_back(
                    arg, all_nodes, function_params=None, lineno=vul_lineno,
                    function_flag=0, vul_function=None, file_path=file_path)
                if is_co2 == 1:
                    source_line_num = expr_lineno2 if expr_lineno2 else vul_lineno
                    source_line_content = source_lines[source_line_num - 1].strip() if source_line_num <= len(source_lines) else callee_name
                    return [{
                        "code": 1,
                        "chain": ["{}:{}".format(source_line_num, source_line_content)],
                        "source": cp2
                    }]

            # CallExpression 嵌套调用，尝试用摘要判断
            if hasattr(arg, 'type') and arg.type == 'CallExpression':
                inner_callee, _ = _extract_call_name_js(arg)
                if inner_callee:
                    callee_summary = lookup_summary(inner_callee)
                    if callee_summary and callee_summary.return_flow:
                        summary_result = _judge_from_summary_js(callee_summary, getattr(arg, 'arguments', []) or [])
                        if summary_result is not None and summary_result[0] == 1:
                            source_line_content = source_lines[vul_lineno - 1].strip() if vul_lineno <= len(source_lines) else callee_name
                            return [{
                                "code": 1,
                                "chain": ["{}:{}".format(vul_lineno, source_line_content)],
                                "source": summary_result[1]
                            }]

    return None


def get_member_data(node, check=False, isparam=False, isclean_prototype=False, isreverse=False):
    if hasattr(node, "type"):
        type = node.type
        value = node

        if type == "Identifier":
            value = node.name
            # if check:
            #     value = 1

        if type == "Literal":  # 数组位移
            value = node.value
            if check:
                value = "1"

            if isreverse:
                value = node.value[::-1]

        elif type == "StringLiteral":  # esprima Property key (e.g. { 'cmd': x })
            value = node.value
            if check:
                value = "1"

        elif type == "MemberExpression":
            data_object = get_member_data(node.object, isclean_prototype=isclean_prototype)
            data_property = get_member_data(node.property, isclean_prototype=isclean_prototype)

            if isparam:
                value = data_object
            else:
                value = "{}.{}".format(data_object, data_property)

            if isclean_prototype:
                if data_property == "prototype":
                    value = ""

        elif type == "AssignmentExpression":
            data_left = get_member_data(node.left, isclean_prototype=isclean_prototype)
            data_right = get_member_data(node.right, isclean_prototype=isclean_prototype)

            if isparam:
                value = data_left
            else:
                value = str(data_left) + "." + str(data_right)

        elif type == "CallExpression":
            value = get_member_data(node.callee, isclean_prototype=isclean_prototype)

        elif type == "ThisExpression":
            value = "this"

        elif type == "ObjectExpression":
            value = " { "
            for i in node.properties:
                value += get_member_data(i.key, isclean_prototype=isclean_prototype)
                value += ", "

            value += " } "

        elif type == "BinaryExpression":
            value = ""

            if node.operator == "+":
                data_left = get_member_data(node.left, check=True, isclean_prototype=isclean_prototype)
                data_right = get_member_data(node.right, check=True, isclean_prototype=isclean_prototype)

                if data_left != "1":
                    value = data_left
                if data_right != "1" and value:
                    value = str(value) + " + " + str(data_right)
                if data_right != "1" and not value:
                    value = data_right

        elif type == "NewExpression":
            callee_name = get_member_data(node.callee)

            value = "New {}".format(callee_name)

            if isparam:
                value = callee_name

        elif type == "FunctionExpression":
            function_name = get_member_data(node.id) if node.id else "tmpfunc"

            value = "{}()".format(function_name)

    elif isinstance(node, list):
        valuelist = []

        for i in node:
            valuelist.append(get_member_data(i, isclean_prototype=isclean_prototype))

        value = valuelist
    else:
        value = node

    return value


def get_param(param, is_eval=False, is_function_regex=False):
    param_list = []
    type = param.type

    if type == "Identifier":
        param_list.append(param.name)

    elif type == "Literal" or type in ("StringLiteral", "NumericLiteral", "BooleanLiteral", "RegExpLiteral", "NullLiteral", "TemplateLiteral"):
        if is_eval:
            if type == "TemplateLiteral":
                # TemplateLiteral has quasis (static parts) and expressions
                param_list.append(param.quasis[0].value.raw if param.quasis else '')
            else:
                param_list.append(param.value)

    elif type == "BinaryExpression":
        left = get_param(param.left, is_eval)
        right = get_param(param.right, is_eval)

        param_list.extend(left)
        param_list.extend(right)

    elif type == "CallExpression":
        call_function = get_member_data(param.callee, isparam=True)

        if is_function_regex and call_function not in special_eval_function:
            params = [param.callee]

        else:
            if call_function in special_eval_function:
                params = get_param_list(param.arguments, is_eval=True)
            else:
                params = get_param_list(param.arguments, is_eval)

        param_list.extend(params)

    elif type == "MemberExpression":
        data_object = get_member_data(param.object)
        data_property = get_member_data(param.property)

        value = str(data_object) + "." + str(data_property)
        param_list.append(value)

    return param_list


def get_param_list(params, is_eval=False, is_function_regex=False):
    param_list = []

    for param in params:
        param_list.extend(get_param(param, is_eval, is_function_regex))

    return param_list


def get_original_object(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return get_original_object(node.object)

        return node
    return get_member_data(node)


def get_property_object(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return get_property_object(node.property)

    return get_member_data(node)


def set_original_object(node, object_name):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            node.object = object_name
            return node

    node = object_name
    return node


def set_property_object(node, object_name):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            node.property = object_name
            return node

        if node.type == "AssignmentExpression":
            node.right = object_name
            return node

    node = object_name
    return node


def generate_memberexp(object, property, vul_lineno=0):
    if hasattr(object, "type"):
        new_member_object = object
    else:
        new_member_object = jsnodes.Identifier(object)
        new_member_object.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    if hasattr(property, "type"):
        new_member_property = property
    else:
        new_member_property = jsnodes.Identifier(property)
        new_member_property.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    new_param = jsnodes.ComputedMemberExpression(new_member_object, new_member_property)
    new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    return new_param


def is_memberexp(node):
    if hasattr(node, "type"):
        if node.type == "MemberExpression":
            return True


def is_thisexp(node):
    if hasattr(node.object, "type"):
        # member的this
        if node.object.type == "ThisExpression":
            return True


def is_vul_function(node, vul_function):
    """
    判断该调用是否为目标漏洞函数
    :param node: 
    :param vul_function: 
    :return: 
    """
    node_type = node.type

    if node_type == "MemberExpression":
        return get_member_data(node) == vul_function

    if node_type == "CallExpression":
        return get_member_data(node) == vul_function


def is_eval_function(node):
    eval_functions = ['eval', 'setTimeout']

    if hasattr(node, "type") and node.type == "CallExpression":
        return get_member_data(node) in eval_functions

    return False


def is_controllable(param):
    """
    判断参数是否为可控
    
    -1 为不可控
    1 为可控
    2 为已修复
    3 为未知，即仍未变量
    4 为新函数规则生成
    
    :param param: 
    :return: 
    """
    global is_controlled_params

    is_co = 3
    real_param = get_member_data(param, True)

    # 首先需要合并下
    controlled_params = is_controlled_params + default_controlled_params

    # 检查常量
    if real_param == 1:
        is_co = -1
        real_param = param

    for controlled_param in controlled_params:
        if controlled_param in str(real_param):
            is_co = 1

    return is_co, param


def check_param(param, vul_lineno=0):
    """
    检查自定义匹配的变量类型，想办法生成相应的结构
    :param vul_lineno: 
    :param param: 
    :return: 
    """
    new_param = param

    if "." in param:
        # Member in param
        logger.debug("New MemberExpression from {}".format(param))
        params = param.split('.')
        param_object = params[0]
        param_property = ".".join(params[1:])

        new_param_object = jsnodes.Identifier(param_object)
        new_param_object.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

        new_param_property = check_param(param_property)

        new_param = jsnodes.ComputedMemberExpression(new_param_object, new_param_property)
        new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    elif not hasattr(param, "type"):
        new_param = jsnodes.Identifier(param)
        new_param.loc = SourceLocation(start=Position(line=vul_lineno), end=Position(line=vul_lineno))

    return new_param


def _collect_js_var_names(node, names=None):
    """递归收集 JS AST 节点中的所有变量名（Identifier 类型）"""
    if names is None:
        names = set()
    if node is None:
        return names
    if hasattr(node, 'type'):
        if node.type == 'Identifier':
            names.add(node.name)
        elif node.type == 'MemberExpression':
            _collect_js_var_names(node.object, names)
            _collect_js_var_names(node.property, names)
        elif node.type == 'CallExpression':
            _collect_js_var_names(node.callee, names)
            for arg in (node.arguments or []):
                _collect_js_var_names(arg, names)
        elif node.type == 'BinaryExpression':
            _collect_js_var_names(node.left, names)
            _collect_js_var_names(node.right, names)
        elif node.type == 'UnaryExpression':
            _collect_js_var_names(node.argument, names)
        elif node.type == 'ConditionalExpression':
            _collect_js_var_names(node.test, names)
            _collect_js_var_names(node.consequent, names)
            _collect_js_var_names(node.alternate, names)
        elif node.type == 'LogicalExpression':
            _collect_js_var_names(node.left, names)
            _collect_js_var_names(node.right, names)
        elif node.type == 'AssignmentExpression':
            _collect_js_var_names(node.left, names)
            _collect_js_var_names(node.right, names)
        elif node.type == 'ArrayExpression':
            for elem in (node.elements or []):
                if elem:
                    _collect_js_var_names(elem, names)
        elif node.type == 'ObjectExpression':
            for prop in (node.properties or []):
                if hasattr(prop, 'value') and prop.value:
                    _collect_js_var_names(prop.value, names)
        elif node.type == 'SequenceExpression':
            for expr in (node.expressions or []):
                _collect_js_var_names(expr, names)
        elif node.type == 'TemplateLiteral':
            for expr in (node.expressions or []):
                _collect_js_var_names(expr, names)
        elif node.type == 'SpreadElement':
            _collect_js_var_names(node.argument, names)
        # 对于 FunctionExpression / FunctionDeclaration / ArrowFunctionExpression，
        # 不深入其 body，避免收集函数内部定义的局部变量名
    elif isinstance(node, list):
        for item in node:
            _collect_js_var_names(item, names)
    return names


def function_back(function_node, function_params, back_nodes=None, file_path=None, isback=False, vul_function=None, method_name=None,
                  iscall=False):
    """
    用于回溯参数为函数变量的时候，使用 deps 机制避免函数体内的循环递归。
    不在函数体内调用 parameters_back，而是分析 return 表达式依赖哪些形参，
    返回 ('deps', [形参名字符串列表], lineno) 由外层映射为调用者实参。
    
    :param function_params:
    :param back_nodes:
    :param iscall:
    :param method_name: 
    :param vul_function: 
    :param function_node: 
    :param file_path: 
    :param isback: 
    :return: (is_co, cp, expr_lineno)
        is_co=1: 返回值直接可控
        is_co=4: 依赖形参，cp 为形参名列表（来自 iscall=True 时）
        ('deps', [形参名列表], lineno): 依赖形参，由外层映射实参
        is_co=3: 未确认
    """
    function_body = function_node.body.body
    function_name = get_member_data(function_node.id) if get_member_data(function_node.id) else "tmpfunc"
    function_lineno = function_node.loc.start.line
    function_params = function_params if function_params else function_node.params

    is_co = 3
    cp = "Function()"
    expr_lineno = 0

    logger.debug("[AST] Sounds like found a new function define {}".format(function_name))

    # 查内置知识库
    knowledge = lookup_builtin(function_name)
    if knowledge:
        if knowledge["safe"] and not knowledge["passthrough"]:
            return -1, "Function()", 0
        if knowledge["passthrough"]:
            # function_back 接收的是函数定义节点，不知道调用处实参
            # 返回形参名让外层映射
            formal_params = [get_member_data(p) for p in function_params]
            deps_formal = []
            for idx in knowledge["passthrough"]:
                if idx < len(formal_params):
                    deps_formal.append(formal_params[idx])
            if deps_formal:
                return ('deps', deps_formal, function_lineno)
        return -1, "Function()", 0

    # Source Discovery check: user-defined source producer
    global _source_registry
    if _source_registry is not None:
        source_info = _source_registry.is_source_producer(function_name)
        if source_info:
            logger.debug('[AST] Source Discovery: {0} is a source producer ({1})'.format(function_name, source_info.origin))
            return 1, function_node, 0

    # 寻找函数体中的 ReturnStatement
    return_node = None
    for node in function_body[::-1]:
        if hasattr(node, "type") and node.type == "ReturnStatement":
            return_node = node
            param = node.argument

            # 当返回包含this时，继续分析已经没有意义了
            if get_member_data(get_original_object(param)) == "this":
                logger.debug("[AST] Function return self.method {}, back to ast object.".format(get_member_data(param)))

                is_co = 3
                cp = param
                expr_lineno = node.loc.start.line
                return is_co, cp, expr_lineno

            break

    if return_node is None:
        # 没有 return 语句
        return is_co, cp, expr_lineno

    param = return_node.argument
    expr_lineno = return_node.loc.start.line

    # 1. 检查 return 表达式是否直接可控
    is_co, cp = is_controllable(param)
    if is_co == 1:
        return is_co, cp, expr_lineno

    # 2. 收集 return 表达式中引用的所有变量名
    var_names = _collect_js_var_names(param)

    # 3. 获取函数形参名字符串列表
    formal_param_names = []
    for p in function_params:
        formal_param_names.append(get_member_data(p))

    # 4. 找出 return 表达式引用的变量中哪些匹配函数形参
    matched_params = []
    for vn in var_names:
        if vn in formal_param_names:
            matched_params.append(vn)

    if matched_params:
        logger.debug("[AST] Function {} return depends on params: {}".format(function_name, matched_params))

        if iscall:
            # 来自 call 的 function 分析，返回 code=4 格式（向后兼容）
            # 使用第一个匹配的形参作为 cp（保持与原逻辑兼容）
            is_co = 4
            # cp 保留原始 AST 节点引用，以便外层通过 get_member_data 获取形参名
            # 这里返回形参名字符串
            cp = matched_params[0]
            return is_co, cp, expr_lineno

        # 非 iscall 场景：生成新函数规则
        logger.debug("[AST] New Function {} rules to regex".format(function_name))
        file_path = os.path.normpath(file_path)
        code = "param {} in NewFunction {}".format(cp, function_name)
        scan_chain.append(('NewFunction', code, file_path, function_lineno))

        is_co = 4
        cp = tuple([function_node.id, cp, vul_function])
        return is_co, cp, 0

    # 5. 没有匹配形参，返回 deps 由外层继续向上追踪
    #    把所有引用的变量名作为 deps 返回
    if var_names:
        logger.debug("[AST] Function {} return depends on vars: {}, returning deps".format(function_name, list(var_names)))
        return 'deps', list(var_names), expr_lineno

    return is_co, cp, expr_lineno


def member_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None, method_name=None):
    """
    用于回溯参数为类变量时，需要保留类方法并回溯类获取方法函数返回
    :param method_name: 
    :param vul_function: 
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :return: 
    """
    global scan_chain

    param_name = get_member_data(param)
    expr_lineno = param.loc.start.line
    param_object = get_original_object(param)
    param_property = get_property_object(param)

    # 由于涉及到私有变量，暂时还没别的办法，先把this返回了吧
    if param_object == "this":
        is_co = 3
        cp = param
        expr_lineno = param.loc.start.line

        return is_co, cp, expr_lineno

    # 首先把类变量名作为正常的分析过程置入parameters_back
    is_co, cp, expr_lineno = parameters_back(param_object, nodes, function_params, file_path=file_path, isback=True,
                                             vul_function=vul_function, method_name=param_property)

    if is_co == 3 and hasattr(cp, "type") and cp.type == "ObjectExpression":
        # 获取的右值为类变量的声明（暂写死
        properties = cp.properties

        for property in properties:
            property_key = get_member_data(property.key)

            if property_key == param_property:
                property_value = property.value

                logger.debug("[AST] AST into Object and find method {}".format(param_property))

                file_path = os.path.normpath(file_path)
                code = "find object method {} define".format(param_property)
                scan_chain.append(('ObjectProperty', code, file_path, property.key.loc.start.line))

                is_co, cp = is_controllable(property_value)

                # 这里干脆单独处理下function好咯
                if property_value.type == "FunctionExpression":
                    function_params = property_value.params

                    is_co, cp, expr_lineno = function_back(property_value, function_params, back_nodes=nodes, file_path=file_path,
                                                           isback=isback, vul_function=vul_function,
                                                           method_name=method_name)

                    # deps 处理：返回值依赖某些变量，跳过当前节点
                    if isinstance(is_co, str) and is_co == 'deps':
                        logger.debug("[AST] member_back function_back returns deps: {}, skip current node".format(cp))
                        return 3, param, expr_lineno

                    if is_co == 3:
                        property_value = cp

                if property_value.type == "MemberExpression" and get_member_data(get_original_object(property_value)) == "this":
                    # 如果是this则回去找找看
                    param_self_key = get_property_object(property_value)

                    for property2 in properties:
                        property2_key = get_member_data(property2.key)

                        if property2_key == param_self_key:
                            property2_value = property2.value

                            logger.debug("[AST] Find object self var {}={}".format(property2_key,
                                                                                   get_member_data(property2_value)))

                            file_path = os.path.normpath(file_path)
                            code = "Find object self var {}={}".format(property2_key, get_member_data(property2_value))
                            scan_chain.append(('ObjectSelfAss', code, file_path, property.key.loc.start.line))

                            is_co, cp = is_controllable(property2_value)
                            return is_co, cp, expr_lineno

    if isback:
        cp = param

    return is_co, cp, expr_lineno


def new_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None, method_name=None):
    """
    用于解决右值为new时，
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :param vul_function: 
    :param method_name: 
    :return: 
    """
    object_name = get_member_data(param, isparam=True)
    evil_method = method_name

    is_co = 3
    cp = param
    expr_lineno = param.loc.start.line

    # new 只要回溯寻找两种可能
    # function x(){}
    # x.evil_method =
    for node in nodes[::-1]:
        if node.type == "FunctionDeclaration" and get_member_data(node.id) == object_name:
            function_body = node.body.body

            # function 不会将属性映射出来
            # is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, file_path=file_path, isback=isback,
            #                                          vul_function=vul_function, method_name=method_name)

        if node.type == "ExpressionStatement":  # 赋值操作
            expression = node.expression

            if expression.type == "AssignmentExpression" and expression.operator == "=":
                if expression.left.type == "MemberExpression":
                    # 左值为object.prototype
                    member_object = expression.left.object
                    member_property = expression.left.property
                    member_right = expression.right

                    if get_member_data(expression.left) == "{}.prototype".format(object_name):
                        # 对象重载
                        logger.debug(
                            "[AST] object {} parent class transfer to object {}...".format(object_name, get_member_data(
                                member_right)))

                        logger.debug(
                            "[AST] Find {}={} in line {}".format(get_member_data(expression.left),
                                                                 get_member_data(member_right),
                                                                 expression.loc.start.line))

                        file_path = os.path.normpath(file_path)
                        code = "{}={}".format(get_member_data(expression.left), get_member_data(member_right))
                        scan_chain.append(('Assignment', code, file_path, expression.loc.start.line))

                        param = member_right

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params,
                                                                 vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)

                        return is_co, cp, expr_lineno

                    if get_member_data(member_object) == "{}.prototype".format(object_name) and get_member_data(
                            member_property) == evil_method:
                        # 对象父类属性修改

                        logger.debug(
                            "[AST] object {} parent class method {} is modified...".format(object_name, evil_method))

                        logger.debug(
                            "[AST] Find {}={} in line {}".format(get_member_data(expression.left),
                                                                 get_member_data(member_right),
                                                                 expression.loc.start.line))

                        file_path = os.path.normpath(file_path)
                        code = "{}={}".format(get_member_data(expression.left), get_member_data(member_right))
                        scan_chain.append(('Assignment', code, file_path, expression.loc.start.line))

                        param = member_right

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params,
                                                                 vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)

                        return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno


def function_call_back(param, nodes, function_params, file_path=None, isback=False, vul_function=None,
                       method_name=None):
    """
    CallExpression back analysize
    :param method_name: 
    :param param: 
    :param nodes: 
    :param function_params: 
    :param file_path: 
    :param isback: 
    :param vul_function: 
    :return: 
    """
    is_co, cp = is_controllable(param)
    expr_lineno = param.loc.start.line

    callee_name = get_member_data(param.callee)
    lineno = param.loc.start.line
    expression = param.callee

    # 额外处理一种神奇的调用思路
    # function (a) {return self.b(a)}

    if callee_name == vul_function or callee_name == "this.{}".format(vul_function) or (callee_name.split(".")[-1] == vul_function.split(".")[-1]):
        callee_params = param.arguments

        logger.debug("[AST] call param from self object method {}".format(callee_name))

        # 恶意函数调用
        for param in callee_params:
            is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                     function_flag=0, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=True, method_name=method_name)
            return is_co, cp, expr_lineno

    elif expression.type == "FunctionExpression":
        # 这个分支代表处理在js中特有的一种常见语义结构
        # (function(a){return a})(c)
        # 闭包
        callee = expression
        callee_body = callee.body.body
        callee_params = callee.params

        logger.debug("[AST] param is Closure FunctionCall in line {}".format(callee.loc.start.line))

        file_path = os.path.normpath(file_path)
        code = "param in Closure FunctionCall"
        scan_chain.append(('TmpFunctionCall', code, file_path, callee.loc.start.line))

        for callee_node in callee_body:

            if callee_node.type == "ReturnStatement":
                param = callee_node.argument

                is_co, cp, expr_lineno = parameters_back(param, callee_body, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                if is_co == 3:

                    for callee_param in callee_params:
                        if get_member_data(callee_param) == cp:
                            expression_arguments = expression.arguments
                            param = expression_arguments[callee_params.index(callee_param)]

                            logger.debug(
                                "[AST] param {} line {} in function params, param transfer to param of Closure Function {}".format(
                                    get_member_data(cp), expr_lineno, get_member_data(param)))

                            file_path = os.path.normpath(file_path)
                            code = "New param {} out from Closure function".format(get_member_data(param))
                            scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                     function_flag=0, vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=isback, method_name=method_name)
                            return is_co, cp, expr_lineno

                is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                return is_co, cp, expr_lineno

    elif expression.type == "MemberExpression":
        # call 后为member目前是特殊语法
        # 原理为调用了某个对象的属性函数，目前只见过"a".split()
        expression_object = expression.object
        expression_property = expression.property

        method_name = get_member_data(expression_property)

        if method_name in JS_BUILTIN_KNOWLEDGE and "this" in JS_BUILTIN_KNOWLEDGE.get(method_name, {}).get("passthrough", []):
            logger.debug(
                "[AST] param {} use internal function {}, pass".format(get_member_data(expression), method_name))

            # 特殊处理
            if method_name == "reverse":
                logger.debug("[AST] param {} use special internal function {}, continue found param.".format(get_member_data(expression), method_name))

                is_co, cp, expr_lineno = parameters_back(expression_object, nodes, function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=True, method_name=method_name)

                cp = get_member_data(cp, isreverse=True)
                logger.debug(
                    "[AST] param {} use special internal function {}, reverse result is {}...".format(get_member_data(expression),
                                                                                                      method_name, cp))

                file_path = os.path.normpath(file_path)
                code = "param reverse result is {}".format(cp)
                scan_chain.append(('ReverseParam', code, file_path, lineno))

                is_co, cp = is_controllable(cp)

                return is_co, cp, expr_lineno

        is_co, cp, expr_lineno = parameters_back(expression_object, nodes, function_params, lineno,
                                                 function_flag=0, vul_function=vul_function,
                                                 file_path=file_path,
                                                 isback=True, method_name=method_name)

        return is_co, cp, expr_lineno

    elif callee_name in JS_BUILTIN_KNOWLEDGE:

        logger.debug("[AST] function {} from internal defines, pass".format(callee_name))

        arguments = param.arguments

        for arg in arguments:
            param = arg

            is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                     function_flag=0, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=True, method_name=method_name)

            if is_co == 1:
                return is_co, cp, expr_lineno

    else:
        # 处理当参数传递到function call时，需要回溯寻找函数定义

        # 先查内置知识库，用 callee_name 匹配
        knowledge = lookup_builtin(callee_name)
        if knowledge:
            if knowledge["safe"] and not knowledge["passthrough"]:
                logger.debug("[AST] callee {} in builtin knowledge, safe=True, skip".format(callee_name))
                return -1, param, expr_lineno
            if knowledge["passthrough"]:
                logger.debug("[AST] callee {} in builtin knowledge, passthrough={}, mapping args".format(
                    callee_name, knowledge["passthrough"]))
                callee_params = param.arguments
                for arg_idx in knowledge["passthrough"]:
                    if callee_params and arg_idx < len(callee_params):
                        arg = callee_params[arg_idx]
                        is_co2, cp2, expr_lineno2 = parameters_back(arg, nodes, function_params, lineno,
                                                                     function_flag=0, vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=True, method_name=method_name)
                        if is_co2 == 1:
                            return is_co2, cp2, expr_lineno2
                return 3, param, expr_lineno

        # 查函数摘要
        callee_summary = lookup_summary(callee_name)
        if callee_summary and callee_summary.return_flow:
            call_args = param.arguments or []
            summary_result = _judge_from_summary_js(callee_summary, call_args)
            if summary_result is not None:
                logger.debug("[AST] callee {} matched summary, result={}".format(callee_name, summary_result))
                if summary_result[0] == 1:
                    return summary_result
                if isinstance(summary_result[0], str) and summary_result[0] == 'deps':
                    # deps: 将变量名映射为调用者实参继续追踪
                    for dep_var in summary_result[1]:
                        for idx, arg in enumerate(call_args):
                            if get_member_data(arg) == dep_var:
                                is_co2, cp2, expr_lineno2 = parameters_back(arg, nodes, function_params, lineno,
                                                                             function_flag=0, vul_function=vul_function,
                                                                             file_path=file_path,
                                                                             isback=True, method_name=method_name)
                                if is_co2 == 1:
                                    return is_co2, cp2, expr_lineno2
                    return 3, param, expr_lineno

        for node in nodes[::-1]:
            if node.type == "FunctionDeclaration" and get_member_data(node.id) == callee_name:

                logger.debug("[AST] Back to found function {} define".format(callee_name))

                file_path = os.path.normpath(file_path)
                code = "param from function {}".format(callee_name)
                scan_chain.append(('Function Define', code, file_path, expression.loc.start.line))

                function_params = node.params

                is_co, cp, expr_lineno = function_back(node, function_params, back_nodes=nodes, file_path=file_path,
                                                       isback=True, vul_function=vul_function, iscall=True)

                # deps 处理：函数返回值依赖某些变量，但不是形参
                # 需要将形参映射为调用者实参继续追踪
                if isinstance(is_co, str) and is_co == 'deps':
                    # cp 是变量名列表，尝试在外层 nodes 中继续向上追踪这些变量
                    logger.debug("[AST] function_back returns deps: {}, mapping to caller args".format(cp))

                    # 对于每个依赖变量，检查是否匹配形参，映射为调用者实参
                    callee_params = param.arguments
                    formal_param_names = [get_member_data(fp) for fp in function_params]

                    for dep_var in cp:
                        if dep_var in formal_param_names:
                            idx = formal_param_names.index(dep_var)
                            if idx < len(callee_params):
                                is_co2, cp2, expr_lineno2 = parameters_back(callee_params[idx], nodes, function_params, lineno,
                                                                             function_flag=0, vul_function=vul_function,
                                                                             file_path=file_path,
                                                                             isback=True, method_name=method_name)
                                if is_co2 == 1:
                                    return is_co2, cp2, expr_lineno2

                    return 3, param, expr_lineno

                if is_co == 4:
                    # 代表返回变量来自于参数
                    # 在新 deps 机制下，cp 是形参名字符串
                    formal_param_name = cp if isinstance(cp, str) else get_member_data(cp)
                    return_method = None
                    if hasattr(cp, "type") and cp.type == "MemberExpression":
                        return_method = get_property_object(cp)
                    callee_params = param.arguments
                    formal_param_names = [get_member_data(fp) for fp in function_params]

                    # 将形参映射为调用者实参并追踪
                    for idx, fp_name in enumerate(formal_param_names):
                        if fp_name == formal_param_name and idx < len(callee_params):
                            param = callee_params[idx]
                            is_co, cp, expr_lineno = parameters_back(param, nodes, function_params, lineno,
                                                                     function_flag=0, vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=True, method_name=method_name)
                            if is_co == 1:
                                return is_co, cp, expr_lineno

                    if return_method:
                        cp = generate_memberexp(cp, return_method, expr_lineno)

                    is_co, cp = is_controllable(cp)

                return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno

def _find_sink_branch_js(if_node, lineno):
    """判断 sink 行号位于 JS if/else 的哪个分支。返回 'if', 'else', 'outside'。"""
    if not lineno:
        return 'outside'
    lineno = int(lineno)

    # if 体范围
    if_body = if_node.consequent
    if if_body.type == "BlockStatement":
        if_nodes = if_body.body
    else:
        if_nodes = [if_body]
    if if_nodes and int(if_nodes[0].loc.start.line) <= lineno <= int(if_nodes[-1].loc.end.line):
        return 'if'

    # else 体范围
    if if_node.alternate:
        alt = if_node.alternate
        if hasattr(alt, "type"):
            if alt.type == "IfStatement":
                return _find_sink_branch_js(alt, lineno)
            elif alt.type == "BlockStatement":
                else_nodes = alt.body
            else:
                else_nodes = [alt]
            if else_nodes and int(else_nodes[0].loc.start.line) <= lineno <= int(else_nodes[-1].loc.end.line):
                return 'else'

    return 'outside'


def _is_strict_js_regex(regex_str):
    """判断 JS 正则字符串是否为严格全匹配模式（安全）。

    JS 正则字面量 /^\d+$/ 在 esprima 中 value 是 ^\d+$（无斜杠包裹）。
    严格条件：以 ^ 开头、以 $ 结尾、中间不含未转义的 . 或 * 或 ?。
    """
    if not regex_str or not isinstance(regex_str, str):
        return False
    if len(regex_str) < 4:
        return False
    if not regex_str.startswith('^') or not regex_str.endswith('$'):
        return False
    body = regex_str[1:-1]
    # 去掉转义的 \. 后检查
    stripped = body.replace('\\.', '')
    if '.' in stripped:
        return False
    if '*' in stripped or '?' in stripped:
        return False
    return True


def extract_constraints_from_js_expr(expr):
    """
    从 JS 条件表达式中提取 BranchConstraint 列表。

    esprima AST 节点是字典格式：
    - typeof x === "string"  -> BinaryExpression(op='===', left=UnaryExpression, right=Literal)
    - x === value            -> BinaryExpression(op='===')
    - x !== null             -> BinaryExpression(op='!==')
    - Array.isArray(x)       -> CallExpression
    - !expr                  -> UnaryExpression(op='!')
    - x && y                 -> LogicalExpression(op='&&')
    - x || y                 -> LogicalExpression(op='||')
    """
    if expr is None or not isinstance(expr, dict):
        return []

    constraints = []
    node_type = expr.get('type', '')

    if node_type == 'LogicalExpression' or (node_type == 'BinaryExpression' and expr.get('operator') in ('&&', '||')):
        op = expr.get('operator', '')
        if op == '&&':
            left = extract_constraints_from_js_expr(expr.get('left'))
            right = extract_constraints_from_js_expr(expr.get('right'))
            constraints = left + right
        elif op == '||':
            # '||' 枚举：a === 'x' || a === 'y' → in 约束
            left = extract_constraints_from_js_expr(expr.get('left'))
            right = extract_constraints_from_js_expr(expr.get('right'))
            # 检查是否为枚举模式（同一变量，不同值）
            left_var = left[0].var_name if left else None
            right_var = right[0].var_name if right else None
            if left_var and right_var and left_var == right_var:
                values = []
                for c in left + right:
                    if c.op in ('==', '==='):
                        values.append(c.value)
                if len(values) == len(left + right) and values:
                    constraints.append(BranchConstraint(var_name=left_var, op='in', value=values))
            else:
                constraints = left + right

    if node_type == 'UnaryExpression' and expr.get('operator') == '!':
        inner = extract_constraints_from_js_expr(expr.get('argument'))
        constraints = [c.negate() for c in inner]
        return constraints

    if node_type == 'BinaryExpression':
        op = expr.get('operator', '')
        if op in ('==', '===', '!=', '!=='):
            left_expr = expr.get('left', {})
            # typeof x === 'number' -> type_validated
            if left_expr.get('type') == 'UnaryExpression' and left_expr.get('operator') == 'typeof':
                inner = left_expr.get('argument', {})
                var_name = _extract_js_var_name(inner)
                if var_name:
                    value = _extract_js_literal(expr.get('right', {}))
                    if value is not None:
                        constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value='typeof.' + str(value)))
                        return constraints
            var_name = _extract_js_var_name(left_expr)
            if var_name:
                value = _extract_js_literal(expr.get('right', {}))
                constraints.append(BranchConstraint(var_name=var_name, op=op, value=value))
        return constraints

    if node_type == 'CallExpression':
        callee = expr.get('callee', {})
        callee_type = callee.get('type', '') if isinstance(callee, dict) else ''

        if callee_type == 'MemberExpression':
            prop = callee.get('property', {})
            prop_name = prop.get('name', '') if isinstance(prop, dict) else ''
            obj = callee.get('object', {})
            obj_type = obj.get('type', '') if isinstance(obj, dict) else ''

            # /regex/.test(x) — 正则对象的 test 方法
            if prop_name == 'test' and obj_type in ('Literal', 'RegExpLiteral'):
                regex_str = ''
                if obj_type == 'RegExpLiteral':
                    pattern = obj.get('pattern', '')
                    flags = obj.get('flags', '')
                    regex_str = pattern
                else:
                    regex_str = obj.get('regex', {}).get('pattern', '') if isinstance(obj.get('regex'), dict) else ''
                    # esprima 将正则字面量存为 regex.pattern，fallback 也检查 value
                    if not regex_str:
                        regex_str = obj.get('value', '')
                if regex_str and isinstance(regex_str, str) and _is_strict_js_regex(regex_str):
                    args = expr.get('arguments', [])
                    if args:
                        var_name = _extract_js_var_name(args[0])
                        if var_name:
                            constraints.append(BranchConstraint(
                                var_name=var_name, op='regex_validated', value=regex_str))

            # x.match(regex) — 变量的 match 方法
            elif prop_name == 'match':
                args = expr.get('arguments', [])
                if args:
                    arg0 = args[0]
                    arg0_type = arg0.get('type', '') if isinstance(arg0, dict) else ''
                    # 参数是正则字面量
                    regex_str = ''
                    if arg0_type == 'Literal':
                        regex_str = arg0.get('regex', {}).get('pattern', '') if isinstance(arg0.get('regex'), dict) else ''
                        if not regex_str:
                            regex_str = arg0.get('value', '')
                    if regex_str and isinstance(regex_str, str) and _is_strict_js_regex(regex_str):
                        var_name = _extract_js_var_name(obj)
                        if var_name:
                            constraints.append(BranchConstraint(
                                var_name=var_name, op='regex_validated', value=regex_str))

            # Number.isInteger(x) / Number.isFinite(x) 等静态方法
            if obj_type == 'Identifier' and obj.get('name') == 'Number':
                if prop_name in ('isInteger', 'isFinite', 'isNaN'):
                    args = expr.get('arguments', [])
                    if args:
                        var_name = _extract_js_var_name(args[0])
                        if var_name:
                            constraints.append(BranchConstraint(
                                var_name=var_name, op='type_validated', value='Number.' + prop_name))

        elif callee_type == 'Identifier' and callee.get('name') == 'isNaN':
            # isNaN(x) — 当取反时（!isNaN(x)）表示是数字
            args = expr.get('arguments', [])
            if args:
                var_name = _extract_js_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='type_validated', value='not_nan'))

        return constraints

    return constraints


def _extract_js_var_name(node):
    """从 JS AST 节点提取变量名（字符串形式）。"""
    if not isinstance(node, dict):
        return None
    node_type = node.get('type', '')
    if node_type == 'Identifier':
        return node.get('name')
    if node_type == 'MemberExpression':
        # 如 location.hash
        obj_name = _extract_js_var_name(node.get('object', {}))
        prop = node.get('property', {})
        prop_name = prop.get('name') if isinstance(prop, dict) else None
        if obj_name and prop_name:
            return f"{obj_name}.{prop_name}"
    return None


def _extract_js_literal(node):
    """从 JS AST 节点提取字面量值。"""
    if not isinstance(node, dict):
        return None
    node_type = node.get('type', '')
    if node_type == 'Literal' or node_type == 'StringLiteral':
        return node.get('value')
    if node_type == 'Identifier' and node.get('name') == 'null':
        return None
    if node_type == 'Identifier' and node.get('name') == 'undefined':
        return '__undefined__'
    return None


def parameters_back(param, nodes, function_params=None, lineno=0,
                    function_flag=0, vul_function=None, file_path=None,
                    isback=None, method_name=None):  # 用来得到回溯过程中的被赋值的变量是否与敏感函数变量相等,param是当前需要跟踪的污点
    """
    递归回溯敏感函数的赋值流程，param为跟踪的污点，当找到param来源时-->分析复制表达式-->获取新污点；否则递归下一个节点
    :param method_name: 恶意属性名，针对对member型的回溯拓展
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

    # 查缓存
    param_name = get_member_data(param)
    if param_name and lineno and file_path:
        cached = _trace_cache.get(file_path, param_name, int(lineno))
        if cached is not None:
            return cached

    expr_lineno = 0  # source所在行号
    is_co, cp = is_controllable(param)
    param_name = get_member_data(param)

    # Class this 属性追踪（字符串参数版本）：当 get_param 将 this.xxx 转为字符串后，
    # parameters_back 需要在这里用 _this_prop_map 替换
    global _this_prop_map
    if (is_co == 3 and isinstance(param, str) and param.startswith("this.")
            and _this_prop_map
            and param[5:] in _this_prop_map):
        prop_name = param[5:]
        original_param = _this_prop_map[prop_name]
        logger.debug("[AST] this.{} (str) found in class prop map, trace to {}".format(prop_name, get_member_data(original_param)))
        return parameters_back(original_param, nodes, function_params, lineno,
                                function_flag=function_flag, vul_function=vul_function,
                                file_path=file_path, isback=isback, method_name=method_name)

    # Class this 属性追踪（AST 节点版本）
    if (is_co == 3 and hasattr(param, "type") and param.type == "MemberExpression"
            and hasattr(param.object, "type") and param.object.type == "ThisExpression"
            and hasattr(param.property, "name") and param.property.name in _this_prop_map):
        prop_name = param.property.name
        original_param = _this_prop_map[prop_name]
        logger.debug("[AST] this.{} (node) found in class prop map, trace to {}".format(prop_name, get_member_data(original_param)))
        file_path_norm = os.path.normpath(file_path) if file_path else ""
        scan_chain.append(('ThisProp', 'this.{} -> {}'.format(prop_name, get_member_data(original_param)), file_path_norm, param.loc.start.line if hasattr(param, "loc") else 0))
        return parameters_back(original_param, nodes, function_params, lineno,
                                function_flag=function_flag, vul_function=vul_function,
                                file_path=file_path, isback=isback, method_name=method_name)

    if is_co == 3 and hasattr(param, "type") and param.type == "MemberExpression":

        # 为了能适应正反向两种搜索方式，加入新的限制条件使搜索可能为顺序
        if param_name == vul_function:
            logger.debug("new eval function {} into sequential analysis".format(param_name))

        else:
            logger.debug(
                "[AST] AST analysis for MemberExpression {} in line {}".format(param_name, param.loc.start.line))
            is_co, cp, expr_lineno = member_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                                 vul_function=vul_function, method_name=method_name)
            return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "NewExpression":
        logger.debug("[AST] AST analysis for NewExpression {} in line {}".format(param_name, param.loc.start.line))
        is_co, cp, expr_lineno = new_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                          vul_function=vul_function, method_name=method_name)
        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "CallExpression":
        is_co, cp, expr_lineno = function_call_back(param, nodes, function_params, file_path=file_path, isback=isback,
                                                    vul_function=vul_function, method_name=method_name)
        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(param, "type") and param.type == "ExpressionStatement":

        if param.expression.type == "CallExpression":
            is_co, cp, expr_lineno = function_call_back(param.expression, nodes, function_params, file_path=file_path,
                                                        isback=isback,
                                                        vul_function=vul_function, method_name=method_name)
            return is_co, cp, expr_lineno

    if isback and hasattr(param, "type") and param.type == "ObjectExpression":
        logger.debug("[AST] AST analysis found param ObjectExpression {}".format(param_name))
        return is_co, param, expr_lineno

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "ReturnStatement":
        # 仔细思考之后我觉得问题的核心还是在这里，当一个函数的返回函数为关键字，那么这种情况则需要特殊处理
        if get_property_object(nodes.argument) == param_name:
            # <del>return x.innerHTML<del>
            # <del>返回为特殊的属性，那么应该为对象传递，我们的目标转为顺序分析敏感对象<del>
            #  之前关于这部分的理解是错误的，在javascript中，不是所有情况下都会传递对象
            # 这里操作符号赋值为5
            logger.debug("[AST] evalobject in return, will not cause problem.")

            is_co = -1
            cp = get_property_object(nodes.argument)
            expr_lineno = nodes.loc.start.line

        return is_co, cp, expr_lineno

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "BlockStatement":
        # block 块简单处理
        nodes = nodes.body

    if is_co == 3 and hasattr(nodes, "type") and nodes.type == "BreakStatement":
        return is_co, cp, expr_lineno

    if type(nodes) == list and len(nodes) != 0 and is_co != 1 and is_co != -1:
        node = nodes[len(nodes) - 1]

        if node.type == "VariableDeclaration":  # 变量定义
            expr_nodes = node.declarations

            for expr_node in expr_nodes:
                if param_name == get_member_data(expr_node.id) or param_name == get_member_data(expr_node.init):
                    node = expr_node

        if node.type == "VariableDeclarator":  # 变量赋值
            if param_name == get_member_data(node.id):
                # 获取右值
                param_expr = node.init
                param_expr_name = get_member_data(param_expr)
                expr_lineno = node.init.loc.start.line if param_expr and hasattr(param_expr, 'loc') and param_expr.loc else 0

                # log
                logger.debug(
                    "[AST] Find {}={} in line {}".format(param_name, param_expr_name, expr_lineno))

                file_path = os.path.normpath(file_path)
                code = "{}={}".format(param_name, param_expr_name)
                scan_chain.append(('Assignment', code, file_path, expr_lineno))

                is_co, cp = is_controllable(param_expr)

                if is_co == 1:
                    return is_co, cp, expr_lineno

                # 三元运算符 (ConditionalExpression) 分支约束追踪
                # 必须在 isback 检查之前执行，否则 isback=True 时会跳过约束分析直接返回
                if hasattr(param_expr, "type") and param_expr.type == "ConditionalExpression":
                    true_names = set()
                    _collect_js_var_names(param_expr.consequent, true_names)
                    false_names = set()
                    _collect_js_var_names(param_expr.alternate, false_names)
                    test_expr = param_expr.test.toDict() if hasattr(param_expr.test, 'toDict') else param_expr.test
                    constraints = extract_constraints_from_js_expr(test_expr)
                    for c in constraints:
                        if c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                            if c.var_name in true_names and c.var_name not in false_names:
                                # 约束变量只在 true 分支 → true 路径中 var == fixed → 阻断
                                logger.info("[AST] Ternary constraint BLOCKS: {} {} {}".format(c.var_name, c.op, c.value))
                                return -1, param, 0
                            elif c.var_name in false_names and c.var_name not in true_names:
                                # 约束变量只在 false 分支 → false 路径中 var != fixed → 不阻断，追踪 false 分支
                                param = get_member_data(param_expr.alternate)
                                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                         function_flag=0, vul_function=vul_function,
                                                                         file_path=file_path,
                                                                         isback=True, method_name=method_name)
                                return is_co, cp, expr_lineno

                if isback is True:
                    return is_co, cp, expr_lineno

                if is_memberexp(param_expr):
                    # 尝试isback获取
                    param = get_original_object(param_expr)
                    is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                             function_flag=0, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=True, method_name=method_name)

                    # 暂时还没想好，暂时设置为对象修改
                    param = set_original_object(param_expr, cp)

                    logger.debug(
                        "[AST] merge object param {} in line {}".format(get_member_data(param), expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "new merge param {}".format(get_member_data(param))
                    scan_chain.append(('NewParam', code, file_path, expr_lineno))

                    is_co, cp = is_controllable(param)
                elif is_co == 3 and hasattr(param_expr, "type") and param_expr.type == "CallExpression":
                    # 右值为函数调用（如 step1.toLowerCase()），提取 callee 的原始对象继续回溯
                    callee = param_expr.callee
                    if hasattr(callee, "type"):
                        if callee.type == "MemberExpression":
                            param = get_original_object(callee)
                        elif callee.type == "Identifier":
                            param = callee.name
                        else:
                            param = get_original_object(param_expr)

                        logger.debug(
                            "[AST] VariableDeclarator right is CallExpression, trace callee {}".format(param))

                        file_path = os.path.normpath(file_path)
                        code = "trace CallExpression callee {}".format(param)
                        scan_chain.append(('CallExprCallee', code, file_path, expr_lineno))

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)
                else:

                    param = get_original_object(param_expr)

            # 这里是一个新的问题，js中涉及到对象传递，所以引入新的思路
            elif param_name == get_member_data(node.init):
                new_function_name = get_member_data(node.id)

                # 如果右值为函数名，则传递生成新的函数对象
                logger.debug(
                    "[AST] function {} line {} declarator new function {}".format(param_name, lineno,
                                                                                  new_function_name))

                file_path = os.path.normpath(file_path)
                code = "New function object passing to {}".format(new_function_name)
                scan_chain.append(('NewFunction', code, file_path, lineno))

                is_co = 4
                cp = tuple([node.id, param, vul_function])
                return is_co, cp, 0

        elif node.type == "ExpressionStatement":  # 赋值操作
            expression = node.expression

            if expression.type == "AssignmentExpression" and expression.operator == "=":

                if get_member_data(expression.right, isparam=True) == vul_function:
                    # 这里面向对象传递操作
                    new_function_name = get_member_data(expression.left)

                    logger.debug("[Deep AST] New eval object transfer to object {}".format(new_function_name))

                    file_path = os.path.normpath(file_path)
                    code = "New function object transfer to {}".format(new_function_name)
                    scan_chain.append(('NewFunction', code, file_path, lineno))

                    # 处理"prototype"问题

                    is_co = 4
                    cp = tuple([get_member_data(expression.left, isclean_prototype=True), "evalobject", vul_function])
                    return is_co, cp, 0

                if get_member_data(expression.left, isparam=True) == param_name:
                    param_expr = expression.right
                    param_expr_name = get_member_data(param_expr)
                    expr_lineno = expression.loc.start.line

                    # log
                    logger.debug(
                        "[AST] Find {}={} in line {}".format(param_name, param_expr_name, expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "{}={}".format(param_name, param_expr_name)
                    scan_chain.append(('Assignment', code, file_path, expr_lineno))

                    is_co, cp = is_controllable(param_expr_name)

                    if is_co == 1:
                        return is_co, cp, expr_lineno

                    if is_co == -1 and isback is True:
                        cp = param_expr_name

                    if is_memberexp(param_expr):
                        # 当右值为memberexp
                        # 尝试isback获取
                        param = get_original_object(param_expr)
                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)

                        # 暂时还没想好，暂时设置为对象修改
                        param = set_original_object(param_expr, cp)

                        logger.debug(
                            "[AST] merge object param {} in line {}".format(get_member_data(param), expr_lineno))

                        file_path = os.path.normpath(file_path)
                        code = "new merge param {}".format(get_member_data(param))
                        scan_chain.append(('NewParam', code, file_path, expr_lineno))

                        is_co, cp = is_controllable(param)

                    elif hasattr(param_expr,
                                 "type") and param_expr.type == "BinaryExpression" and param_expr.operator == "+":
                        # 即右值为列表
                        param_list = get_param(param_expr)

                        for param in param_list:
                            logger.debug("[AST] new param {} ast".format(get_member_data(param)))

                            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                     function_flag=function_flag,
                                                                     vul_function=vul_function,
                                                                     file_path=file_path,
                                                                     isback=isback, method_name=method_name)

                            if is_co != 3:
                                return is_co, cp, expr_lineno

                        return is_co, cp, expr_lineno

                    elif is_memberexp(expression.left):
                        # 当左值为memberexp
                        # 也同样需要isback来想办法处理
                        is_co, cp, expr_lineno = parameters_back(param_expr, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)

                        logger.debug("[AST] New object method modify {}={}".format(get_member_data(expression.left),
                                                                                   get_member_data(cp)))

                        if is_thisexp(cp):
                            param = set_property_object(expression.left, cp.property)

                            logger.debug(
                                "[AST] New object method merge {}".format(get_member_data(param)))

                            file_path = os.path.normpath(file_path)
                            code = "new merge Object method {}".format(get_member_data(param))
                            scan_chain.append(('NewParam', code, file_path, expr_lineno))

                            is_co, cp = is_controllable(param)

                    elif param_expr.type == "CallExpression":
                        callee = param_expr.callee
                        callee_name = get_member_data(callee, isparam=True)

                        # 检查是不是内置函数
                        if callee_name in function_dict:

                            logger.debug(
                                "[AST] Assignment right is default function {}, continue...".format(callee_name))
                            param = param

                        else:
                            param = get_original_object(param_expr)

                    else:

                        param = get_original_object(param_expr)

                elif get_member_data(expression.right) == param_name and vul_function == param_name:
                    # 遇到了新的问题，自定义匹配的时候遇到对象传递，当前规则匹配到右值的时候
                    # 需要获取左值来作为新的规则
                    new_function_name = get_member_data(expression.left)

                    logger.debug(
                        "[AST] function {} line {} declarator new function {}".format(param_name, lineno,
                                                                                      new_function_name))

                    file_path = os.path.normpath(file_path)
                    code = "New function object transfer to {}".format(new_function_name)
                    scan_chain.append(('NewFunction', code, file_path, lineno))

                    is_co = 4
                    cp = tuple([expression.left.name, "evalobject", vul_function])
                    return is_co, cp, 0

                elif expression.right.type == "ObjectExpression":
                    # 当右值为对象时，需要跟进去分析
                    objectexpression = expression.right
                    object_properties = objectexpression.properties

                    for property in object_properties:
                        property_key = property.key
                        property_value = property.value

                        # 在这里打个断点，思考一个问题，如果敏感对象类右值是什么的时候可能会有问题
                        # 在这里我们暂且认为右值为functioncall

                        if property_value.type == "FunctionExpression":
                            is_co, cp, expr_lineno = function_back(property_value, function_params, nodes, file_path, isback,
                                                                   vul_function=vul_function, method_name=method_name)

                            # deps 处理：返回值依赖某些变量，跳过当前节点
                            if isinstance(is_co, str) and is_co == 'deps':
                                logger.debug("[AST] parameters_back function_back returns deps: {}, skip".format(cp))
                                # 跳过当前 ObjectExpression，继续向上追踪
                                is_co = 3
                                cp = param
                            elif is_co == 4:
                                logger.debug("[AST] object.method transfer found {}".format(vul_function))

                                object_name = get_member_data(expression.left)

                                new_eval_function = str(object_name) + "." + str(get_member_data(property_key))

                                logger.debug("[AST] new eval function {}".format(new_eval_function))
                                file_path = os.path.normpath(file_path)
                                code = "New vustomize-Function {}".format(new_eval_function)
                                scan_chain.append(('NewFunction', code, file_path, property.loc.start.line))

                                cp = tuple([new_eval_function, "evalmethod"])

                        if is_co != 3:
                            return is_co, cp, expr_lineno

            elif expression.type == "CallExpression":
                callee_name = get_member_data(expression.callee)
                expr_lineno = expression.loc.start.line

                if callee_name and vul_function and (callee_name == vul_function or callee_name == "this." + vul_function.split(".")[-1]):
                    callee_params = expression.arguments
                    param_name = get_member_data(callee_params)

                    logger.debug("[AST] call param from self object method {}".format(callee_name))
                    logger.debug(
                        "[AST] Find {} in {} param in line {}".format(param_name, callee_name, expr_lineno))

                    file_path = os.path.normpath(file_path)
                    code = "{} in function {} param".format(param_name, callee_name)
                    scan_chain.append(('NewParam', code, file_path, expr_lineno))

                    # 恶意函数调用
                    for param in callee_params:
                        # issue #50:
                        # eval('callback') 这类伪语法会让参数在调用处变成字符串字面量，
                        # 但其语义上代表变量名，需要继续按变量回溯。
                        if vul_function in special_eval_function \
                                and hasattr(param, "type") and param.type == "Literal" \
                                and isinstance(param.value, str):
                            param = check_param(param.value, vul_lineno=param.loc.start.line)

                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=True, method_name=method_name)
                        return is_co, cp, expr_lineno

                elif expression.callee and expression.callee.type == "FunctionExpression":
                    # 这个分支代表处理在js中特有的一种常见语义结构
                    # (function(a){return a})(c)
                    # 闭包
                    callee = expression.callee
                    callee_body = callee.body.body
                    callee_params = callee.params

                    if node.loc.end.line < int(lineno):
                        is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                 function_flag=0, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)
                        return is_co, cp, expr_lineno

                    logger.debug("[AST] param {} line {} in Closure Function in line {}".format(param, lineno,
                                                                                                callee.loc.start.line))

                    file_path = os.path.normpath(file_path)
                    code = "param {} in Closure function".format(param_name)
                    scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                    vul_nodes = []

                    for vul_node in callee_body:
                        if vul_node is not None and vul_node.loc.start.line < int(lineno):
                            vul_nodes.append(vul_node)

                    is_co, cp, expr_lineno = parameters_back(param, vul_nodes, function_params, lineno,
                                                             function_flag=0, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=True, method_name=method_name)

                    if is_co == 3:

                        for callee_param in callee_params:
                            if get_member_data(callee_param) == cp:
                                expression_arguments = expression.arguments
                                param = expression_arguments[callee_params.index(callee_param)]

                                logger.debug(
                                    "[AST] param {} line {} in function params, param transfer to param of Closure Function {}".format(
                                        get_member_data(cp), expr_lineno, get_member_data(param)))

                                file_path = os.path.normpath(file_path)
                                code = "New param {} out from Closure function".format(get_member_data(param))
                                scan_chain.append(('TmpFunction', code, file_path, callee.loc.start.line))

                                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                                         function_flag=0, vul_function=vul_function,
                                                                         file_path=file_path,
                                                                         isback=isback, method_name=method_name)
                                return is_co, cp, expr_lineno

        elif node.type == "FunctionDeclaration":  # 函数定义
            function_expression = node.expression
            function_isAsync = node.isAsync
            function_name = get_member_data(node.id)
            function_params = get_param_list(node.params)
            function_body = node.body.body  # blockstatement
            function_lineno = node.loc.start.line

            vul_nodes = []

            # 遇到了一个令人难受的问题
            # client js 有严重的动态类型问题，所有的变量、函数等都是对象
            # 为了解决这个问题，现在尝试把逻辑设置为name相同时即同一个对象
            if param_name == function_name:
                is_co, cp, expr_lineno = function_back(node, function_params, back_nodes=nodes, file_path=file_path,
                                                       isback=isback, method_name=method_name)

                # deps 处理：返回值依赖某些变量，跳过当前函数定义节点
                if isinstance(is_co, str) and is_co == 'deps':
                    logger.debug("[AST] parameters_back function_back returns deps: {}, skip function node".format(cp))
                    is_co = 3
                    cp = param

                # 由于从函数内部出来的很有可能是类的私有变量，所以如果私有变量为this的时候
                return is_co, cp, expr_lineno

            # 这是一个优化，无关的变量跳过
            if node.loc.end.line < int(lineno):
                is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                         function_flag=0, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)
                return is_co, cp, expr_lineno

            logger.debug(
                "[AST] param {} line {} in function {} line {}, start ast in function".format(param_name,
                                                                                              lineno,
                                                                                              function_name,
                                                                                              function_lineno))

            file_path = os.path.normpath(file_path)
            code = "param {} in function {}".format(param_name, function_name)
            scan_chain.append(('Function', code, file_path, function_lineno))

            for function_node in function_body:
                if function_node is not None and int(function_lineno) <= function_node.loc.start.line <= int(lineno):
                    vul_nodes.append(function_node)

            if len(vul_nodes) > 0:
                is_co, cp, expr_lineno = parameters_back(param, vul_nodes, function_params, lineno,
                                                         function_flag=1, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)
                function_flag = 0

            if is_co == 3:  # 出现新的敏感函数，重新生成新的漏洞结构，进入新的遍历结构
                for function_param in function_params:
                    if function_param == cp:
                        logger.debug(
                            "[AST] param {} line {} in function_params, start new rule for function {}".format(
                                param_name, function_lineno, function_name))

                        file_path = os.path.normpath(file_path)
                        code = "param {} in NewFunction {}".format(param_name, function_name)
                        scan_chain.append(('NewFunction', code, file_path, function_lineno))

                        if vul_function is None or function_name != vul_function:
                            logger.info(
                                "[Deep AST] Now vulnerability function from function {}() param ({})".format(
                                    function_name,
                                    cp))

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

            elif is_co == 5:  # 出现函数返回值为敏感参数的情况需要对象传递
                eval_method = cp

                logger.debug("[Deep AST] eval method {} return from function {}".format(eval_method, function_name))

                file_path = os.path.normpath(file_path)
                code = "NewEvalObject {} with {}".format(function_name, eval_method)
                scan_chain.append(('NewEvalObject', code, file_path, function_lineno))

                is_co = 4
                cp = tuple([function_name, "evalobject", vul_function])

                return is_co, cp, 0

        elif node.type == "IfStatement":
            logger.debug(
                "[AST] param {} line {} in if/else, start ast in if/else".format(param_name, node.loc.start.line))

            # 1. 判断 sink 在哪个分支
            sink_branch = _find_sink_branch_js(node, lineno)
            logger.debug("[AST] sink_branch={} for param {} lineno {}".format(sink_branch, param_name, lineno))

            # 2. 提取当前分支的条件约束并确定分支体
            # esprima AST 节点是自定义对象，需转为 dict 供约束提取使用
            test_expr = node.test.toDict() if hasattr(node.test, 'toDict') else node.test
            if sink_branch == 'if':
                constraints = extract_constraints_from_js_expr(test_expr)
                if_body = node.consequent
                if if_body.type != "BlockStatement":
                    if_body = [if_body]
                body_nodes = if_body
            elif sink_branch == 'else':
                constraints = [c.negate() for c in extract_constraints_from_js_expr(test_expr)]
                else_body = node.alternate
                if hasattr(else_body, "type") and else_body.type == "IfStatement":
                    else_body = [else_body]
                body_nodes = else_body if else_body else []
            else:
                # sink 在 if/else 之外 → 遍历所有分支找变量重赋值
                if_body = node.consequent
                if if_body.type != "BlockStatement":
                    if_body = [if_body]
                is_co, cp, expr_lineno = parameters_back(param, if_body, function_params, lineno,
                                                         function_flag=function_flag, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)
                if is_co != 1 and node.alternate:
                    else_body = node.alternate
                    if hasattr(else_body, "type") and else_body.type == "IfStatement":
                        else_body = [else_body]
                    is_co, cp, expr_lineno = parameters_back(param, else_body, function_params, lineno,
                                                             function_flag=function_flag, vul_function=vul_function,
                                                             file_path=file_path,
                                                             isback=isback, method_name=method_name)

            # 3. 立即检查约束（仅在 sink 在具体分支内时执行）
            if sink_branch != 'outside':
                # param_name 可能是列表形式（如 ['input']），统一转为字符串比较
                _param_str = param_name[0] if isinstance(param_name, list) else str(param_name)
                for c in constraints:
                    if c.var_name == _param_str and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                        logger.info("[AST] Branch constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                        return -1, param, 0

                # 4. 不等约束不阻断，继续回溯分支体
                is_co, cp, expr_lineno = parameters_back(param, body_nodes, function_params, lineno,
                                                         function_flag=function_flag, vul_function=vul_function,
                                                         file_path=file_path,
                                                         isback=isback, method_name=method_name)

            if is_co == 1:
                return is_co, cp, expr_lineno

        elif node.type == "SwitchStatement":
            logger.debug(
                "[AST] param {} line {} in Switch, start branch constraint analysis".format(param_name, node.loc.start.line if node.loc else 0))

            # switch/case 分支约束追踪
            # 判断 sink（lineno）在哪个 case 中
            sink_in_default = False
            sink_in_case = False
            if node.cases and lineno > 0:
                for i, switch_case in enumerate(node.cases):
                    if not switch_case.loc:
                        continue
                    case_start = switch_case.loc.start.line
                    case_end = switch_case.loc.end.line

                    if case_start <= lineno <= case_end:
                        if switch_case.test is None:
                            sink_in_default = True
                        else:
                            sink_in_case = True
                        break

            if sink_in_case:
                # sink 在非 default case 中 → switch expr == case_value → 阻断
                logger.info("[AST] Switch constraint BLOCKS: sink in non-default case (line {})".format(lineno))
                return -1, param, 0

            # sink 在 default 或不在 switch 中 → 正常回溯每个 case
            if node.cases:
                for switch_case in node.cases:
                    if switch_case.consequent:
                        is_co, cp, expr_lineno = parameters_back(param, switch_case.consequent, function_params, lineno,
                                                                 function_flag=1, vul_function=vul_function,
                                                                 file_path=file_path,
                                                                 isback=isback, method_name=method_name)
                        if is_co == 1:
                            return is_co, cp, expr_lineno

        elif node.type == "WhileStatement":
            logger.debug("[AST] Param {} line {} in while, start ast in while".format(param_name, node.loc.start.line))

            while_body = node.body.body

            # while 循环条件等值约束检查：如果 while 条件中 param_name 有 == 约束，且 sink 在 while 体内 → 阻断
            if while_body and lineno:
                _lineno = int(lineno)
                body_start = node.body.loc.start.line
                body_end = node.body.loc.end.line
                if body_start <= _lineno <= body_end:
                    test_expr = node.test.toDict() if hasattr(node.test, 'toDict') else node.test
                    constraints = extract_constraints_from_js_expr(test_expr)
                    _param_str = param_name[0] if isinstance(param_name, list) else str(param_name)
                    for c in constraints:
                        if c.var_name == _param_str and c.op in ('==', '===', 'in', 'type_validated', 'regex_validated'):
                            logger.info("[AST] While constraint BLOCKS param {}: {} {}".format(param_name, c.op, c.value))
                            return -1, param, 0

            is_co, cp, expr_lineno = parameters_back(param, while_body, function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)

        elif node.type == "ForStatement":
            logger.debug("[AST] Param {} line {} in for loop".format(param_name, node.loc.start.line))
            for_body = node.body.body if hasattr(node.body, 'body') else []

            is_co, cp, expr_lineno = parameters_back(param, for_body, function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)

        elif node.type in ("ForInStatement", "ForOfStatement"):
            logger.debug("[AST] Param {} line {} in for-in/of loop".format(param_name, node.loc.start.line))
            for_body = node.body.body if hasattr(node.body, 'body') else []

            is_co, cp, expr_lineno = parameters_back(param, for_body, function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)

        if is_co == 3:
            is_co, cp, expr_lineno = parameters_back(param, nodes[:-1], function_params, lineno,
                                                     function_flag=function_flag, vul_function=vul_function,
                                                     file_path=file_path,
                                                     isback=isback, method_name=method_name)  # 找到可控的输入时，停止递归


    return is_co, cp, expr_lineno


def deep_parameters_back(param, back_node, function_params, count, file_path, lineno=0, vul_function=None,
                         isback=False):
    """
    深层递归分析外层逻辑，主要是部分初始化条件和新递归的确定
    :param isback: 
    :param lineno: 
    :param vul_function: 
    :param param: 
    :param back_node: 
    :param function_params: 
    :param count: 
    :param file_path: 
    :return: 
    """
    count += 1
    padding = {}

    is_co, cp, expr_lineno = parameters_back(param, back_node, function_params, lineno, vul_function=vul_function,
                                             file_path=file_path, isback=isback)

    # 缓存确定性结果（只缓存确定性结果，跳过中间状态）
    if lineno and file_path and isinstance(is_co, int) and is_co in (-1, 1, 2):
        param_str = get_member_data(param) if hasattr(param, 'type') else str(param)
        _trace_cache.put(file_path, param_str, int(lineno), (is_co, cp, expr_lineno))

    if count > 20:
        logger.warning("[Deep AST] depth too big, auto exit...")
        return is_co, cp, expr_lineno

    return is_co, cp, expr_lineno


def analysis_params(expression, back_node, vul_function, vul_lineno, file_path, repair_functions=None,
                    controlled_params=None, isexternal=False, is_eval=False, is_function=False):
    """
    当分析到具体的参数时
    :param is_function: 真是出现了新的问题，常规函数式匹配，右值为function时
    :param is_eval: 
    :param controlled_params: 
    :param repair_functions: 
    :param isexternal: 
    :param vul_function: 
    :param expression: 
    :param back_node: 这是一个设计问题，这里函数可能有很多入口，所以这里不应该为直接传node
    :param vul_lineno: 
    :param file_path: 
    :return: 
    """
    global scan_chain, is_repair_functions, is_controlled_params

    function_params = None
    is_co = -1
    cp = get_member_data(expression)
    expr_lineno = vul_lineno

    if repair_functions is not None:
        is_repair_functions = repair_functions

    if controlled_params is not None:
        is_controlled_params = controlled_params

    if isexternal:
        scan_chain = ['start']
        param_list = [check_param(expression, vul_lineno=vul_lineno)]
        _nodes = ast_object.get_nodes(file_path, vul_lineno=vul_lineno, lan='javascript')
        if (not _nodes) or type(_nodes) is list:
            back_node = _nodes if type(_nodes) is list else []
        else:
            back_node = getattr(_nodes, 'body', []) or []

    elif is_function:
        param_list = [check_param(expression, vul_lineno=vul_lineno)]

    else:
        arguments = expression.arguments
        param_list = get_param_list(arguments, is_eval=is_eval, is_function_regex=True)

    logger.debug("[AST] AST to find param {}".format(get_member_data(param_list)))
    logger.debug("[AST] AST for Vul function {}".format(vul_function))


    code = "find param {}".format(get_member_data(param_list))
    scan_chain.append(('NewFind', code, file_path, vul_lineno))

    for param in param_list:
        count = 0
        is_co, cp, expr_lineno = deep_parameters_back(param, back_node, function_params, count, file_path, vul_lineno,
                                                      vul_function=vul_function)

        if isexternal:
            if is_co != 3:
                return is_co, cp, expr_lineno, scan_chain
        set_scan_results(is_co, cp, expr_lineno, vul_function, param, vul_lineno)

    return is_co, cp, expr_lineno, scan_chain


def analysis_If(node, vul_function, back_node, vul_lineno, file_path, function_params):
    """
    if 语句
    :param node: 
    :param vul_function: 
    :param back_node: 
    :param vul_lineno: 
    :param file_path: 
    :param function_params: 
    :return: 
    """
    if_condition = node.test
    if_body = node.consequent
    if node.loc.start.line <= vul_lineno <= node.loc.end.line:
        analysis([if_body], vul_function, back_node, vul_lineno, file_path, function_params)

        if node.alternate:
            else_body = node.alternate
            analysis([else_body], vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_while(node, vul_function, back_node, vul_lineno, file_path, function_params):
    """
    while 语句
    :param node:
    :param vul_function:
    :param back_node:
    :param vul_lineno:
    :param file_path:
    :param function_params:
    :return:
    """
    while_body = node.body.body
    if node.loc.start.line <= vul_lineno <= node.loc.end.line:
        analysis(while_body, vul_function, back_node, vul_lineno, file_path, function_params)


def analysis_callexpression(node, vul_function, back_node, vul_lineno, file_path, function_params):
    if vul_lineno == node.loc.start.line:
        call_arguments = node.arguments
        call_callee = node.callee

        for arg in call_arguments:
            if arg.type == "CallExpression":
                analysis_callexpression(arg, vul_function, back_node, vul_lineno, file_path, function_params)

        if is_eval_function(node):
            analysis_params(node, back_node, vul_function, vul_lineno, file_path, function_params, is_eval=True)

        elif call_callee.type in ("FunctionExpression", "ArrowFunctionExpression"):
            if call_callee.body.type == "BlockStatement":
                child_nodes = call_callee.body.body
            else:
                child_nodes = [call_callee.body]
            function_params = call_callee.arguments

            analysis(child_nodes, vul_function, back_node, int(vul_lineno), file_path, function_params=function_params,
                     in_funtion=True)

        else:
            # 检测 class 方法调用：obj.setCommand(req.query.cmd) → 把实参存入 _this_prop_map
            global _class_method_param_map, _this_prop_map
            if call_callee.type == "MemberExpression" and hasattr(call_callee, "property"):
                callee_method = get_member_data(call_callee.property)
                if callee_method in _class_method_param_map:
                    for arg_idx, prop_name in _class_method_param_map[callee_method].items():
                        if arg_idx < len(call_arguments):
                            actual_arg = call_arguments[arg_idx]
                            logger.debug("[AST] class method call {}({}), this.{} = {}".format(
                                callee_method, get_member_data(actual_arg), prop_name, get_member_data(actual_arg)))
                            _this_prop_map[prop_name] = actual_arg

            analysis_params(node, back_node, vul_function, vul_lineno, file_path, function_params)

    elif node.loc.start.line < vul_lineno <= node.loc.end.line:
        if node.callee.type in ("FunctionExpression", "ArrowFunctionExpression"):
            if node.callee.body.type == "BlockStatement":
                nodes = node.callee.body.body
            else:
                nodes = [node.callee.body]
            function_params = node.callee.params

            analysis(nodes, vul_function, back_node, int(vul_lineno), file_path, function_params=function_params,
                     in_funtion=True)
        else:
            # 遍历 arguments，递归进入 FunctionExpression 类型的回调参数
            for arg in node.arguments:
                if arg.type in ("FunctionExpression", "ArrowFunctionExpression"):
                    if arg.body.type == "BlockStatement":
                        nodes = arg.body.body
                    else:
                        nodes = [arg.body]
                    function_params = arg.params
                    # 构造包含回调体内节点的 back_node，使参数回溯能找到函数体内的变量定义
                    callback_back_node = list(back_node)
                    for n in nodes:
                        callback_back_node.append(n)

                    analysis(nodes, vul_function, callback_back_node, int(vul_lineno), file_path, function_params=function_params,
                             in_funtion=True)
                    break


def analysis_objectexpression(node, vul_function, back_node, vul_lineno, file_path, function_params, object_name):
    """
    这是一个神奇的函数，js才有可能出现，即右值为对象，其中方法为恶意函数
    :param node: 
    :param vul_function: 
    :param back_node: 
    :param vul_lineno: 
    :param file_path: 
    :param function_params: 
    :return: 
    """
    # object_name = get_member_data(node.id)
    object_expr_node = node
    object_properties = object_expr_node.properties

    for property in object_properties:
        property_key = property.key
        property_value = property.value

        if get_member_data(property_value) == vul_function and property_value.loc.start.line == vul_lineno:
            logger.debug("[AST] object.method transfer found {}".format(vul_function))

            new_eval_function = str(object_name) + "." + str(get_member_data(property_key))

            logger.debug("[AST] new eval function {}".format(new_eval_function))
            file_path = os.path.normpath(file_path)
            code = "New vustomize-Function {}".format(new_eval_function)
            scan_chain.append(('NewFunction', code, file_path, vul_lineno))

            is_co = 4
            cp = tuple([new_eval_function, "evalmethod", vul_function])
            set_scan_results(is_co, cp, 1, vul_function, "", vul_lineno)


def analysis_expression(node, vul_function, back_node, vul_lineno, file_path, function_params):
    expression = node.expression
    expression_loc = node.loc

    expr_type = expression.type

    if expr_type == "CallExpression":
        analysis_callexpression(expression, vul_function, back_node, vul_lineno, file_path, function_params)

    elif expr_type == "AwaitExpression":
        # await expr：提取 argument（通常是 CallExpression）进行分析
        await_arg = expression.argument
        if hasattr(await_arg, "type"):
            if await_arg.type == "CallExpression":
                analysis_callexpression(await_arg, vul_function, back_node, vul_lineno, file_path, function_params)

    elif expr_type == "AssignmentExpression":
        expression_node = get_member_data(expression.right)

        # 这里需要更精细的处理方式
        if expression.right.type == "ObjectExpression":
            # 仔细想了下，由于这应该是一个可以称之为evalmethod的问题，应该在参数回溯的时候分析，所以不在这里处理
            # param = get_member_data(set_property_object(expression, key))
            object_name = get_member_data(expression.left)
            analysis_objectexpression(expression.right, vul_function, back_node, vul_lineno, file_path, function_params,
                                      object_name=object_name)

        elif expression.right.type == "NewExpression":
            # 右值为new object
            pass

        # else:
        #     analysis_params(expression_node, back_node, vul_function, vul_lineno, file_path, is_function=True)


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
        'source': get_member_data(cp),
        'source_lineno': expr_lineno,
        'sink': sink,
        'sink_param:': get_member_data(param),
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


def _resolve_class_method_calls(nodes, method_param_map):
    """
    递归搜索 AST 找 class 方法调用（如 executor.setCommand(req.query.cmd)），
    把实参存入 _this_prop_map[prop_name]。
    """
    global _this_prop_map
    for node in nodes:
        target = node
        # ExpressionStatement → 取 expression
        if node.type == "ExpressionStatement" and hasattr(node, "expression"):
            target = node.expression
        # 递归进入子节点
        if hasattr(target, "type") and target.type == "CallExpression":
            callee = target.callee
            if hasattr(callee, "type") and callee.type == "MemberExpression" and hasattr(callee, "property"):
                callee_method = get_member_data(callee.property)
                if callee_method in method_param_map:
                    for arg_idx, prop_name in method_param_map[callee_method].items():
                        if arg_idx < len(target.arguments):
                            actual_arg = target.arguments[arg_idx]
                            logger.debug("[AST] class method call {}({}), this.{} = {}".format(
                                callee_method, get_member_data(actual_arg), prop_name, get_member_data(actual_arg)))
                            _this_prop_map[prop_name] = actual_arg
        # 递归子节点：BlockStatement.body, CallExpression.arguments, FunctionExpression/ArrowFunctionExpression.body
        for attr in ("body", "arguments", "consequent", "alternate", "cases"):
            if hasattr(target, attr):
                child = getattr(target, attr)
                if child is not None:
                    if isinstance(child, list):
                        _resolve_class_method_calls(child, method_param_map)
                    elif hasattr(child, "type") and child.type == "BlockStatement":
                        _resolve_class_method_calls(child.body, method_param_map)


def analysis(all_nodes, vul_function, back_node, vul_lineno, file_path, function_params, in_funtion=False):
    global scan_results

    for node in all_nodes:

        # 检查line范围，以快速锁定参数
        if vul_lineno < node.loc.start.line:
            break

        if not in_funtion:
            back_node.append(node)

        if node.type == "ExpressionStatement":  # 函数调用
            analysis_expression(node, vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "ReturnStatement":  # return 中的函数调用（如 return eval(expr)）
            if hasattr(node, 'argument') and node.argument:
                if node.argument.type == "CallExpression":
                    analysis_callexpression(node.argument, vul_function, back_node, vul_lineno, file_path, function_params)
                elif node.argument.type == "AwaitExpression":
                    await_arg = node.argument.argument
                    if hasattr(await_arg, "type") and await_arg.type == "CallExpression":
                        analysis_callexpression(await_arg, vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "FunctionDeclaration":  # 函数声明
            # analysis_functiondec(node, vul_function, back_node, vul_lineno, file_path, function_params)
            function_params = get_param_list(node.params)

            # 递归进函数
            if node.body.type == "BlockStatement":
                analysis(node.body.body, vul_function, back_node, vul_lineno, file_path,
                         function_params=function_params, in_funtion=True)

        if node.type == "BlockStatement":  # 函数块？
            analysis(node.body, vul_function, back_node, vul_lineno, file_path, function_params=function_params)

        if node.type == "IfStatement":
            analysis_If(node, vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "SwitchStatement":
            # switch 语句：遍历 case 的 consequent，追加到 back_node
            if node.cases:
                for switch_case in node.cases:
                    if switch_case.consequent:
                        back_node.append(switch_case)
                        for stmt in switch_case.consequent:
                            analysis([stmt], vul_function, back_node, vul_lineno, file_path, function_params)

        if node.type == "VariableDeclaration":  # 函数赋值表达式
            for child_node in node.declarations:

                # 追加到 back_node（即使在函数体内也追加，确保 parameters_back 能回溯到局部变量）
                back_node.append(child_node)

                if child_node.init:
                    if child_node.init.type == "CallExpression":
                        analysis_callexpression(child_node.init, vul_function, back_node, vul_lineno, file_path,
                                                function_params)

                    elif child_node.init.type == "ObjectExpression":
                        object_name = get_member_data(child_node.id)
                        analysis_objectexpression(child_node.init, vul_function, back_node, vul_lineno, file_path,
                                                  function_params, object_name)

                    elif child_node.init.type == "ArrowFunctionExpression":
                        if child_node.init.body.type == "BlockStatement":
                            child_nodes = child_node.init.body.body
                        else:
                            child_nodes = [child_node.init.body]
                        child_params = get_param_list(child_node.init.params)
                        analysis(child_nodes, vul_function, back_node, vul_lineno, file_path,
                                 function_params=child_params, in_funtion=True)

                    elif child_node.init.type == "AwaitExpression":
                        # await expr：提取 argument（通常是 CallExpression）进行分析
                        await_arg = child_node.init.argument
                        if hasattr(await_arg, "type"):
                            if await_arg.type == "CallExpression":
                                analysis_callexpression(await_arg, vul_function, back_node, vul_lineno, file_path, function_params)
                            # 其他类型（如 MemberExpression）暂不处理

        if node.type == "TryStatement":
            # 进入 try 块的 body 分析（async/await 常配合 try-catch）
            try_block = node.block
            if hasattr(try_block, "body"):
                analysis(try_block.body, vul_function, back_node, vul_lineno, file_path,
                         function_params=function_params, in_funtion=in_funtion)

        if node.type == "ClassDeclaration":
            # 处理 ES6 Class 的方法体
            class_body = node.body
            if hasattr(class_body, "body"):
                # 第一步：扫描所有方法中的 this.xxx = yyy 赋值，构建属性映射
                global _this_prop_map, _class_method_param_map
                _this_prop_map = {}
                _class_method_param_map = {}
                for class_member in class_body.body:
                    if class_member.type == "ClassMethod" and class_member.body and class_member.body.type == "BlockStatement":
                        method_name = get_member_data(class_member.key) if hasattr(class_member, "key") else None
                        for stmt in class_member.body.body:
                            if stmt.type == "ExpressionStatement" and hasattr(stmt, "expression"):
                                expr = stmt.expression
                                if expr.type == "AssignmentExpression" and expr.operator == "=":
                                    left = expr.left
                                    right = expr.right
                                    if (hasattr(left, "object") and hasattr(left.object, "type")
                                        and left.object.type == "ThisExpression"
                                        and hasattr(left, "property") and hasattr(left.property, "name")):
                                        prop_name = left.property.name
                                        # 如果右值是方法参数，建立方法参数映射（用于在调用点解析实参）
                                        if method_name and right.type == "Identifier":
                                            for idx, p in enumerate(class_member.params):
                                                if get_member_data(p) == get_member_data(right):
                                                    _class_method_param_map[method_name] = {idx: prop_name}
                                        # 同时存入 this_prop_map（用于非方法参数的简单赋值）
                                        _this_prop_map[prop_name] = right

                # 第 1.5 步：在全文件 AST 中搜索 class 方法调用，解析实参
                if _class_method_param_map:
                    _resolve_class_method_calls(all_nodes, _class_method_param_map)

                # 第二步：进入包含 vul_lineno 的方法体进行分析
                for class_member in class_body.body:
                    if class_member.type == "ClassMethod" and class_member.body and class_member.body.type == "BlockStatement":
                        if class_member.loc.start.line <= vul_lineno <= class_member.loc.end.line:
                            child_nodes = class_member.body.body
                            child_params = get_param_list(class_member.params)
                            # 构造 back_node：复制外层 + 追加方法体节点 + 追加 this 赋值对应的虚拟节点
                            callback_back_node = list(back_node)
                            for n in child_nodes:
                                callback_back_node.append(n)

                            analysis(child_nodes, vul_function, callback_back_node, vul_lineno, file_path,
                                     function_params=child_params, in_funtion=True)

        if node.type == "WhileStatement":
            analysis_while(node, vul_function, back_node, vul_lineno, file_path, function_params)

    return scan_results


def _walk_ast_nodes(node, callback):
    """递归遍历 esprima AST 节点，对每个节点调用 callback(node)"""
    if node is None:
        return
    callback(node)
    # 遍历所有可能的子节点属性
    for attr in ('body', 'consequent', 'alternate', 'cases', 'block', 'expression',
                 'declarations', 'init', 'test', 'update', 'argument', 'arguments',
                 'left', 'right', 'object', 'property', 'callee', 'elements',
                 'properties', 'key', 'value'):
        child = getattr(node, attr, None)
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if item is not None and hasattr(item, 'type'):
                    _walk_ast_nodes(item, callback)
        elif hasattr(child, 'type'):
            _walk_ast_nodes(child, callback)


def _extract_call_name_js(node):
    """
    从 CallExpression 节点提取调用名。
    返回 (callee_name, is_indirect) 元组。
    """
    if not hasattr(node, 'type') or node.type != 'CallExpression':
        return None, False

    callee = node.callee
    is_indirect = False

    if callee.type == 'Identifier':
        # 直接函数调用: func()
        return callee.name, False
    elif callee.type == 'MemberExpression':
        # 方法调用: obj.method()
        name = get_member_data(callee)
        return name, False
    else:
        # 其他类型（如 CallExpression 作为 callee）：间接调用
        return None, True


def _check_js_indirect_assignment(var_name, sink_names, all_nodes):
    """
    JS 赋值追踪：在 AST 中查找 var_name 的赋值，检查赋值右侧是否包含 sink 引用。

    支持模式：
    - const f = eval;       → f = eval（Identifier 直接引用 sink）
    - const f = obj.eval;   → f = obj.eval（MemberExpression 引用 sink）
    - const f = require('child_process').exec → f = exec

    :param var_name: 变量名（如 'f'）
    :param sink_names: sink 名称列表
    :param all_nodes: 文件顶层 AST 节点列表
    :return: bool — 是否发现间接调用
    """
    sink_method_set = {s.method for s in sink_names if s.class_ is None}

    def _walk_and_check(node, visited=None):
        """递归遍历节点查找变量声明和赋值"""
        if visited is None:
            visited = set()
        if not hasattr(node, 'type'):
            return False
        node_type = getattr(node, 'type', '')

        # VariableDeclaration: const/let/var f = <expr>
        if node_type == 'VariableDeclaration':
            for decl in getattr(node, 'declarations', []):
                if not hasattr(decl, 'type'):
                    continue
                decl_id = getattr(decl, 'id', None)
                if hasattr(decl_id, 'type') and getattr(decl_id, 'type', '') == 'Identifier':
                    if getattr(decl_id, 'name', None) == var_name:
                        init = getattr(decl, 'init', None)
                        if _check_value_is_sink(init, sink_method_set):
                            return True
                        # 多层间接调用递归: func2 = func → 查找 func = eval
                        if hasattr(init, 'type') and init.type == 'Identifier':
                            inner_name = init.name
                            if inner_name not in visited:
                                visited.add(inner_name)
                                for top_node in all_nodes:
                                    if _check_js_indirect_assignment_inner(inner_name, sink_method_set, [top_node], visited):
                                        return True

        # AssignmentExpression: f = <expr>
        if node_type == 'AssignmentExpression':
            left = getattr(node, 'left', None)
            if hasattr(left, 'type') and getattr(left, 'type', '') == 'Identifier':
                if getattr(left, 'name', None) == var_name:
                    right = getattr(node, 'right', None)
                    if _check_value_is_sink(right, sink_method_set):
                        return True
                    # 多层间接调用递归: func2 = func → 查找 func = eval
                    if hasattr(right, 'type') and right.type == 'Identifier':
                        inner_name = right.name
                        if inner_name not in visited:
                            visited.add(inner_name)
                            for top_node in all_nodes:
                                if _check_js_indirect_assignment_inner(inner_name, sink_method_set, [top_node], visited):
                                    return True

        # 递归遍历子节点（通过属性遍历，跳过非节点属性）
        for attr_name in dir(node):
            if attr_name.startswith('_') or attr_name in ('type', 'range', 'loc', 'raw', 'line', 'column'):
                continue
            try:
                value = getattr(node, attr_name)
            except Exception:
                continue
            if isinstance(value, list):
                for child in value:
                    if _walk_and_check(child):
                        return True
            elif hasattr(value, 'type'):
                if _walk_and_check(value):
                    return True

        return False

    for top_node in all_nodes:
        if _walk_and_check(top_node):
            return True
    return False


def _check_value_is_sink(value_node, sink_method_set):
    """检查赋值右侧是否是 sink 函数的引用"""
    if not hasattr(value_node, 'type'):
        return False
    node_type = getattr(value_node, 'type', '')

    # 直接引用：const f = eval → Identifier('eval')
    if node_type == 'Identifier':
        return getattr(value_node, 'name', None) in sink_method_set

    # 属性引用：const f = obj.eval → MemberExpression(Identifier('obj'), 'eval')
    if node_type == 'MemberExpression':
        prop = getattr(value_node, 'property', None)
        if hasattr(prop, 'type') and getattr(prop, 'type', '') == 'Identifier':
            return getattr(prop, 'name', None) in sink_method_set

    # CallExpression 链：const f = require('child_process').exec
    if node_type == 'CallExpression':
        callee = getattr(value_node, 'callee', None)
        if hasattr(callee, 'type') and getattr(callee, 'type', '') == 'MemberExpression':
            return _check_value_is_sink(callee, sink_method_set)

    return False


def _check_js_indirect_assignment_inner(var_name, sink_method_set, all_nodes, visited):
    """递归解析间接调用赋值链: func2 = func → func = eval → 匹配 sink"""
    if var_name in visited:
        return False

    for top_node in all_nodes:
        if not hasattr(top_node, 'type'):
            continue
        node_type = getattr(top_node, 'type', '')

        if node_type == 'VariableDeclaration':
            for decl in getattr(top_node, 'declarations', []):
                if not hasattr(decl, 'type'):
                    continue
                decl_id = getattr(decl, 'id', None)
                if hasattr(decl_id, 'type') and getattr(decl_id, 'type', '') == 'Identifier':
                    if getattr(decl_id, 'name', None) == var_name:
                        init = getattr(decl, 'init', None)
                        if _check_value_is_sink(init, sink_method_set):
                            return True
                        if hasattr(init, 'type') and init.type == 'Identifier':
                            inner_name = init.name
                            if inner_name not in visited:
                                visited.add(inner_name)
                                if _check_js_indirect_assignment_inner(inner_name, sink_method_set, all_nodes, visited):
                                    return True

        if node_type == 'AssignmentExpression':
            left = getattr(top_node, 'left', None)
            if hasattr(left, 'type') and getattr(left, 'type', '') == 'Identifier':
                if getattr(left, 'name', None) == var_name:
                    right = getattr(top_node, 'right', None)
                    if _check_value_is_sink(right, sink_method_set):
                        return True
                    if hasattr(right, 'type') and right.type == 'Identifier':
                        inner_name = right.name
                        if inner_name not in visited:
                            visited.add(inner_name)
                            if _check_js_indirect_assignment_inner(inner_name, sink_method_set, all_nodes, visited):
                                return True

    return False


def find_sinks(sink_names, files):
    """
    AST-based sink 查找。遍历所有文件的 AST 节点，查找匹配的函数调用。
    支持直接调用匹配和间接调用检测。

    :param sink_names: list of SinkName(class_, method) from parse_sink_names()
    :param files: 文件路径列表
    :return: list of dict
    """
    from core.utils import SinkName

    results = []

    for file_path in files:
        file_path = ast_object.get_path(file_path)
        if not file_path:
            continue
        _nodes = ast_object.get_nodes(file_path)
        if not _nodes:
            continue

        if isinstance(_nodes, list):
            all_nodes = _nodes
        else:
            all_nodes = getattr(_nodes, 'body', []) or []

        def _check_node(node):
            if not hasattr(node, 'type') or node.type != 'CallExpression':
                return

            callee_name, is_indirect = _extract_call_name_js(node)

            # 赋值追踪：Identifier callee 不匹配 sink 时，查找同名变量的赋值
            if not is_indirect and callee_name and hasattr(node.callee, 'type') and getattr(node.callee, 'type', '') == 'Identifier':
                matched_any = any(
                    s.class_ is None and (callee_name == s.method or callee_name.endswith('.' + s.method))
                    for s in sink_names
                )
                if not matched_any:
                    indirect_info = _check_js_indirect_assignment(callee_name, sink_names, all_nodes)
                    if indirect_info:
                        is_indirect = True

            if is_indirect or callee_name is None:
                # 间接调用
                lineno = node.loc.start.line if hasattr(node, 'loc') and node.loc else 0
                for sink in sink_names:
                    results.append({
                        'file_path': file_path,
                        'lineno': lineno,
                        'node': node,
                        'is_indirect': True,
                        'callee_name': callee_name or '<indirect>',
                        'class_name': None,
                        'matched_sink': sink,
                    })
                    break
                return

            for sink in sink_names:
                if sink.class_ is None:
                    # 模糊匹配
                    short_name = callee_name.split('.')[-1] if '.' in callee_name else callee_name
                    if callee_name == sink.method or short_name == sink.method or callee_name.endswith('.' + sink.method):
                        lineno = node.loc.start.line if hasattr(node, 'loc') and node.loc else 0
                        results.append({
                            'file_path': file_path,
                            'lineno': lineno,
                            'node': node,
                            'is_indirect': False,
                            'callee_name': callee_name,
                            'class_name': callee_name.rsplit('.', 1)[0] if '.' in callee_name else None,
                            'matched_sink': sink,
                        })
                        break
                else:
                    # 精确匹配
                    if callee_name == '{}.{}'.format(sink.class_, sink.method):
                        lineno = node.loc.start.line if hasattr(node, 'loc') and node.loc else 0
                        results.append({
                            'file_path': file_path,
                            'lineno': lineno,
                            'node': node,
                            'is_indirect': False,
                            'callee_name': callee_name,
                            'class_name': sink.class_,
                            'matched_sink': sink,
                        })
                        break

        for top_node in all_nodes:
            _walk_ast_nodes(top_node, _check_node)

    return results


def _init_function_summaries(file_path):
    """初始化 JS 文件的函数摘要"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.function_summary import SummaryCacheManager
        from core.core_engine.javascript.summary_generator import generate_file_summaries, generate_summaries_for_target

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
                if data.get('language') == 'javascript':
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
            logger.debug(f"[AST][JS] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][JS] 摘要初始化失败: {e}")


def _judge_from_summary_js(summary, call_args):
    """根据函数摘要判定返回值可控性（JS版）

    返回: (code, source, expr_lineno) 三元组或 None
    """
    for rf in summary.return_flow:
        if rf.origin_type == "param":
            for param_idx in rf.dep_params:
                if param_idx < len(call_args):
                    is_co, cp = is_controllable(call_args[param_idx])
                    if is_co == 1:
                        return (1, cp, 0)
                    names = _collect_js_var_names(call_args[param_idx])
                    if names:
                        return ('deps', list(names), 0)

        elif rf.origin_type == "global":
            controlled = is_controlled_params + default_controlled_params
            for cp_item in controlled:
                if cp_item in rf.origin:
                    return (1, rf.origin, 0)

        elif rf.origin_type == "call":
            controlled = is_controlled_params + default_controlled_params
            for cp_item in controlled:
                if cp_item in rf.origin:
                    return (1, rf.origin, 0)
            knowledge = lookup_builtin(rf.origin)
            if knowledge and knowledge.get("passthrough"):
                for param_idx in rf.dep_params:
                    if param_idx < len(call_args):
                        is_co, cp = is_controllable(call_args[param_idx])
                        if is_co == 1:
                            return (1, rf.origin, 0)
            # 无内置知识库但有 dep_params → 追踪实参（用户自定义函数包装）
            if rf.dep_params:
                for param_idx in rf.dep_params:
                    if param_idx < len(call_args):
                        is_co, cp = is_controllable(call_args[param_idx])
                        if is_co == 1:
                            return (1, cp, 0)
                        names = _collect_js_var_names(call_args[param_idx])
                        if names:
                            return ('deps', list(names), 0)

        elif rf.origin_type == "literal":
            continue

    return None


def _handle_js_indirect_call(all_nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path):
    """
    处理 JS 间接调用场景：在 AST 中定位 vul_lineno 处的 CallExpression 节点，
    用 indirect_map 确认是间接调用后，提取参数做可控性分析。

    JS AST 是 esprima 格式（dict），不是 ast 模块。

    :param all_nodes: 文件顶层 AST 节点列表
    :param vul_lineno: 漏洞行号（可能是 str 或 int）
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param file_path: 文件路径
    :return: list[dict] 或 None
    """
    global scan_results

    target_line = int(vul_lineno)
    target_node = None

    def _find_at_line(node):
        nonlocal target_node
        if target_node is not None:
            return
        if not hasattr(node, 'type') or getattr(node, 'type', '') != 'CallExpression':
            return
        loc = getattr(node, 'loc', None)
        if not loc:
            return
        start = getattr(loc, 'start', None)
        if not start:
            return
        if int(getattr(start, 'line', 0)) != target_line:
            return
        # 检查 callee 是否在 indirect_map 中
        callee = getattr(node, 'callee', None)
        if callee and hasattr(callee, 'type') and getattr(callee, 'type', '') == 'Identifier':
            if getattr(callee, 'name', '') in indirect_map:
                target_node = node

    for top_node in all_nodes:
        _walk_ast_nodes(top_node, _find_at_line)
        if target_node is not None:
            break

    if target_node is None:
        return None

    # 提取参数做可控性分析
    args = getattr(target_node, 'arguments', []) or []
    for arg in args:
        if not hasattr(arg, 'type'):
            continue
        arg_type = getattr(arg, 'type', '')

        if arg_type == 'Identifier':
            arg_name = getattr(arg, 'name', '')
            if _is_js_controllable(arg_name, controlled_params, file_path, target_line):
                scan_results.append({
                    'code': 1,
                    'chain': [
                        ('source', arg_name, file_path, target_line),
                        ('sink', 'indirect_call', file_path, target_line),
                    ]
                })
                return scan_results

    return None


def _is_js_controllable(var_name, controlled_params, file_path, vul_lineno):
    """
    检查 JS 变量是否可控。

    :param var_name: 变量名
    :param controlled_params: 可控参数列表
    :param file_path: 文件路径
    :param vul_lineno: 行号
    :return: bool
    """
    import re

    if var_name in (controlled_params or []):
        return True

    # 常见可控源模式
    controllable_patterns = [
        r'input', r'request', r'args', r'params', r'query',
        r'param', r'data', r'form', r'cookie', r'header',
        r'user', r'cmd', r'command',
    ]
    for pattern in controllable_patterns:
        if re.search(pattern, var_name, re.IGNORECASE):
            return True

    # 反向追踪：查找变量赋值
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_lines = f.readlines()
    except Exception:
        return False

    # 在源码中查找 var_name 的赋值（在 vul_lineno 之前）
    for i, line in enumerate(source_lines, 1):
        if i >= vul_lineno:
            break
        if re.search(r'(?:const|let|var|,\s*)\s*' + re.escape(var_name) + r'\s*=', line):
            if re.search(r'request|query|params|input|args|data', line, re.IGNORECASE):
                return True

    return False


def scan_parser(sensitive_func, vul_lineno, file_path, repair_functions=[], controlled_params=[], indirect_map=None):
    """
    开始检测函数
    :param controlled_params:
    :param repair_functions:
    :param sensitive_func: 要检测的敏感函数,传入的为函数列表
    :param vul_lineno: 漏洞函数所在行号
    :param file_path: 文件路径
    :param indirect_map: 间接调用映射 {变量名: sink函数名}
    :return:
    """
    try:
        global scan_results, is_repair_functions, is_controlled_params, scan_chain

        _trace_cache.clear()
        global _summaries_initialized
        _summaries_initialized = False
        _init_function_summaries(file_path)
        scan_chain = ['start']
        # Initialize Source Discovery (once per project)
        global _source_registry
        if _source_registry is None:
            project_dir = os.path.dirname(os.path.abspath(file_path))
            try:
                _source_registry = discover_sources(project_dir, ast_object, controlled_list=controlled_params)
            except Exception as e:
                logger.debug('[AST] Source Discovery init error: {0}'.format(e))
        scan_results = []
        is_repair_functions = repair_functions
        is_controlled_params = controlled_params.copy()
        _nodes = ast_object.get_nodes(file_path)
        if (not _nodes) or type(_nodes) is list:
            all_nodes = []
        else:
            all_nodes = getattr(_nodes, 'body', []) or []

        # 初始化 import map（跨文件追踪用）
        import_map = {}
        if all_nodes:
            import_map = _parse_js_imports(_nodes, file_path)

        # 间接调用快速路径
        if indirect_map and isinstance(indirect_map, dict):
            indirect_result = _handle_js_indirect_call(
                all_nodes, vul_lineno, indirect_map, repair_functions, controlled_params, file_path
            )
            if indirect_result:
                return indirect_result

        for func in sensitive_func:  # 循环判断代码中是否存在敏感函数，若存在，递归判断参数是否可控;对文件内容循环判断多次
            back_node = []
            analysis(all_nodes, func, back_node, int(vul_lineno), file_path, function_params=None)

            # 如果检测到一次，那么就可以退出了
            if len(scan_results) > 0:
                logger.debug("[AST] Scan parser end for {}".format(str(scan_results)))
                break

            # 单文件扫描未找到，尝试跨文件追踪
            if not scan_results and import_map:
                cross_result = _try_cross_file_trace_js(
                    all_nodes, int(vul_lineno), sensitive_func, file_path,
                    import_map, controlled_params)
                if cross_result:
                    scan_results = cross_result
                    break

    except Exception as e:
        logger.warning('[AST] [ERROR]:{e}'.format(e=traceback.format_exc()))

    return scan_results
