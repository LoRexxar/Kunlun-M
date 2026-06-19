#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Ruby AST Parser — Ruby 反向污点追踪引擎（基础实现）
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Ruby 语言静态分析引擎，支持正则匹配和 AST 污点追踪。
    当前为基础实现，支持 tree-sitter 解析 + 基本的函数/参数/调用追踪。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
import re
import traceback

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.ruby.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.ruby.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.ruby.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter Ruby AST 解析
import tree_sitter_ruby as _tsruby
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_RUBY_TS_LANGUAGE = _TS_Language(_tsruby.language())
_ts_parser = _TS_Parser(_RUBY_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("ruby")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# Ruby 特有的可控输入源
RUBY_CONTROLLED_SOURCES = [
    "params", "params[]", "params[",
    "request", "request.body",
    "cookies", "cookies[]", "cookies[",
    "session", "session[]", "session[",
    "ENV", "ENV[]", "ENV[",
    "ARGV", "ARGV[",
    "$stdin", "STDIN",
    "gets", "gets.chomp", "readline",
    "open", "File.read", "File.open", "IO.read",
    "URI.parse", "URI.open",
    "Net::HTTP.get", "Net::HTTP.post",
    "JSON.parse", "YAML.load", "YAML.safe_load",
    "ERB", "ERB.new",
    "CGI", "CGI.new", "cgi",
    "Rack::Request", "Sinatra::Request",
    "Rails::Request", "ActionController",
    # Sinatra
    "sinatra", "params",
    # Rails
    "ActiveRecord",
]

# Ruby 特有的敏感函数列表
RUBY_SENSITIVE_SINKS = [
    "eval", "binding.eval", "instance_eval", "class_eval", "module_eval",
    "Kernel.eval", "send", "public_send", "method_missing",
    "system", "exec", "`", "spawn", "IO.popen", "Open3.popen3",
    "Open3.capture3", "Open3.pipeline",
    "File.open", "File.write", "File.delete", "File.read",
    "IO.read", "IO.write", "IO.popen",
    "Kernel.system", "Kernel.exec", "Kernel.spawn", "Kernel.open",
    "require", "require_relative", "load",
    "Dir.glob", "Dir[]", "Dir.chdir", "FileUtils.rm", "FileUtils.cp",
    "FileUtils.mv", "FileUtils.mkdir", "FileUtils.touch",
    "ActiveRecord::Base.connection.execute",
    "ActiveRecord::Base.find_by_sql",
    "Model.find_by_sql", "Model.where", "Model.first", "Model.last",
    "User.where", "User.find_by",
    "Net::HTTP.get", "Net::HTTP.post", "Net::HTTP.start",
    "URI.open", "open-uri",
    "Kernel.puts", "puts", "print", "printf", "p",
    "ERB.new", "ERB.result",
    "render", "render_to_string", "render_template",
    "send_file", "send_data",
    "redirect_to", "redirect",
    "cookies[]=", "session[]=", "flash[]=",
    "Marshal.dump", "Marshal.load",
    "YAML.dump", "YAML.load",
    "exec", "system", "spawn",
    "Base64.decode64", "Base64.encode64",
]


def _extract_var_names_from_expr(expr):
    """
    从 Ruby 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串插值 (#{var})、简单变量、方法调用
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 字符串插值: "Hello #{name}" 或 "Hello #{user.name}"
    # 提取 #{} 中的变量名
    interpolations = re.findall(r'#\{([^}]+)\}', expr)
    for interp in interpolations:
        interp = interp.strip()
        ident = re.match(r'^([a-zA-Z_@]\w*(?:\.\w+)*)', interp)
        if ident:
            names.append(ident.group(1))

    # 字符串拼接: "a" + var + "b"
    if '+' in expr and '#' not in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith("'") and part.endswith("'")):
                continue
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            ident = re.match(r'^([a-zA-Z_@]\w*(?:\.\w+)*)', part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'nil', 'self', 'super',
                                'String', 'Array', 'Hash', 'Integer', 'Float',
                                'Symbol', 'Class', 'Module', 'Object',
                                'puts', 'print', 'p', 'gets', 'chomp'):
                    names.append(name)
        return names

    # 方法调用透传: var.method(args)
    call_match = re.match(r'^([a-zA-Z_@]\w*(?:\.\w+)*)\s*\((.+)\)$', expr)
    if call_match:
        func_name = call_match.group(1)
        knowledge = lookup_builtin(func_name)
        if knowledge and (knowledge.get("passthrough") or knowledge.get("param_flow")):
            inner_args = call_match.group(2)
            for a in inner_args.split(','):
                a = a.strip()
                if a.startswith('"') and a.endswith('"'):
                    continue
                ident = re.match(r'^([a-zA-Z_@]\w*)', a)
                if ident:
                    names.append(ident.group(1))
        return names

    # 简单变量名
    simple = re.match(r'^([a-zA-Z_@]\w*(?:\.\w+)*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _ruby_line_to_text(file_path, lineno):
    """从源文件读取指定行的文本"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            if 1 <= lineno <= len(lines):
                return lines[lineno - 1].strip()
    except Exception:
        pass
    return ""


def _init_function_summaries(file_path):
    """初始化当前文件及依赖文件的函数摘要（带缓存）"""
    global _summaries_initialized, _file_summaries

    if _summaries_initialized:
        return

    try:
        from core.core_engine.function_summary import SummaryCacheManager
        from core.core_engine.ruby.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'ruby':
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
            logger.debug(f"[AST][Ruby] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Ruby] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}
_import_cache = {}


def _parse_ruby_ast(file_path):
    """解析 Ruby 文件为 tree-sitter AST，带缓存"""
    if file_path in _ast_cache:
        return _ast_cache[file_path]

    if not _HAS_TREE_SITTER:
        return None

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = _ts_parser.parse(source.encode('utf-8'))
        _ast_cache[file_path] = tree
        return tree
    except Exception as e:
        logger.warning(f"[AST][Ruby] 解析失败 {file_path}: {e}")
        return None


def _node_text(node):
    """获取 tree-sitter 节点的文本内容"""
    if node is None:
        return ""
    try:
        return node.text.decode('utf-8', errors='ignore')
    except (AttributeError, UnicodeDecodeError):
        return ""


def _find_method_node(root_node, func_name, is_method=False, class_type=None):
    """在 AST 中查找指定名称的方法定义"""
    if root_node is None:
        return None

    for child in root_node.children:
        if child.type == 'method':
            name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

        # class/module body
        if child.type in ('class', 'module'):
            body = None
            for c in child.children:
                if c.type == 'body_statement':
                    body = c
                    break
            if body:
                result = _find_method_node(body, func_name, is_method, class_type)
                if result:
                    return result

    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/unless/while/until）
# ---------------------------------------------------------------------------

def _extract_constraints_from_ruby_expr(cond_node):
    """从 Ruby 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _get_var_name(n):
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'instance_variable':
            return _node_text(n)
        if n.type == 'call':
            recv = None
            for c in n.children:
                if c.type == 'receiver':
                    recv = c
                    break
            if recv:
                return _get_var_name(recv)
        return None

    def _get_literal_value(n):
        if n is None:
            return None
        if n.type in ('integer', 'float'):
            try:
                return int(_node_text(n))
            except ValueError:
                return _node_text(n)
        if n.type in ('string', 'string_content'):
            return _node_text(n).strip('"').strip("'")
        if n.type == 'true':
            return True
        if n.type == 'false':
            return False
        if n.type == 'nil':
            return None
        return None

    if node_type == 'binary':
        children = cond_node.children
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in children:
            if child.type in ('==', '!=', '>=', '<=', '>', '<', '&&', '||',
                              'and', 'or', '=~', '!~', '==='):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        op_text = _node_text(op_node) if op_node else ''

        if op_text in ('&&', 'and'):
            if left_node:
                constraints.extend(_extract_constraints_from_ruby_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_ruby_expr(right_node))
            return constraints

        if op_text in ('||', 'or'):
            if left_node:
                constraints.extend(_extract_constraints_from_ruby_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_ruby_expr(right_node))
            return constraints

        if op_text in ('==', '!=', '=~', '==='):
            var_name = _get_var_name(left_node)
            if var_name:
                value = _get_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
            else:
                var_name = _get_var_name(right_node)
                if var_name:
                    value = _get_literal_value(left_node)
                    neg_op = '!=' if op_text == '==' else '=='
                    constraints.append(BranchConstraint(var_name=var_name, op=neg_op, value=value))

        return constraints

    if node_type == 'call':
        func_name = ""
        args = []
        for child in cond_node.children:
            if child.type == 'identifier':
                func_name = _node_text(child)
            elif child.type == 'argument_list':
                args = [c for c in child.children if c.type not in ('(', ')', ',')]

        if func_name and args:
            RUBY_TYPE_FUNCS = {
                'is_a?', 'kind_of?',
                'nil?', 'empty?', 'blank?', 'present?',
                'numeric?', 'integer?', 'float?',
                'match?', 'include?', 'start_with?', 'end_with?',
            }
            if func_name in RUBY_TYPE_FUNCS and len(args) >= 1:
                var_name = _get_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

    return constraints


def _find_enclosing_if_for_ruby(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if/unless 或 while/until/for 语句节点。"""
    best = [None]

    def _search(node):
        if node.type in ('if', 'unless'):
            for child in node.children:
                if child.type == 'body_statement':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break

        elif node.type in ('while', 'until', 'for'):
            for child in node.children:
                if child.type == 'body_statement':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'for')
                        break

        for child in node.children:
            _search(child)

    _search(root_node)
    return best[0]


def _check_ruby_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_ruby_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_if_for_ruby(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_ruby_if_constraint(node, vul_lineno, var_name)
    elif node_type == 'for':
        return _check_ruby_for_constraint(node, vul_lineno, var_name)

    return False


def _check_ruby_if_constraint(if_node, vul_lineno, var_name):
    """检查 Ruby if/unless/elsif 分支约束。"""
    cond_node = None
    if_body = None
    else_body = None

    for child in if_node.children:
        if child.type == 'elsif':
            result = _check_ruby_if_constraint(child, vul_lineno, var_name)
            if result:
                return result
        elif child.type == 'else':
            else_body = child
        elif child.type == 'body_statement' and if_body is None:
            if_body = child
        elif child.type not in ('if', 'unless', 'then', 'end', 'body_statement', 'elsif', 'else'):
            if cond_node is None:
                cond_node = child

    if cond_node is None:
        return False

    if_start = if_body.start_point[0] + 1 if if_body else None
    if_end = if_body.end_point[0] + 1 if if_body else None
    else_start = else_body.start_point[0] + 1 if else_body else None
    else_end = else_body.end_point[0] + 1 if else_body else None

    in_if = if_start is not None and if_end is not None and if_start <= vul_lineno <= if_end
    in_else = else_start is not None and else_end is not None and else_start <= vul_lineno <= else_end

    if not in_if and not in_else:
        return False

    constraints = _extract_constraints_from_ruby_expr(cond_node)

    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('==', '=~', '===', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][Ruby] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!=', 'not in'):
            logger.info("[AST][Ruby] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_ruby_for_constraint(for_node, vul_lineno, var_name):
    """检查 Ruby while/until/for 条件约束。"""
    cond_node = None
    body_node = None

    for child in for_node.children:
        if child.type == 'body_statement' and body_node is None:
            body_node = child
        elif child.type not in ('while', 'until', 'for', 'in', 'do', 'end', 'body_statement'):
            if cond_node is None:
                cond_node = child

    if body_node is None:
        return False

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return False

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_ruby_expr(cond_node)

    for c in constraints:
        if c.var_name == var_name and c.op in ('==', '=~', '===', 'in', 'type_validated', 'regex_validated'):
            return True

    return False


# ---------------------------------------------------------------------------
# AST 污点追踪核心逻辑
# ---------------------------------------------------------------------------

def _scan_function_ast(func_node, func_name, file_path, params, param_lineno_map,
                       scan_result, vul_function, depth=0):
    """
    在单个方法的 AST 中进行污点追踪。

    基础实现：遍历函数体，识别变量赋值和函数调用，
    追踪可控数据从参数到敏感函数调用点的传播路径。
    """
    if depth > 15:
        return scan_result

    body = None
    for child in func_node.children:
        if child.type == 'body_statement':
            body = child
            break

    if body is None:
        return scan_result

    # 收集函数体中的赋值关系
    assignments = _collect_assignments(body)

    # 收集函数体中的函数调用
    calls = _collect_calls(body)

    # 分析每个函数调用是否使用了可控参数
    for call_info in calls:
        call_lineno = call_info['lineno']
        call_name = call_info['name']
        call_args = call_info['args']

        # 检查是否为敏感函数
        if not _is_sink(call_name):
            continue

        # 检查是否有可控参数流入敏感函数
        controlled_params = _find_controlled_params_in_call(
            call_args, params, assignments, body)

        if controlled_params:
            for cp in controlled_params:
                result_data = {
                    'code': _ruby_line_to_text(file_path, call_lineno),
                    'sink': call_name,
                    'source': cp,
                    'source_lineno': param_lineno_map.get(cp, '?'),
                    'vul_lineno': call_lineno,
                    'vul_function': func_name,
                }
                scan_result.append(result_data)
                logger.info("[AST][Ruby] Taint found: {} -> {} at line {} ({})".format(
                    cp, call_name, call_lineno, func_name))

    return scan_result


def _collect_assignments(body_node):
    """
    收集块中的赋值关系。
    返回 {变量名: 赋值表达式节点}
    """
    assignments = {}

    def _walk(node):
        for child in node.children:
            if child.type == 'assignment':
                left = None
                right = None
                for c in child.children:
                    if c.type == '=':
                        continue
                    if left is None:
                        left = c
                    elif right is None:
                        right = c
                        break
                if left and right:
                    left_text = _node_text(left)
                    # Strip simple identifiers and instance variables
                    if re.match(r'^[a-zA-Z_@]\w*$', left_text):
                        assignments[left_text] = right
            elif child.type in ('if', 'unless', 'while', 'until', 'for',
                               'case', 'begin', 'body_statement',
                               'block', 'lambda'):
                _walk(child)

    _walk(body_node)
    return assignments


def _collect_calls(body_node):
    """
    收集块中的函数调用。
    返回 [{'name': str, 'args': [str], 'lineno': int}]
    """
    calls = []

    def _walk(node):
        for child in node.children:
            if child.type == 'call':
                func_name = ""
                args = []
                lineno = child.start_point[0] + 1
                for c in child.children:
                    if c.type == 'identifier':
                        func_name = _node_text(c)
                    elif c.type == 'argument_list':
                        args = _extract_arg_names(c)
                if func_name:
                    calls.append({'name': func_name, 'args': args, 'lineno': lineno})
            elif child.type in ('if', 'unless', 'while', 'until', 'for',
                               'case', 'begin', 'body_statement',
                               'block', 'lambda'):
                _walk(child)

    _walk(body_node)
    return calls


def _extract_arg_names(arg_list_node):
    """从参数列表节点中提取参数变量名列表。"""
    names = []
    for child in arg_list_node.children:
        if child.type in ('(', ')', ','):
            continue
        if child.type in ('identifier', 'instance_variable', 'constant'):
            names.append(_node_text(child))
        elif child.type in ('integer', 'float', 'string',
                           'string_content', 'true', 'false', 'nil',
                           'simple_symbol', 'symbol'):
            continue
        else:
            inner_names = _extract_var_names_from_expr(_node_text(child))
            names.extend(inner_names)
    return names


def _is_sink(func_name):
    """检查函数是否为敏感函数。"""
    for sink in RUBY_SENSITIVE_SINKS:
        if func_name == sink or func_name.endswith('.' + sink.split('.')[-1]):
            return True
    knowledge = lookup_builtin(func_name)
    if knowledge and not knowledge.get('safe', True):
        return True
    return False


def _is_controlled_var(var_name, params, assignments, body, depth):
    """检查变量是否可控（递归追踪赋值链）。"""
    if depth > 10:
        return False

    if var_name in params:
        return True

    if var_name in assignments:
        expr = assignments[var_name]
        expr_names = _extract_var_names_from_expr(_node_text(expr))
        for name in expr_names:
            if _is_controlled_var(name, params, assignments, body, depth + 1):
                return True

    return False


def _find_controlled_params_in_call(args, params, assignments, body):
    """找出调用中哪些参数是可控的。"""
    controlled = []
    for arg in args:
        if _is_controlled_var(arg, params, assignments, body, 0):
            if arg in params:
                controlled.append(arg)
            else:
                origin = _trace_to_origin(arg, params, assignments, body, 0)
                if origin in params:
                    controlled.append(origin)
                else:
                    controlled.append(arg)
    return controlled


def _trace_to_origin(var_name, params, assignments, body, depth):
    """追溯变量的源头参数。"""
    if depth > 10:
        return var_name

    if var_name in params:
        return var_name

    if var_name in assignments:
        expr = assignments[var_name]
        expr_names = _extract_var_names_from_expr(_node_text(expr))
        for name in expr_names:
            origin = _trace_to_origin(name, params, assignments, body, depth + 1)
            if origin in params:
                return origin

    return var_name


# ---------------------------------------------------------------------------
# 主入口函数
# ---------------------------------------------------------------------------

def scan_parser(code_content, file_path, vul_function, fix_module=None):
    """
    Ruby AST 污点追踪引擎主入口。

    :param code_content: 源文件内容
    :param file_path: 文件路径
    :param vul_function: 漏洞函数名
    :param fix_module: 修复模块（预留）
    :return: scan_results 列表
    """
    global scan_results
    scan_results = []

    if not _HAS_TREE_SITTER:
        logger.debug("[AST][Ruby] tree-sitter 不可用，跳过 AST 分析")
        return scan_results

    tree = _parse_ruby_ast(file_path)
    if tree is None:
        return scan_results

    root = tree.root_node

    # 初始化函数摘要
    _init_function_summaries(file_path)

    # 查找目标函数（搜索顶层和 class/module 内部）
    func_node = _find_method_node(root, vul_function)
    if func_node is None:
        logger.debug(f"[AST][Ruby] 未找到方法定义: {vul_function}")
        return scan_results

    # 提取方法参数
    params = []
    param_lineno_map = {}
    params_node = None
    for child in func_node.children:
        if child.type == 'method_parameters':
            params_node = child
            break

    if params_node:
        for child in params_node.children:
            if child.type == 'parameter':
                pname = None
                for c in child.children:
                    if c.type in ('identifier', 'instance_variable'):
                        pname = _node_text(c)
                        break
                if pname:
                    params.append(pname)
                    param_lineno_map[pname] = child.start_point[0] + 1

    # 执行 AST 污点追踪
    scan_result = []
    _scan_function_ast(func_node, vul_function, file_path, params,
                       param_lineno_map, scan_result, vul_function)

    if scan_result:
        scan_results = scan_result
        logger.info(f"[AST][Ruby] 发现 {len(scan_result)} 个污点传播路径")
    else:
        logger.debug(f"[AST][Ruby] 未发现污点传播路径")

    return scan_results


def scan_regex(code_content, file_path, vul_function, fix_module=None):
    """
    Ruby 正则匹配引擎（预留）。

    基础实现暂不支持正则匹配。
    """
    return []


# ---------------------------------------------------------------------------
# 新规则生成支持
# ---------------------------------------------------------------------------

def new_scan_param(file_path, code_content, target_func):
    """
    分析方法参数，判断哪些参数可能影响返回值。

    :param file_path: 文件路径
    :param code_content: 源文件内容
    :param target_func: 目标方法名
    :return: (参数索引列表, 可控参数列表)
    """
    if not _HAS_TREE_SITTER:
        return [], []

    tree = _parse_ruby_ast(file_path)
    if tree is None:
        return [], []

    root = tree.root_node
    func_node = _find_method_node(root, target_func)
    if func_node is None:
        return [], []

    # 提取参数
    params = []
    params_node = None
    for child in func_node.children:
        if child.type == 'method_parameters':
            params_node = child
            break

    if params_node:
        idx = 0
        for child in params_node.children:
            if child.type == 'parameter':
                pname = None
                for c in child.children:
                    if c.type in ('identifier', 'instance_variable'):
                        pname = _node_text(c)
                        break
                if pname:
                    params.append((idx, pname))
                idx += 1

    # 分析返回值是否依赖参数
    body = None
    for child in func_node.children:
        if child.type == 'body_statement':
            body = child
            break

    controlled_indices = []
    if body:
        assignments = _collect_assignments(body)
        for param_idx, param_name in params:
            if _param_in_return(body, param_name, assignments):
                controlled_indices.append(param_idx)

    indices = [i for i, _ in params]
    controlled_names = [name for i, name in params if i in controlled_indices]

    return indices, controlled_names


def _param_in_return(body_node, param_name, assignments):
    """检查参数是否在 return 语句中使用"""
    for child in body_node.children:
        if child.type == 'return':
            ret_text = _node_text(child)
            if param_name in ret_text:
                return True
        elif child.type in ('if', 'unless', 'while', 'until', 'for',
                           'case', 'begin', 'body_statement', 'block'):
            if _param_in_return(child, param_name, assignments):
                return True
    return False
