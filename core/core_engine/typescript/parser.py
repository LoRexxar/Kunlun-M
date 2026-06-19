#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    TypeScript AST Parser — TypeScript 反向污点追踪引擎（基础实现）
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    TypeScript 语言静态分析引擎，支持正则匹配和 AST 污点追踪。
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
from core.core_engine.typescript.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.typescript.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.typescript.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter TypeScript AST 解析
import tree_sitter_typescript as _tsts
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_TS_TS_LANGUAGE = _TS_Language(_tsts.language_typescript())
_ts_parser = _TS_Parser(_TS_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("typescript")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# TypeScript 特有的可控输入源
TS_CONTROLLED_SOURCES = [
    "process.env", "process.argv",
    "req.query", "req.body", "req.params", "req.headers",
    "req.cookies", "req.files", "req.url",
    "request.query", "request.body", "request.params",
    "request.headers", "request.cookies",
    "ctx.query", "ctx.querystring", "ctx.params",
    "ctx.request.body", "ctx.request.query",
    "location.hash", "location.search", "location.href",
    "document.cookie", "document.URL",
    "document.referrer", "document.domain",
    "window.name", "window.location",
]

# TypeScript 特有的敏感函数列表
TS_SENSITIVE_SINKS = [
    "eval", "Function", "setTimeout", "setInterval",
    "innerHTML", "outerHTML", "document.write",
    "document.writeln", "insertAdjacentHTML",
    "fs.readFile", "fs.writeFile", "fs.unlink",
    "child_process.exec", "child_process.spawn",
    "child_process.execSync", "child_process.spawnSync",
    "require", "import",
    "console.log", "console.error", "console.warn",
    "process.stdout.write", "process.stderr.write",
    "res.send", "res.json", "res.render",
    "response.send", "response.json",
    "$", "jQuery",
    "fetch", "XMLHttpRequest", "axios",
    "document.createElement", "element.setAttribute",
    "express.static", "express.json", "express.urlencoded",
]


def _extract_var_names_from_expr(expr):
    """
    从 TypeScript 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：模板字符串、字符串拼接、简单变量、方法调用
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 模板字符串: `Hello ${name}`
    if '`' in expr:
        # 提取 ${...} 中的变量
        tmpl_match = re.findall(r'\$\{([^}]+)\}', expr)
        for tmpl_expr in tmpl_match:
            inner_names = _extract_var_names_from_expr(tmpl_expr)
            names.extend(inner_names)
        return names

    # 字符串拼接: "a" + var + "b"
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith("'") and part.endswith("'")):
                continue
            if (part.startswith('`') and part.endswith('`')):
                continue
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            ident = re.match(r'^([a-zA-Z_$]\w*(?:\.[a-zA-Z_$]\w*)*)', part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'null', 'undefined', 'NaN',
                                'Infinity', 'this', 'super',
                                'String', 'Number', 'Boolean',
                                'Object', 'Array', 'Map', 'Set',
                                'Promise', 'console', 'Math',
                                'JSON', 'Error', 'RegExp',
                                'Date', 'Symbol', 'BigInt'):
                    names.append(name)
        return names

    # 方法调用透传: var.method(args)
    call_match = re.match(r'^(\w+(?:\.\w+)*)\s*\((.+)\)$', expr)
    if call_match:
        func_name = call_match.group(1)
        knowledge = lookup_builtin(func_name)
        if knowledge and (knowledge.get("passthrough") or knowledge.get("param_flow")):
            inner_args = call_match.group(2)
            for a in inner_args.split(','):
                a = a.strip()
                ident = re.match(r'^([a-zA-Z_$]\w*)', a)
                if ident and not (a.startswith('"') or a.startswith("'")):
                    names.append(ident.group(1))
        return names

    # 简单变量名或属性访问
    simple = re.match(r'^([a-zA-Z_$]\w*(?:\.[a-zA-Z_$]\w*)*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _ts_line_to_text(file_path, lineno):
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
        from core.core_engine.typescript.summary_generator import generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') in ('typescript', 'javascript'):
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
            logger.debug(f"[AST][TypeScript] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][TypeScript] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}
_import_cache = {}


def _parse_ts_ast(file_path):
    """解析 TypeScript 文件为 tree-sitter AST，带缓存"""
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
        logger.warning(f"[AST][TypeScript] 解析失败 {file_path}: {e}")
        return None


def _node_text(node):
    """获取 tree-sitter 节点的文本内容"""
    if node is None:
        return ""
    try:
        return node.text.decode('utf-8', errors='ignore')
    except (AttributeError, UnicodeDecodeError):
        return ""


def _find_function_node(root_node, func_name, is_method=False, class_type=None):
    """在 AST 中查找指定名称的函数定义"""
    if root_node is None:
        return None

    for child in root_node.children:
        if child.type in ('function_declaration', 'generator_function_declaration'):
            name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

        if child.type == 'method_definition':
            name_node = None
            for c in child.children:
                if c.type in ('property_identifier', 'private_property_identifier'):
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

        if child.type in ('class_declaration', 'abstract_class_declaration'):
            # 检查 class 中的方法
            cls_name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    cls_name_node = c
                    break
            cls_name = _node_text(cls_name_node) if cls_name_node else None
            if class_type is None or cls_name == class_type:
                class_body = None
                for c in child.children:
                    if c.type == 'class_body':
                        class_body = c
                        break
                if class_body:
                    result = _find_function_node(class_body, func_name, is_method=True, class_type=cls_name)
                    if result:
                        return result

        # 递归进入 statement_block, export_statement 等
        if child.type in ('statement_block', 'export_statement',
                          'program', 'lexical_declaration'):
            result = _find_function_node(child, func_name, is_method, class_type)
            if result:
                return result

    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/loop）
# ---------------------------------------------------------------------------

def _extract_constraints_from_ts_expr(cond_node):
    """从 TypeScript 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _get_var_name(n):
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'member_expression':
            # 最左边的对象
            if n.children:
                return _get_var_name(n.children[0])
        if n.type == 'call_expression':
            return None
        return None

    def _get_literal_value(n):
        if n is None:
            return None
        if n.type in ('number', 'string', 'null', 'true', 'false'):
            text = _node_text(n)
            if n.type == 'number':
                try:
                    return int(text)
                except ValueError:
                    return text
            if n.type in ('string',):
                return text.strip('"').strip("'")
            if n.type == 'true':
                return True
            if n.type == 'false':
                return False
            if n.type == 'null':
                return None
        return None

    def _is_type_check_call(func_name):
        """检查是否为类型检查/验证函数"""
        type_funcs = {
            'typeof', 'parseInt', 'parseFloat', 'Number', 'String',
            'isNaN', 'isFinite', 'Number.isInteger', 'Number.isFinite',
            'Array.isArray', 'Buffer.isBuffer',
            'validator.isEmail', 'validator.isURL', 'validator.isInt',
            'validator.isNumeric', 'validator.isAlpha', 'validator.matches',
            'z.string', 'z.number', 'z.boolean',
        }
        return func_name in type_funcs

    if node_type == 'binary_expression':
        children = cond_node.children
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in children:
            if child.type in ('==', '!=', '===', '!==', '>=', '<=', '>', '<',
                              '&&', '||', '??', 'in', 'instanceof'):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        op_text = _node_text(op_node) if op_node else ''

        if op_text in ('&&', '||', '??'):
            if left_node:
                constraints.extend(_extract_constraints_from_ts_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_ts_expr(right_node))
            return constraints

        if op_text in ('===', '!==', '==', '!='):
            var_name = _get_var_name(left_node)
            if var_name:
                value = _get_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
            else:
                var_name = _get_var_name(right_node)
                if var_name:
                    value = _get_literal_value(left_node)
                    neg_op = '!=' if op_text in ('==', '===') else '=='
                    constraints.append(BranchConstraint(var_name=var_name, op=neg_op, value=value))

        if op_text == 'instanceof':
            var_name = _get_var_name(left_node)
            if var_name:
                type_name = _node_text(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=type_name))

        return constraints

    if node_type == 'unary_expression':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == '!' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                inner_constraints = _extract_constraints_from_ts_expr(inner)
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
            elif child.type in ('member_expression', 'call_member_expression'):
                func_node = child
            elif child.type == 'arguments':
                args = [c for c in child.children if c.type not in ('(', ')', ',')]

        if func_node and args:
            func_name = _node_text(func_node)
            if _is_type_check_call(func_name) and len(args) >= 1:
                var_name = _get_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

        return constraints

    # typeof expression: typeof x === "string"
    if node_type in ('parenthesized_expression',):
        for child in cond_node.children:
            if child.type not in ('(', ')'):
                return _extract_constraints_from_ts_expr(child)

    return constraints


def _find_enclosing_if_for_ts(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if 或 for/while/switch 语句节点。"""
    best = [None]

    def _search(node):
        if node.type == 'if_statement':
            # consequent = statement_block
            for child in node.children:
                if child.type == 'statement_block':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break
                elif child.type == 'else_clause':
                    for ec in child.children:
                        if ec.type == 'statement_block':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                                    best[0] = (node, 'if')
                                break
                        elif ec.type == 'if_statement':
                            _search(ec)

        elif node.type in ('for_statement', 'while_statement', 'do_statement',
                           'for_in_statement'):
            for child in node.children:
                if child.type == 'statement_block':
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


def _check_ts_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_ts_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_if_for_ts(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_ts_if_constraint(node, vul_lineno, var_name)
    elif node_type == 'for':
        return _check_ts_for_constraint(node, vul_lineno, var_name)

    return False


def _check_ts_if_constraint(if_node, vul_lineno, var_name):
    """检查 TypeScript if/else 分支约束。"""
    cond_node = None
    if_body = None
    else_body = None

    for child in if_node.children:
        if child.type == 'else_clause':
            for ec in child.children:
                if ec.type == 'statement_block':
                    else_body = ec
                elif ec.type == 'if_statement':
                    return _check_ts_if_constraint(ec, vul_lineno, var_name)
        elif child.type == 'statement_block' and if_body is None:
            if_body = child
        if child.type not in ('if', 'statement_block', 'else_clause') and cond_node is None:
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

    constraints = _extract_constraints_from_ts_expr(cond_node)

    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('===', '==', 'instanceof', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][TypeScript] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!==', '!=', 'not in'):
            logger.info("[AST][TypeScript] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_ts_for_constraint(for_node, vul_lineno, var_name):
    """检查 TypeScript for/while 条件约束。"""
    cond_node = None
    body_node = None

    for child in for_node.children:
        if child.type == 'statement_block' and body_node is None:
            body_node = child
        elif child.type not in ('for', 'for_in', 'while', 'do', 'statement_block') and cond_node is None:
            cond_node = child

    if body_node is None:
        return False

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return False

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_ts_expr(cond_node)

    for c in constraints:
        if c.var_name == var_name and c.op in ('===', '==', 'instanceof', 'in', 'type_validated', 'regex_validated'):
            return True

    return False


# ---------------------------------------------------------------------------
# AST 污点追踪核心逻辑
# ---------------------------------------------------------------------------

def _scan_function_ast(func_node, func_name, file_path, params, param_lineno_map,
                       scan_result, vul_function, depth=0):
    """
    在单个函数的 AST 中进行污点追踪。

    基础实现：遍历函数体，识别变量赋值和函数调用，
    追踪可控数据从参数到敏感函数调用点的传播路径。
    """
    if depth > 15:
        return scan_result

    # 找函数体：statement_block
    block = None
    for child in func_node.children:
        if child.type == 'statement_block':
            block = child
            break

    if block is None:
        return scan_result

    # 收集函数体中的赋值关系
    assignments = _collect_assignments(block)

    # 收集函数体中的函数调用
    calls = _collect_calls(block)

    # 分析每个函数调用是否使用了可控参数
    for call_info in calls:
        call_lineno = call_info['lineno']
        call_name = call_info['name']
        call_args = call_info['args']

        # 检查是否为敏感函数
        if not _is_sink(call_name):
            # 检查参数是否可控（递归追踪）
            for arg_name in call_args:
                if _is_controlled_var(arg_name, params, assignments, block, 0):
                    pass
            continue

        # 检查是否有可控参数流入敏感函数
        controlled_params = _find_controlled_params_in_call(
            call_args, params, assignments, block)

        if controlled_params:
            for cp in controlled_params:
                result_data = {
                    'code': _ts_line_to_text(file_path, call_lineno),
                    'sink': call_name,
                    'source': cp,
                    'source_lineno': param_lineno_map.get(cp, '?'),
                    'vul_lineno': call_lineno,
                    'vul_function': func_name,
                }
                scan_result.append(result_data)
                logger.info("[AST][TypeScript] Taint found: {} -> {} at line {} ({})".format(
                    cp, call_name, call_lineno, func_name))

    return scan_result


def _collect_assignments(block_node):
    """
    收集块中的赋值关系。
    返回 {变量名: 赋值表达式节点}
    """
    assignments = {}

    def _walk(node):
        for child in node.children:
            if child.type in ('lexical_declaration', 'variable_declaration'):
                var_name = None
                init_expr = None
                for c in child.children:
                    if c.type == 'identifier' and var_name is None:
                        var_name = _node_text(c)
                    if c.type == 'variable_declarator':
                        for vc in c.children:
                            if vc.type == 'identifier' and not var_name:
                                var_name = _node_text(vc)
                            if init_expr is None and vc.type in (
                                'call_expression', 'call_member_expression',
                                'member_expression', 'binary_expression',
                                'unary_expression', 'template_string',
                                'arrow_function', 'function_expression',
                                'new_expression', 'identifier',
                                'parenthesized_expression', 'ternary_expression',
                                'as_expression', 'non_null_expression',
                                'await_expression', 'type_assertion',
                                'array', 'object', 'assignment_expression',
                                'spread_element',
                            ):
                                init_expr = vc
                                break
                if var_name and init_expr:
                    assignments[var_name] = init_expr
            elif child.type == 'expression_statement':
                inner = None
                for c in child.children:
                    if c.type == 'assignment_expression':
                        inner = c
                        break
                if inner:
                    left = None
                    right = None
                    found_eq = False
                    for c in inner.children:
                        if c.type == '=':
                            found_eq = True
                            continue
                        if not found_eq and left is None:
                            if c.type == 'identifier':
                                left = _node_text(c)
                            elif c.type == 'member_expression':
                                # 取最后的 property
                                left = _node_text(c)
                        elif found_eq and right is None:
                            right = c
                            break
                    if left and right:
                        assignments[left] = right
            elif child.type in ('if_statement', 'for_statement', 'while_statement',
                               'do_statement', 'for_in_statement',
                               'switch_statement', 'try_statement', 'with_statement',
                               'statement_block', 'labeled_statement'):
                _walk(child)

    _walk(block_node)
    return assignments


def _collect_calls(block_node):
    """
    收集块中的函数调用。
    返回 [{'name': str, 'args': [str], 'lineno': int}]
    """
    calls = []

    def _walk(node):
        for child in node.children:
            if child.type == 'call_expression':
                func_name = ""
                args = []
                lineno = child.start_point[0] + 1
                for c in child.children:
                    if c.type == 'identifier':
                        func_name = _node_text(c)
                    elif c.type == 'arguments':
                        args = _extract_arg_names(c)
                if func_name:
                    calls.append({'name': func_name, 'args': args, 'lineno': lineno})
            elif child.type == 'call_member_expression':
                func_name = ""
                args = []
                lineno = child.start_point[0] + 1
                for c in child.children:
                    if c.type == 'property_identifier':
                        func_name = _node_text(c)
                    elif c.type == 'arguments':
                        args = _extract_arg_names(c)
                if func_name:
                    calls.append({'name': func_name, 'args': args, 'lineno': lineno})
            elif child.type in ('if_statement', 'for_statement', 'while_statement',
                               'do_statement', 'for_in_statement',
                               'switch_statement', 'try_statement', 'with_statement',
                               'statement_block', 'labeled_statement'):
                _walk(child)

    _walk(block_node)
    return calls


def _extract_arg_names(arg_list_node):
    """从参数列表节点中提取参数变量名列表。"""
    names = []
    for child in arg_list_node.children:
        if child.type in ('(', ')', ','):
            continue
        if child.type == 'identifier':
            names.append(_node_text(child))
        elif child.type in ('number', 'string', 'true', 'false', 'null', 'undefined',
                           'template_string', 'regex', 'undefined'):
            continue
        else:
            # 复杂表达式：提取其中的标识符
            inner_names = _extract_var_names_from_expr(_node_text(child))
            names.extend(inner_names)
    return names


def _is_sink(func_name):
    """检查函数是否为敏感函数。"""
    for sink in TS_SENSITIVE_SINKS:
        if func_name == sink or func_name.endswith('.' + sink.split('.')[-1]):
            return True
    # 检查内置知识库中的 sink
    knowledge = lookup_builtin(func_name)
    if knowledge and not knowledge.get('safe', True):
        return True
    return False


def _is_controlled_var(var_name, params, assignments, block, depth):
    """检查变量是否可控（递归追踪赋值链）。"""
    if depth > 10:
        return False

    if var_name in params:
        return True

    if var_name in assignments:
        expr = assignments[var_name]
        expr_names = _extract_var_names_from_expr(_node_text(expr))
        for name in expr_names:
            if _is_controlled_var(name, params, assignments, block, depth + 1):
                return True

    return False


def _find_controlled_params_in_call(args, params, assignments, block):
    """找出调用中哪些参数是可控的。"""
    controlled = []
    for arg in args:
        if _is_controlled_var(arg, params, assignments, block, 0):
            if arg in params:
                controlled.append(arg)
            else:
                origin = _trace_to_origin(arg, params, assignments, block, 0)
                if origin in params:
                    controlled.append(origin)
                else:
                    controlled.append(arg)
    return controlled


def _trace_to_origin(var_name, params, assignments, block, depth):
    """追溯变量的源头参数。"""
    if depth > 10:
        return var_name

    if var_name in params:
        return var_name

    if var_name in assignments:
        expr = assignments[var_name]
        expr_names = _extract_var_names_from_expr(_node_text(expr))
        for name in expr_names:
            origin = _trace_to_origin(name, params, assignments, block, depth + 1)
            if origin in params:
                return origin

    return var_name


# ---------------------------------------------------------------------------
# 主入口函数
# ---------------------------------------------------------------------------

def scan_parser(code_content, file_path, vul_function, fix_module=None):
    """
    TypeScript AST 污点追踪引擎主入口。

    :param code_content: 源文件内容
    :param file_path: 文件路径
    :param vul_function: 漏洞函数名
    :param fix_module: 修复模块（预留）
    :return: scan_results 列表
    """
    global scan_results
    scan_results = []

    if not _HAS_TREE_SITTER:
        logger.debug("[AST][TypeScript] tree-sitter 不可用，跳过 AST 分析")
        return scan_results

    tree = _parse_ts_ast(file_path)
    if tree is None:
        return scan_results

    root = tree.root_node

    # 初始化函数摘要
    _init_function_summaries(file_path)

    # 查找目标函数
    func_node = _find_function_node(root, vul_function)
    if func_node is None:
        logger.debug(f"[AST][TypeScript] 未找到函数定义: {vul_function}")
        return scan_results

    # 提取函数参数
    params = []
    param_lineno_map = {}
    param_list = None
    for child in func_node.children:
        if child.type == 'formal_parameters':
            param_list = child
            break

    if param_list:
        for child in param_list.children:
            if child.type in ('required_parameter', 'optional_parameter',
                              'rest_parameter', 'parameter'):
                pname = None
                for c in child.children:
                    if c.type == 'identifier':
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
        logger.info(f"[AST][TypeScript] 发现 {len(scan_result)} 个污点传播路径")
    else:
        logger.debug(f"[AST][TypeScript] 未发现污点传播路径")

    return scan_results


def scan_regex(code_content, file_path, vul_function, fix_module=None):
    """
    TypeScript 正则匹配引擎（预留）。

    基础实现暂不支持正则匹配。
    """
    return []


# ---------------------------------------------------------------------------
# 新规则生成支持
# ---------------------------------------------------------------------------

def new_scan_param(file_path, code_content, target_func):
    """
    分析函数参数，判断哪些参数可能影响返回值。

    :param file_path: 文件路径
    :param code_content: 源文件内容
    :param target_func: 目标函数名
    :return: (参数索引列表, 可控参数列表)
    """
    if not _HAS_TREE_SITTER:
        return [], []

    tree = _parse_ts_ast(file_path)
    if tree is None:
        return [], []

    root = tree.root_node
    func_node = _find_function_node(root, target_func)
    if func_node is None:
        return [], []

    # 提取参数
    params = []
    param_list = None
    for child in func_node.children:
        if child.type == 'formal_parameters':
            param_list = child
            break

    if param_list:
        idx = 0
        for child in param_list.children:
            if child.type in ('required_parameter', 'optional_parameter',
                              'rest_parameter', 'parameter'):
                pname = None
                for c in child.children:
                    if c.type == 'identifier':
                        pname = _node_text(c)
                        break
                if pname:
                    params.append((idx, pname))
                idx += 1

    # 分析返回值是否依赖参数
    block = None
    for child in func_node.children:
        if child.type == 'statement_block':
            block = child
            break

    controlled_indices = []
    if block:
        assignments = _collect_assignments(block)
        for param_idx, param_name in params:
            if _param_in_return(block, param_name, assignments):
                controlled_indices.append(param_idx)

    indices = [i for i, _ in params]
    controlled_names = [name for i, name in params if i in controlled_indices]

    return indices, controlled_names


def _param_in_return(block, param_name, assignments):
    """简单检查参数是否被用在 return 表达式中。"""
    def _check(node):
        if node is None:
            return False
        for child in node.children:
            if child.type == 'return_statement':
                ret_text = _node_text(child)
                if param_name in ret_text:
                    return True
            elif child.type in ('if_statement', 'for_statement', 'while_statement',
                               'switch_statement', 'try_statement', 'statement_block'):
                if _check(child):
                    return True
        return False

    return _check(block)
