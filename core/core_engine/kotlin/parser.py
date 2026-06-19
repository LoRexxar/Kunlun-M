#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Kotlin AST Parser — Kotlin 反向污点追踪引擎（基础实现）
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Kotlin 语言静态分析引擎，支持正则匹配和 AST 污点追踪。
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
from core.core_engine.kotlin.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.kotlin.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.kotlin.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter Kotlin AST 解析
import tree_sitter_kotlin as _tskotlin
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_KOTLIN_TS_LANGUAGE = _TS_Language(_tskotlin.language())
_ts_parser = _TS_Parser(_KOTLIN_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("kotlin")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# Kotlin 特有的可控输入源
KOTLIN_CONTROLLED_SOURCES = [
    "System.console", "System.`in`", "readLine",
    "readln", "readlnOrNull",
    "java.lang.System.getenv", "java.lang.System.getProperty",
    "java.util.Scanner", "java.io.BufferedReader",
    "java.io.FileReader", "java.io.FileInputStream",
    "java.net.URL", "java.net.HttpURLConnection",
    "java.net.Socket", "java.net.ServerSocket",
    "java.sql.Connection", "java.sql.DriverManager",
    "kotlinx.coroutines.channels.Channel",
    "kotlinx.io.files.readFile",
    "args", "bundle", "intent", "savedInstanceState",
    "request", "response", "session",
]

# Kotlin 特有的敏感函数列表
KOTLIN_SENSITIVE_SINKS = [
    "Runtime.getRuntime", "ProcessBuilder", "exec",
    "java.lang.Runtime.exec", "java.lang.ProcessBuilder",
    "java.io.File", "java.io.FileOutputStream",
    "java.net.URL", "java.net.HttpURLConnection",
    "java.lang.System.loadLibrary", "java.lang.System.load",
    "java.sql.Statement.executeQuery", "java.sql.Statement.executeUpdate",
    "java.sql.Connection.prepareStatement",
    "javax.script.ScriptEngine.eval",
    "java.lang.reflect.Method.invoke",
    "println", "print",
    "ProcessBuilder", "exec",
]


def _extract_var_names_from_expr(expr):
    """
    从 Kotlin 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串模板 ("Hello $name")、简单变量、方法调用
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 字符串模板: "Hello $name" or "Hello ${obj.name}"
    template_names = re.findall(r'\$\{([^}]+)\}|\$(\w+)', expr)
    for group in template_names:
        name = group[0] or group[1]
        if name:
            # 取最后一个 . 后的部分作为变量名
            if '.' in name:
                name = name.split('.')[-1]
            names.append(name)
    if template_names:
        # 如果整个表达式只是字符串模板，返回变量名
        if expr.startswith('"') and expr.endswith('"'):
            return names

    # 字符串拼接: "a" + var + "b"
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith("'") and part.endswith("'")):
                continue
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            ident = re.match(r'^([a-zA-Z_]\w*(?:\.\w+)*)', part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'null', 'this', 'super',
                                'String', 'Int', 'Long', 'Double', 'Float',
                                'Boolean', 'Char', 'Byte', 'Short',
                                'Unit', 'Nothing', 'Any', 'List', 'Map', 'Set',
                                'Array', 'MutableList', 'MutableMap', 'MutableSet'):
                    names.append(name)
        return names

    # 方法调用透传: var.method(args) 或 Type.function(args)
    call_match = re.match(r'^(\w+(?:\.\w+)*)\s*\((.+)\)$', expr)
    if call_match:
        func_name = call_match.group(1)
        knowledge = lookup_builtin(func_name)
        if knowledge and (knowledge.get("passthrough") or knowledge.get("param_flow")):
            inner_args = call_match.group(2)
            for a in inner_args.split(','):
                a = a.strip()
                ident = re.match(r'^([a-zA-Z_]\w*)', a)
                if ident and not (a.startswith('"') and a.endswith('"')):
                    names.append(ident.group(1))
        return names

    # 简单变量名
    simple = re.match(r'^([a-zA-Z_]\w*(?:\.\w+)*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _kotlin_line_to_text(file_path, lineno):
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
        from core.core_engine.kotlin.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'kotlin':
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
            logger.debug(f"[AST][Kotlin] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Kotlin] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}
_import_cache = {}


def _parse_kotlin_ast(file_path):
    """解析 Kotlin 文件为 tree-sitter AST，带缓存"""
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
        logger.warning(f"[AST][Kotlin] 解析失败 {file_path}: {e}")
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
        if child.type == 'function_declaration':
            name_node = None
            for c in child.children:
                if c.type == 'simple_identifier':
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

        if child.type in ('class_declaration', 'object_declaration',
                          'interface_declaration', 'enum_declaration'):
            type_name = None
            for c in child.children:
                if c.type == 'simple_identifier':
                    type_name = _node_text(c)
                    break
            if type_name and (class_type is None or type_name == class_type):
                # 检查类体中的方法
                body = _find_child_by_type(child, 'class_body')
                if body:
                    for sub in body.children:
                        if sub.type == 'function_declaration':
                            name_node = None
                            for c in sub.children:
                                if c.type == 'simple_identifier':
                                    name_node = c
                                    break
                            if name_node and _node_text(name_node) == func_name:
                                return sub
                        # 检查 companion object
                        if sub.type == 'companion_object':
                            comp_body = _find_child_by_type(sub, 'class_body')
                            if comp_body:
                                for comp_sub in comp_body.children:
                                    if comp_sub.type == 'function_declaration':
                                        name_node = None
                                        for c in comp_sub.children:
                                            if c.type == 'simple_identifier':
                                                name_node = c
                                                break
                                        if name_node and _node_text(name_node) == func_name:
                                            return comp_sub

    return None


def _find_child_by_type(node, *types):
    """返回第一个匹配指定类型的子节点"""
    if node is None:
        return None
    for c in node.children:
        if c.type in types:
            return c
    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/when/for/while）
# ---------------------------------------------------------------------------

def _extract_constraints_from_kotlin_expr(cond_node):
    """从 Kotlin 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _get_var_name(n):
        if n is None:
            return None
        if n.type == 'simple_identifier':
            return _node_text(n)
        if n.type in ('call_expression', 'dot_expression'):
            return None
        return None

    def _get_literal_value(n):
        if n is None:
            return None
        if n.type in ('integer_literal', 'real_literal'):
            try:
                return int(_node_text(n))
            except ValueError:
                return _node_text(n)
        if n.type == 'string_literal':
            return _node_text(n).strip('"').strip("'")
        if n.type == 'true':
            return True
        if n.type == 'false':
            return False
        if n.type == 'null':
            return None
        return None

    if node_type == 'binary_expression':
        children = cond_node.children
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in children:
            if child.type in ('==', '!=', '>=', '<=', '>', '<', '&&', '||',
                              '===', '!==', 'plus', 'minus', 'times', 'div', 'mod'):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        op_text = _node_text(op_node) if op_node else ''

        if op_text in ('&&', '||'):
            if left_node:
                constraints.extend(_extract_constraints_from_kotlin_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_kotlin_expr(right_node))
            return constraints

        if op_text in ('==', '!=', '===', '!=='):
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

    return constraints


def _find_enclosing_branch_for_kotlin(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if/when/for/while 语句节点。"""
    best = [None]

    def _search(node):
        if node.type == 'if_expression':
            for child in node.children:
                if child.type in ('block', 'statement'):
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break

        elif node.type == 'when_expression':
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= vul_lineno <= end:
                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                    best[0] = (node, 'when')

        elif node.type in ('for_statement', 'while_statement', 'do_while_statement'):
            for child in node.children:
                if child.type in ('block', 'statement'):
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


def _check_kotlin_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_kotlin_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_branch_for_kotlin(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result
    cond_node = None

    if node_type == 'if':
        for child in node.children:
            if child.type not in ('if', 'else', 'block', 'statement', '{', '}'):
                cond_node = child
                break
    elif node_type == 'when':
        pass  # when 表达式多分支，简化处理
    elif node_type == 'for':
        pass

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_kotlin_expr(cond_node)
    for c in constraints:
        if c.var_name == var_name:
            return True

    return False


# ---------------------------------------------------------------------------
# 主扫描入口
# ---------------------------------------------------------------------------

def scan_statement(file_path, rule, vul_function, param_name, vul_lineno, vul_type="xss"):
    """扫描单条语句，判断是否存在安全风险。"""
    try:
        # 简化的正则扫描实现
        import core.core_engine.base.engine as base_engine
        return base_engine._base_scan_statement(
            file_path, rule, vul_function, param_name, vul_lineno, vul_type
        )
    except Exception as e:
        logger.debug(f"[AST][Kotlin] scan_statement 异常: {e}")
        return []


def scan_function(file_path, function_name, param_name, vul_function, vul_type="xss"):
    """扫描函数体中的污点传播。"""
    try:
        tree = _parse_kotlin_ast(file_path)
        if tree is None:
            return []

        func_node = _find_function_node(tree.root_node, function_name)
        if func_node is None:
            return []

        func_body = _find_child_by_type(func_node, 'block')
        if func_body is None:
            return []

        results = []

        def _scan_body(body_node, depth=0):
            if depth > 10:
                return
            for child in body_node.children:
                if child is None or not hasattr(child, 'type'):
                    continue

                text = _node_text(child)

                # 检查是否调用敏感函数
                for sink in KOTLIN_SENSITIVE_SINKS:
                    if sink in text:
                        # 检查参数是否来自可控输入
                        if param_name and param_name in text:
                            lineno = child.start_point[0] + 1
                            results.append({
                                'vul_function': vul_function,
                                'param_name': param_name,
                                'sink': sink,
                                'lineno': lineno,
                                'code': text[:200] if len(text) > 200 else text,
                            })

                # 递归进入子节点
                if child.type in ('block', 'statement', 'if_expression',
                                  'when_expression', 'for_statement',
                                  'while_statement', 'try_expression',
                                  'lambda_expression'):
                    _scan_body(child, depth + 1)

        _scan_body(func_body)
        return results

    except Exception as e:
        logger.debug(f"[AST][Kotlin] scan_function 异常: {e}")
        return []
