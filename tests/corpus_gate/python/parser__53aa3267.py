#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Lua AST Parser — Lua 反向污点追踪引擎（基础实现）
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Lua 语言静态分析引擎，支持正则匹配和 AST 污点追踪。
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
from core.core_engine.lua.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.lua.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.lua.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter Lua AST 解析
import tree_sitter_lua as _tslua
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_LUA_TS_LANGUAGE = _TS_Language(_tslua.language())
_ts_parser = _TS_Parser(_LUA_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("lua")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# Lua 特有的可控输入源
LUA_CONTROLLED_SOURCES = [
    "os.getenv",
    # io.open/io.read/io.lines/io.stdin/io.input/io.output removed: CLI/file, not web
    # io.popen/os.execute removed: CLI/command, not web
    # http.request/socket.* removed: CLI/network client, not web
    "json.decode",
    "cjson.decode",
    "arg",
    "ngx.req.get_uri_args",
    "ngx.req.get_post_args",
    "ngx.req.get_headers",
    "ngx.req.get_body_data",
    "ngx.var.request_body",
    "ngx.var.uri",
    "ngx.var.query_string",
]


def _extract_var_names_from_expr(expr):
    """
    从 Lua 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串拼接 (".." 操作符)、简单变量、方法调用
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 简单变量名
    simple = re.match(r'^([a-zA-Z_]\w*(?:\.\w+)*)$', expr)
    if simple:
        name = simple.group(1)
        if name not in ('true', 'false', 'nil', 'self', '_',
                        'string', 'table', 'math', 'io', 'os',
                        'coroutine', 'debug', 'package', 'require'):
            names.append(name)
        return names

    # 字符串拼接: "a" .. var .. "b"
    if '..' in expr:
        parts = re.split(r'\.\.', expr)
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
                if name not in ('true', 'false', 'nil', 'self', '_',
                                'string', 'table', 'math', 'io', 'os',
                                'coroutine', 'debug', 'package', 'require',
                                'tostring', 'tonumber', 'type', 'pairs', 'ipairs'):
                    names.append(name)
        return names

    # 方法调用透传: var:method(args) 或 func(args)
    call_match = re.match(r'^(\w+(?:\.\w+)*)\s*[:\.]?\s*\((.+)\)$', expr)
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

    return names


def _lua_line_to_text(file_path, lineno):
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
        from core.core_engine.lua.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'lua':
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
            logger.debug(f"[AST][Lua] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Lua] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}
_import_cache = {}


def _parse_lua_ast(file_path):
    """解析 Lua 文件为 tree-sitter AST，带缓存"""
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
        logger.warning(f"[AST][Lua] 解析失败 {file_path}: {e}")
        return None


def _node_text(node):
    """获取 tree-sitter 节点的文本内容"""
    if node is None:
        return ""
    try:
        return node.text.decode('utf-8', errors='ignore')
    except (AttributeError, UnicodeDecodeError):
        return ""


def _find_function_node(root_node, func_name):
    """在 AST 中查找指定名称的函数定义"""
    if root_node is None:
        return None

    for child in root_node.children:
        if child.type == 'function_declaration':
            name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/while/for）
# ---------------------------------------------------------------------------

def _extract_constraints_from_lua_expr(cond_node):
    """从 Lua 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _get_var_name(n):
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'dot_index_expression':
            if n.children:
                return _get_var_name(n.children[0])
        return None

    def _get_literal_value(n):
        if n is None:
            return None
        if n.type == 'number':
            try:
                return int(_node_text(n))
            except ValueError:
                return _node_text(n)
        if n.type == 'string':
            return _node_text(n).strip('"').strip("'")
        if n.type == 'true':
            return True
        if n.type == 'false':
            return False
        return None

    if node_type == 'binary_operation':
        children = cond_node.children
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in children:
            if child.type in ('==', '~=', '>=', '<=', '<', '>',
                              'and', 'or'):
                if not found_op:
                    op_node = child
                    found_op = True
                continue
            if not found_op and left_node is None:
                left_node = child
            elif found_op and right_node is None:
                right_node = child

        op_text = _node_text(op_node) if op_node else ''

        if op_text == 'and':
            if left_node:
                constraints.extend(_extract_constraints_from_lua_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_lua_expr(right_node))
            return constraints

        if op_text == 'or':
            if left_node:
                constraints.extend(_extract_constraints_from_lua_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_lua_expr(right_node))
            return constraints

        if op_text in ('==', '~='):
            var_name = _get_var_name(left_node)
            if var_name:
                value = _get_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
            else:
                var_name = _get_var_name(right_node)
                if var_name:
                    value = _get_literal_value(left_node)
                    neg_op = '~=' if op_text == '==' else '=='
                    constraints.append(BranchConstraint(var_name=var_name, op=neg_op, value=value))

        return constraints

    if node_type == 'unary_operation':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == 'not' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                inner_constraints = _extract_constraints_from_lua_expr(inner)
                if inner_constraints:
                    constraints = [c.negate() for c in inner_constraints]
                    return constraints
        return constraints

    if node_type == 'function_call':
        func_node = None
        args = []
        for child in cond_node.children:
            if child.type == 'identifier':
                func_node = child
            elif child.type == 'arguments':
                args = [c for c in child.children if c.type not in ('(', ')', ',')]

        if func_node and args:
            func_name = _node_text(func_node)
            LUA_TYPE_FUNCS = {
                'tonumber', 'type', 'math.type',
            }
            if func_name in LUA_TYPE_FUNCS and len(args) >= 1:
                var_name = _get_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

        return constraints

    return constraints


def _find_enclosing_if_for_lua(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if 或 for/while 语句节点。"""
    best = [None]

    def _search(node):
        if node.type == 'if_statement':
            for child in node.children:
                if child.type == 'block':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break
                elif child.type == 'elseif_clause':
                    for ec in child.children:
                        if ec.type == 'block':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                                    best[0] = (node, 'if')
                                break

        elif node.type in ('while_statement', 'for_statement', 'for_in_statement',
                           'repeat_statement'):
            for child in node.children:
                if child.type == 'block':
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


def _check_lua_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_lua_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_if_for_lua(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_lua_if_constraint(node, vul_lineno, var_name)
    elif node_type == 'for':
        return _check_lua_for_constraint(node, vul_lineno, var_name)

    return False


def _check_lua_if_constraint(if_node, vul_lineno, var_name):
    """检查 Lua if 条件约束"""
    # 找到条件表达式
    for child in if_node.children:
        if child.type not in ('if', 'then', 'block', 'elseif_clause', 'else_clause'):
            constraints = _extract_constraints_from_lua_expr(child)
            for c in constraints:
                if c.var_name == var_name:
                    return True
    return False


def _check_lua_for_constraint(for_node, vul_lineno, var_name):
    """检查 Lua for/while 循环约束"""
    # For numeric loop: for i = start, end, step do
    # For generic loop: for k, v in pairs(t) do
    return False


# ---------------------------------------------------------------------------
# Source Discovery 初始化
# ---------------------------------------------------------------------------

def _init_source_discovery(project_dir):
    """初始化 source discovery"""
    global _sd_registry
    if _sd_registry is not None:
        return _sd_registry

    pt = _ast_object_singleton
    if pt and hasattr(pt, 'target_directory'):
        project_dir = pt.target_directory

    tree = _parse_lua_ast(project_dir)
    _sd_registry = discover_sources(project_dir, tree)
    return _sd_registry


# ---------------------------------------------------------------------------
# 扫描文件入口（被上层调用）
# ---------------------------------------------------------------------------

def scan_file(file_path, **kwargs):
    """
    扫描 Lua 文件中的安全漏洞（基础实现）
    """
    global scan_results, scan_chain, is_repair_functions, is_controlled_params

    scan_results = []
    scan_chain = []
    is_repair_functions = []
    is_controlled_params = []

    try:
        tree = _parse_lua_ast(file_path)
        if tree is None:
            return

        _init_function_summaries(file_path)
        _init_source_discovery(file_path)

        root = tree.root_node
        _walk_for_vulnerabilities(root, file_path)

    except Exception as e:
        logger.warning(f"[AST][Lua] 扫描文件失败 {file_path}: {e}")
        traceback.print_exc()


def _walk_for_vulnerabilities(node, file_path):
    """遍历 AST 查找潜在漏洞模式"""
    if node is None:
        return

    for child in node.children:
        if hasattr(child, 'type'):
            if child.type in ('function_declaration', 'if_statement',
                              'while_statement', 'for_statement',
                              'for_in_statement', 'block'):
                _walk_for_vulnerabilities(child, file_path)
            elif child.type == 'function_call':
                _check_call_safety(child, file_path)


def _check_call_safety(call_node, file_path):
    """检查函数调用是否安全"""
    func_name = ""
    for child in call_node.children:
        if child.type == 'identifier':
            func_name = _node_text(child)
            break

    if not func_name:
        return

    knowledge = lookup_builtin(func_name)
    if knowledge and not knowledge.get('safe', False):
        logger.debug(f"[AST][Lua] 潜在不安全调用: {func_name} in {file_path}:{call_node.start_point[0] + 1}")


# ---------------------------------------------------------------------------
# 跨函数追踪
# ---------------------------------------------------------------------------

def _scan_function_by_name(func_name, file_path, param_index=None, depth=0):
    """跨函数追踪：根据被调用函数名，追踪其内部污点传播"""
    if depth > 5 or func_name in _scan_function_stack:
        return []

    _scan_function_stack.append(func_name)

    try:
        tree = _parse_lua_ast(file_path)
        if tree is None:
            return []

        func_node = _find_function_node(tree.root_node, func_name)
        if func_node is None:
            return []

        results = []
        # 基础实现：检查函数内是否有返回可控参数的逻辑
        return results
    finally:
        _scan_function_stack.pop()
