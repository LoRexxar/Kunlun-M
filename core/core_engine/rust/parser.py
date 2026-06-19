#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Rust AST Parser — Rust 反向污点追踪引擎（基础实现）
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Rust 语言静态分析引擎，支持正则匹配和 AST 污点追踪。
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
from core.core_engine.rust.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.rust.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.rust.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter Rust AST 解析
import tree_sitter_rust as _tsrust
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_RUST_TS_LANGUAGE = _TS_Language(_tsrust.language())
_ts_parser = _TS_Parser(_RUST_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("rust")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# Rust 特有的可控输入源
RUST_CONTROLLED_SOURCES = [
    "std::env::args", "std::env::var", "std::env::args_os",
    "std::io::stdin", "std::io::BufReader", "std::io::Read",
    "std::fs::read_to_string", "std::fs::read",
    "std::env::args", "std::env::var_os",
    "std::net::TcpStream", "std::net::UdpSocket",
    "std::process::Command", "std::process::Stdio",
    "http::Request", "http::request::Request",
    "actix_web::HttpRequest", "HttpRequest",
    "axum::extract::Query", "axum::extract::Path",
    "axum::extract::Form", "axum::extract::Json",
    "rocket::http::RawStr", "rocket::request::Request",
    "reqwest::Response", "reqwest::blocking::Response",
    "serde_json::from_str", "serde_json::from_value",
    "serde_yaml::from_str", "toml::from_str",
]

# Rust 特有的敏感函数列表
RUST_SENSITIVE_SINKS = [
    "std::process::Command", "Command::new", "Command::arg",
    "std::process::Command::new",
    "std::fs::OpenOptions", "std::fs::File", "std::fs::create_dir",
    "std::fs::create_dir_all", "std::fs::remove_dir",
    "std::fs::remove_dir_all", "std::fs::remove_file",
    "std::fs::write", "std::fs::copy",
    "std::net::TcpStream::connect", "std::net::UdpSocket::bind",
    "std::os::unix::command",
    "std::fmt::format", "format!", "print!", "println!",
    "std::env::set_var", "std::env::remove_var",
    "std::thread::spawn",
    "std::ptr::read_volatile", "std::ptr::write_volatile",
    "unsafe",
    "libc::system", "libc::exec",
    "shellwords::split",
    "regex::Regex::new", "regex::RegexBuilder::new",
    "sqlx::query", "sqlx::query_as", "sqlx::query_scalar",
    "diesel::insert_into", "diesel::update", "diesel::delete",
    "reqwest::Client::get", "reqwest::Client::post",
    "reqwest::blocking::Client::get", "reqwest::blocking::Client::post",
]


def _extract_var_names_from_expr(expr):
    """
    从 Rust 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串拼接 (format!("a{}b", var))、简单变量、方法调用
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # format! 宏: format!("...{}...", var)
    fmt_match = re.match(r'format!\s*\(\s*"[^"]*"(?:\s*,\s*(.+))?\)', expr)
    if fmt_match:
        extra_args = fmt_match.group(1)
        if extra_args:
            for arg in extra_args.split(','):
                arg = arg.strip()
                ident = re.match(r'^([a-zA-Z_]\w*)', arg)
                if ident:
                    names.append(ident.group(1))
        return names

    # 字符串拼接: "a".to_string() + &var + "b"
    # In Rust, string concat is usually done via format! or concat!
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith('r#') and '"' in part):
                continue
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            ident = re.match(r'^([a-zA-Z_]\w*(?:::[a-zA-Z_]\w*)*)', part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'None', 'Some', 'Ok', 'Err',
                                'Self', 'self', 'super', 'crate',
                                'String', 'Vec', 'Box', 'Option', 'Result',
                                'i8', 'i16', 'i32', 'i64', 'i128',
                                'u8', 'u16', 'u32', 'u64', 'u128',
                                'f32', 'f64', 'bool', 'str', 'char',
                                'usize', 'isize'):
                    names.append(name)
        return names

    # 方法调用透传: var.method(args) 或 Type::function(args)
    call_match = re.match(r'^(\w+(?:::\w+)*)\s*\((.+)\)$', expr)
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
    simple = re.match(r'^([a-zA-Z_]\w*(?:::[a-zA-Z_]\w*)*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _rust_line_to_text(file_path, lineno):
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
        from core.core_engine.rust.summary_generator import generate_file_summaries, generate_summaries_for_target

        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'rust':
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
            logger.debug(f"[AST][Rust] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Rust] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}
_import_cache = {}


def _parse_rust_ast(file_path):
    """解析 Rust 文件为 tree-sitter AST，带缓存"""
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
        logger.warning(f"[AST][Rust] 解析失败 {file_path}: {e}")
        return None


def _node_text(node):
    """获取 tree-sitter 节点的文本内容"""
    if node is None:
        return ""
    try:
        return node.text.decode('utf-8', errors='ignore')
    except (AttributeError, UnicodeDecodeError):
        return ""


def _find_function_node(root_node, func_name, is_method=False, impl_type=None):
    """在 AST 中查找指定名称的函数定义"""
    if root_node is None:
        return None

    for child in root_node.children:
        if child.type == 'function_item':
            name_node = None
            for c in child.children:
                if c.type == 'identifier':
                    name_node = c
                    break
            if name_node and _node_text(name_node) == func_name:
                return child

        if child.type == 'impl_item':
            # 检查 impl 中的方法
            type_id = None
            for c in child.children:
                if c.type == 'type_identifier':
                    type_id = _node_text(c)
                    break
            if type_id and (impl_type is None or type_id == impl_type):
                for sub in child.children:
                    if sub.type == 'function_item':
                        name_node = None
                        for c in sub.children:
                            if c.type == 'identifier':
                                name_node = c
                                break
                        if name_node and _node_text(name_node) == func_name:
                            return sub

        # 递归进入 mod_item
        if child.type == 'mod_item':
            block = None
            for c in child.children:
                if c.type == 'block':
                    block = c
                    break
            if block:
                result = _find_function_node(block, func_name, is_method, impl_type)
                if result:
                    return result

    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/loop）
# ---------------------------------------------------------------------------

def _extract_constraints_from_rust_expr(cond_node):
    """从 Rust 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _get_var_name(n):
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'field_expression':
            if n.children:
                return _get_var_name(n.children[0])
        if n.type == 'index_expression':
            if n.children:
                return _get_var_name(n.children[0])
        if n.type in ('call_expression', 'method_call_expression', 'macro_invocation'):
            return None
        return None

    def _get_literal_value(n):
        if n is None:
            return None
        if n.type in ('integer_literal', 'float_literal'):
            try:
                return int(_node_text(n))
            except ValueError:
                return _node_text(n)
        if n.type in ('string_literal', 'char_literal'):
            return _node_text(n).strip('"').strip("'")
        if n.type == 'true':
            return True
        if n.type == 'false':
            return False
        return None

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
                constraints.extend(_extract_constraints_from_rust_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_rust_expr(right_node))
            return constraints

        if op_text == '||':
            if left_node:
                constraints.extend(_extract_constraints_from_rust_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_rust_expr(right_node))
            return constraints

        if op_text in ('==', '!='):
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

    if node_type == 'unary_expression':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == '!' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                inner_constraints = _extract_constraints_from_rust_expr(inner)
                if inner_constraints:
                    constraints = [c.negate() for c in inner_constraints]
                    return constraints
        return constraints

    if node_type == 'call_expression':
        func_node = None
        args = []
        for child in cond_node.children:
            if child.type in ('identifier', 'scoped_identifier', 'field_expression'):
                func_node = child
            elif child.type == 'arguments':
                args = [c for c in child.children if c.type not in ('(', ')', ',')]

        if func_node and args:
            func_name = _node_text(func_node)
            RUST_TYPE_FUNCS = {
                'char::is_digit', 'char::is_alphabetic', 'char::is_alphanumeric',
                'char::is_whitespace', 'char::is_uppercase', 'char::is_lowercase',
                'str::is_ascii', 'str::contains',
                'str::parse::<i32>', 'str::parse::<u32>',
            }
            if func_name in RUST_TYPE_FUNCS and len(args) >= 1:
                var_name = _get_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

        return constraints

    return constraints


def _find_enclosing_if_for_rust(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if 或 for/while/loop 语句节点。"""
    best = [None]

    def _search(node):
        if node.type == 'if_expression':
            for child in node.children:
                if child.type == 'block':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break
                elif child.type == 'else_clause':
                    for ec in child.children:
                        if ec.type == 'block':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                                    best[0] = (node, 'if')
                                break
                        elif ec.type == 'if_expression':
                            _search(ec)

        elif node.type in ('for_expression', 'while_expression', 'loop_expression'):
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


def _check_rust_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_rust_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_if_for_rust(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_rust_if_constraint(node, vul_lineno, var_name)
    elif node_type == 'for':
        return _check_rust_for_constraint(node, vul_lineno, var_name)

    return False


def _check_rust_if_constraint(if_node, vul_lineno, var_name):
    """检查 Rust if/else 分支约束。"""
    cond_node = None
    if_body = None
    else_body = None

    for child in if_node.children:
        if child.type == 'else_clause':
            for ec in child.children:
                if ec.type == 'block':
                    else_body = ec
                elif ec.type == 'if_expression':
                    return _check_rust_if_constraint(ec, vul_lineno, var_name)
        elif child.type == 'block' and if_body is None:
            if_body = child
        if child.type not in ('if', 'let', 'block', 'else_clause') and if_body is None:
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

    constraints = _extract_constraints_from_rust_expr(cond_node)

    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][Rust] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!=', 'not in'):
            logger.info("[AST][Rust] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_rust_for_constraint(for_node, vul_lineno, var_name):
    """检查 Rust for/while/loop 条件约束。"""
    cond_node = None
    body_node = None

    for child in for_node.children:
        if child.type == 'block' and body_node is None:
            body_node = child
        elif child.type not in ('for', 'in', 'while', 'loop', 'block') and body_node is None:
            cond_node = child

    if body_node is None:
        return False

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return False

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_rust_expr(cond_node)

    for c in constraints:
        if c.var_name == var_name and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
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

    block = None
    for child in func_node.children:
        if child.type == 'block':
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
                    # 传递式追踪
                    pass
            continue

        # 检查是否有可控参数流入敏感函数
        controlled_params = _find_controlled_params_in_call(
            call_args, params, assignments, block)

        if controlled_params:
            for cp in controlled_params:
                result_data = {
                    'code': _rust_line_to_text(file_path, call_lineno),
                    'sink': call_name,
                    'source': cp,
                    'source_lineno': param_lineno_map.get(cp, '?'),
                    'vul_lineno': call_lineno,
                    'vul_function': func_name,
                }
                scan_result.append(result_data)
                logger.info("[AST][Rust] Taint found: {} -> {} at line {} ({})".format(
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
            if child.type == 'let_declaration':
                var_name = None
                init_expr = None
                for c in child.children:
                    if c.type == 'identifier' and var_name is None:
                        var_name = _node_text(c)
                    if c.type == 'expression' or (c.type not in (
                        'let', 'mut', 'ref', ';', ':', '=',
                        'type_identifier', 'reference_type',
                        'abstract_type', 'generic_type',
                        'scoped_type_identifier') and init_expr is None):
                        if c.type in ('identifier', 'call_expression',
                                      'method_call_expression', 'macro_invocation',
                                      'field_expression', 'binary_expression',
                                      'scoped_identifier', 'unary_expression',
                                      'if_expression', 'match_expression',
                                      'struct_expression', 'index_expression',
                                      'await_expression', 'try_expression',
                                      'type_cast_expression', 'parenthesized_expression',
                                      'tuple_expression', 'array_expression',
                                      'return_expression'):
                            init_expr = c
                            break
                if var_name and init_expr:
                    assignments[var_name] = init_expr
            elif child.type == 'assignment_expression':
                # x = expr
                left = None
                right = None
                found_eq = False
                for c in child.children:
                    if c.type == '=':
                        found_eq = True
                        continue
                    if not found_eq and left is None:
                        if c.type == 'identifier':
                            left = _node_text(c)
                    elif found_eq and right is None:
                        right = c
                        break
                if left and right:
                    assignments[left] = right
            elif child.type in ('if_expression', 'for_expression', 'while_expression',
                               'loop_expression', 'match_expression', 'block',
                               'unsafe_block', 'expression_statement'):
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
                    if c.type in ('identifier', 'scoped_identifier'):
                        func_name = _node_text(c)
                    elif c.type == 'arguments':
                        args = _extract_arg_names(c)
                if func_name:
                    calls.append({'name': func_name, 'args': args, 'lineno': lineno})
            elif child.type == 'method_call_expression':
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
            elif child.type == 'macro_invocation':
                macro_name = ""
                lineno = child.start_point[0] + 1
                for c in child.children:
                    if c.type == 'identifier':
                        macro_name = _node_text(c) + "!"
                        break
                    elif c.type == 'scoped_identifier':
                        macro_name = _node_text(c) + "!"
                        break
                if macro_name and macro_name.rstrip('!') in (
                    'println', 'eprintln', 'format', 'print', 'eprint',
                    'vec', 'dbg', 'todo', 'unimplemented', 'panic',
                    'assert', 'assert_eq', 'assert_ne'):
                    calls.append({'name': macro_name, 'args': [], 'lineno': lineno})
            elif child.type in ('if_expression', 'for_expression', 'while_expression',
                               'loop_expression', 'match_expression', 'block',
                               'unsafe_block', 'expression_statement'):
                _walk(child)

    _walk(block_node)
    return calls


def _extract_arg_names(arg_list_node):
    """从参数列表节点中提取参数变量名列表。"""
    names = []
    for child in arg_list_node.children:
        if child.type in ('(', ')', ','):
            continue
        # 简单标识符参数
        if child.type == 'identifier':
            names.append(_node_text(child))
        elif child.type == 'scoped_identifier':
            names.append(_node_text(child))
        # 字符串字面量（不追踪）
        elif child.type in ('string_literal', 'char_literal',
                           'integer_literal', 'float_literal', 'true', 'false'):
            continue
        else:
            # 复杂表达式：提取其中的标识符
            inner_names = _extract_var_names_from_expr(_node_text(child))
            names.extend(inner_names)
    return names


def _is_sink(func_name):
    """检查函数是否为敏感函数。"""
    for sink in RUST_SENSITIVE_SINKS:
        if func_name == sink or func_name.endswith('::' + sink.split('::')[-1]):
            short_sink = sink.split('::')[-1]
            if func_name == short_sink or func_name.endswith('::' + short_sink):
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
                # 追溯到原始参数
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
    Rust AST 污点追踪引擎主入口。

    :param code_content: 源文件内容
    :param file_path: 文件路径
    :param vul_function: 漏洞函数名
    :param fix_module: 修复模块（预留）
    :return: scan_results 列表
    """
    global scan_results
    scan_results = []

    if not _HAS_TREE_SITTER:
        logger.debug("[AST][Rust] tree-sitter 不可用，跳过 AST 分析")
        return scan_results

    tree = _parse_rust_ast(file_path)
    if tree is None:
        return scan_results

    root = tree.root_node

    # 初始化函数摘要
    _init_function_summaries(file_path)

    # 查找目标函数
    func_node = _find_function_node(root, vul_function)
    if func_node is None:
        logger.debug(f"[AST][Rust] 未找到函数定义: {vul_function}")
        return scan_results

    # 提取函数参数
    params = []
    param_lineno_map = {}
    param_list = None
    for child in func_node.children:
        if child.type == 'parameters':
            param_list = child
            break

    if param_list:
        for child in param_list.children:
            if child.type == 'parameter':
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
        logger.info(f"[AST][Rust] 发现 {len(scan_result)} 个污点传播路径")
    else:
        logger.debug(f"[AST][Rust] 未发现污点传播路径")

    return scan_results


def scan_regex(code_content, file_path, vul_function, fix_module=None):
    """
    Rust 正则匹配引擎（预留）。

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

    tree = _parse_rust_ast(file_path)
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
        if child.type == 'parameters':
            param_list = child
            break

    if param_list:
        idx = 0
        for child in param_list.children:
            if child.type == 'parameter':
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
        if child.type == 'block':
            block = child
            break

    controlled_indices = []
    if block:
        assignments = _collect_assignments(block)
        for param_idx, param_name in params:
            # 简单检查：参数是否被用在 return 表达式中
            if _param_in_return(block, param_name, assignments):
                controlled_indices.append(param_idx)

    indices = [i for i, _ in params]
    controlled_names = [name for i, name in params if i in controlled_indices]

    return indices, controlled_names


def _param_in_return(block_node, param_name, assignments):
    """检查参数是否在 return 表达式中被使用。"""
    for child in block_node.children:
        if child.type == 'return_expression':
            for c in child.children:
                if c.type == 'return':
                    continue
                ret_text = _node_text(c)
                if param_name in ret_text:
                    return True
                # 检查赋值链
                for var, expr in assignments.items():
                    expr_text = _node_text(expr)
                    if param_name in expr_text and var in ret_text:
                        return True
    return False


def scan_assign_controlflow(code_content, file_path, vul_function, fix_module=None):
    """
    Rust 赋值和控制流分析（预留）。

    基础实现暂不支持。
    """
    return []
