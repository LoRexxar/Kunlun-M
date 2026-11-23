#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    C# AST Parser — C# 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    C# 语言静态分析引擎，支持正则匹配和 AST 污点追踪。

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""
import re
import os
from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.csharp.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.csharp.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.csharp.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter C# AST 解析
import tree_sitter_c_sharp as _tscs
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_CS_TS_LANGUAGE = _TS_Language(_tscs.language())
_ts_parser = _TS_Parser(_CS_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("csharp")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# C# 特有的可控输入源
CSHARP_CONTROLLED_SOURCES = [
    "Request.Query", "Request.Form", "Request.QueryString",
    "Request.Cookies", "Request.Headers", "Request.UserAgent",
    "Request.Url", "Request.RawUrl", "Request.Path",
    "Request[" , "Request.Form[",
    "HttpContext.Request",
    "Environment.GetEnvironmentVariable",
    "Console.ReadLine", "Console.Read",
    "args",
    "Configuration", "IConfiguration",
    "HttpContext.Current.Request",
    "HttpRequest.QueryString",
    "HttpRequest.Form",
    "HttpRequest.Cookies",
    "HttpRequest.Headers",
    "HttpRequest.Files",
    "Request.InputStream", "Request.Body",
    "MapPath",
]

# C# 特有的敏感函数列表
CSHARP_SENSITIVE_SINKS = [
    "Process.Start", "ProcessStartInfo",
    "SqlCommand", "SqlCommand.CommandText",
    "SqlConnection", "SqlDataAdapter",
    "File.ReadAllText", "File.WriteAllText", "File.ReadAllBytes",
    "File.Delete", "File.Move", "File.Copy",
    "Directory.CreateDirectory", "Directory.Delete",
    "StreamReader", "StreamWriter",
    "HttpWebRequest", "WebClient", "HttpClient",
    "Response.Write", "Response.Redirect",
    "HttpContext.Response.Write",
    "Server.Execute", "Server.Transfer",
    "XDocument.Parse", "XElement.Parse",
    "XmlDocument.LoadXml",
    "JavaScriptSerializer", "DataContractJsonSerializer",
    "Regex.Replace", "Regex.Match",
    "String.Format", "StringBuilder.AppendFormat",
    "Path.Combine", "Path.GetFullPath",
    "Assembly.Load", "Assembly.LoadFrom",
    "Type.GetType",
    "eval", "ExecuteSqlCommand",
]


def _extract_var_names_from_expr(expr):
    """
    从 C# 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串插值 ($"...{var}...")、字符串拼接 (var + "str")、简单变量
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 字符串插值: $"Hello {Name}, age {Age}"
    if '$"' in expr or '$@"' in expr:
        # 提取 {var} 部分
        interpolations = re.findall(r'\{([^{}]+)\}', expr)
        for interp in interpolations:
            # 跳过格式说明符
            var_part = interp.split(':')[0].split(',')[0].strip()
            # 提取标识符
            ident = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)', var_part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'null', 'int', 'string', 'bool',
                                'var', 'this', 'base', 'nameof'):
                    names.append(name)
        return names

    # 字符串拼接: "SELECT..." + userId + "..." + name
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            # 跳过字符串字面量
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith('@') and '"'):
                continue
            # 跳过数字字面量
            if re.match(r'^\d+(\.\d+)?[fFdDmM]?$', part):
                continue
            # 提取标识符
            ident = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)', part)
            if ident:
                name = ident.group(1)
                if name not in ('true', 'false', 'null', 'int', 'string', 'bool',
                                'var', 'this', 'base', 'nameof', 'typeof',
                                'new', 'return', 'throw', 'await', 'yield'):
                    names.append(name)
        return names

    # String.Format("...{0}...", args)
    fmt_match = re.match(r'(?:string\.)?Format\s*\(\s*"[^"]*"\s*(?:,\s*(.+))?\)', expr, re.IGNORECASE)
    if fmt_match:
        extra_args = fmt_match.group(1)
        if extra_args:
            for arg in extra_args.split(','):
                arg = arg.strip()
                ident = re.match(r'^([a-zA-Z_]\w*)', arg)
                if ident:
                    names.append(ident.group(1))
        return names

    # 函数调用透传: someFunc(variable)
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
    simple = re.match(r'^([a-zA-Z_]\w*)$', expr)
    if simple:
        names.append(simple.group(1))

    return names


def _cs_line_to_text(file_path, lineno):
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
        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory

        cache_mgr = SummaryCacheManager()

        # 收集所有 C# 文件内容
        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'csharp':
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
            logger.debug(f"[AST][C#] 摘要初始化完成: {len(_file_summaries)} 个文件")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][C#] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}  # file_path → tree


def _parse_csharp_ast(file_path):
    """用 tree-sitter 解析 C# 文件，返回 AST tree（带缓存）"""
    if file_path in _ast_cache:
        return _ast_cache[file_path]
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
        tree = _ts_parser.parse(source)
        _ast_cache[file_path] = tree
        return tree
    except Exception as e:
        logger.warning(f"[AST][C#] C# AST 解析失败: file={file_path}, error={e}")
        return None


def _get_node_text(node):
    """获取 tree-sitter 节点的文本内容"""
    if node is None:
        return ""
    try:
        return node.text.decode('utf-8', errors='ignore')
    except (AttributeError, UnicodeDecodeError):
        return str(node)


def _find_call_at_line(tree, lineno, func_name):
    """
    在 AST 中查找指定行号上的 invocation_expression 节点。
    匹配 func_name（支持完整名称）。
    """
    if tree is None:
        return None

    short_name = func_name.split('.')[-1]

    def _get_callee_name(node):
        """获取 invocation_expression 的调用者名称"""
        for child in node.children:
            if child.type in ('identifier', 'member_access_expression',
                               'generic_name', 'qualified_name'):
                return _get_node_text(child).rstrip('(').strip()
        return ''

    def _search(node):
        if node.type == 'invocation_expression':
            node_line = node.start_point[0] + 1
            if node_line == lineno:
                for child in node.children:
                    result = _search(child)
                    if result:
                        return result
                callee = _get_callee_name(node)
                if func_name in callee or short_name in callee:
                    return node
                return None
        for child in node.children:
            result = _search(child)
            if result:
                return result
        return None

    return _search(tree.root_node)


def _find_enclosing_function(tree, lineno):
    """
    在 AST 中查找包含指定行的函数定义。
    返回 (函数名, parameter_list节点, 起始行, 结束行) 或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        if node.type in ('method_declaration', 'constructor_declaration',
                         'destructor_declaration', 'local_function_statement'):
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= lineno <= end_line:
                func_name = None
                params = None
                is_static = False
                for child in node.children:
                    if child.type == 'identifier':
                        func_name = _get_node_text(child)
                    elif child.type == 'parameter_list' and params is None:
                        params = child
                    elif child.type == 'static':
                        is_static = True
                result[0] = (func_name, params, start_line, end_line, is_static)
                return
        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return result[0]


def _get_formal_param_names(param_list_node):
    """从 parameter_list AST 节点提取形参名列表"""
    if param_list_node is None:
        return []
    names = []
    for child in param_list_node.children:
        if child.type == 'parameter':
            for sc in child.children:
                if sc.type == 'identifier':
                    names.append(_get_node_text(sc))
                    break
    return names


def _collect_identifiers_from_ast(node):
    """从 AST 节点中递归收集所有 identifier（变量名）。"""
    identifiers = []

    # C# 关键字排除列表
    _CS_KEYWORDS = frozenset({
        'true', 'false', 'null', 'int', 'string', 'bool', 'double', 'float',
        'decimal', 'long', 'short', 'byte', 'char', 'object', 'void',
        'var', 'this', 'base', 'new', 'return', 'throw', 'await', 'yield',
        'if', 'else', 'for', 'foreach', 'while', 'do', 'switch', 'case',
        'break', 'continue', 'goto', 'try', 'catch', 'finally',
        'class', 'struct', 'interface', 'enum', 'namespace', 'using',
        'public', 'private', 'protected', 'static', 'virtual', 'override',
        'abstract', 'sealed', 'readonly', 'const', 'async', 'partial',
        'in', 'out', 'ref', 'params', 'is', 'as', 'typeof', 'nameof',
        'get', 'set', 'value', 'where', 'select', 'from', 'orderby',
        'group', 'by', 'ascending', 'descending', 'join', 'on', 'equals',
        'into', 'let', 'async', 'await', 'yield',
    })

    def _walk(n):
        if n.type == 'identifier':
            name = _get_node_text(n)
            if name and name not in _CS_KEYWORDS:
                identifiers.append(name)
        elif n.type == 'member_access_expression':
            # obj.prop 或 obj.method — 收集基础变量 obj
            if n.children:
                for child in n.children:
                    if child.type in ('identifier', 'this', 'base'):
                        identifiers.append(_get_node_text(child))
                        break
            full_text = _get_node_text(n)
            if full_text and full_text not in identifiers:
                identifiers.append(full_text)
            for child in n.children:
                _walk(child)
        elif n.type == 'invocation_expression':
            # 函数调用：只收集参数中的标识符
            for child in n.children:
                if child.type == 'argument_list':
                    for arg_child in child.children:
                        _walk(arg_child)
                elif child.type == 'member_access_expression':
                    # 也收集调用对象
                    _walk(child)
        else:
            for child in n.children:
                _walk(child)

    _walk(node)
    seen = set()
    unique = []
    for name in identifiers:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


def _find_assignment_rhs_at_line(tree, lineno, var_name):
    """
    在 AST 中查找指定行上 var_name 的赋值 RHS 节点。
    支持: 变量声明 (type name = expr)、赋值表达式 (name = expr)
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        node_line = node.start_point[0] + 1
        if node_line > lineno:
            return

        if node.type == 'variable_declarator':
            if node_line == lineno:
                for child in node.children:
                    if child.type == 'identifier':
                        name = _get_node_text(child)
                        if name == var_name:
                            # 查找 equals_value_clause
                            for sc in node.children:
                                if sc.type == 'equals_value_clause':
                                    for ssc in sc.children:
                                        if ssc.type not in ('=',):
                                            result[0] = ssc
                                            return
                            return

        elif node.type == 'assignment_expression':
            if node_line == lineno:
                left = None
                right = None
                found_op = False
                for child in node.children:
                    if child.type in ('=', '+=', '-=', '*=', '/=', '%=',
                                      '&=', '|=', '^=', '<<=', '>>='):
                        found_op = True
                        continue
                    if not found_op and left is None:
                        left = child
                    elif found_op and right is None:
                        right = child
                if left:
                    left_text = _get_node_text(left).strip()
                    if left_text == var_name or left_text.endswith('.' + var_name):
                        result[0] = right

        for child in node.children:
            _search(child)
            if result[0] is not None:
                return

    _search(tree.root_node)
    return result[0]


def _find_return_nodes(tree, start_line, end_line):
    """在 AST 中查找指定行范围内的 return_statement 节点列表。"""
    if tree is None:
        return []

    returns = []

    def _search(node):
        node_line = node.start_point[0] + 1
        if node_line > end_line:
            return
        if node.type == 'return_statement':
            if start_line <= node_line <= end_line:
                returns.append(node)
        for child in node.children:
            _search(child)

    _search(tree.root_node)
    return returns


def _extract_args_with_nesting(text, func_name):
    """从代码行中提取函数调用的完整参数字符串，支持嵌套括号（回退方案）"""
    idx = text.find(func_name + '(')
    if idx < 0:
        short_name = func_name.split('.')[-1]
        idx = text.find(short_name + '(')
        if idx < 0:
            return None
        idx += len(short_name)
    else:
        idx += len(func_name)
    if idx >= len(text) or text[idx] != '(':
        return None
    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for i in range(idx, len(text)):
        ch = text[i]
        if in_string:
            if ch == '\\' and i + 1 < len(text):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            if depth == 0:
                return text[start:i]
            depth -= 1
    return None


# ---------------------------------------------------------------------------
# 分支约束追踪（if/while/foreach）
# ---------------------------------------------------------------------------

def _extract_constraints_from_cs_expr(cond_node):
    """从 C# 条件表达式中提取 BranchConstraint 列表。"""
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _node_text(n):
        return _get_node_text(n)

    def _get_cs_var_name(n):
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'member_access_expression':
            if n.children:
                return _get_cs_var_name(n.children[0])
        if n.type == 'invocation_expression':
            return None
        return None

    def _get_cs_literal_value(n):
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
        op_node = None
        left_node = None
        right_node = None
        found_op = False
        for child in cond_node.children:
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
                constraints.extend(_extract_constraints_from_cs_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_cs_expr(right_node))
            return constraints

        if op_text == '||':
            or_constraints = []
            if left_node:
                or_constraints.extend(_extract_constraints_from_cs_expr(left_node))
            if right_node:
                or_constraints.extend(_extract_constraints_from_cs_expr(right_node))
            from collections import defaultdict
            eq_values = defaultdict(list)
            other = []
            for c in or_constraints:
                if c.op == '==' and c.var_name:
                    eq_values[c.var_name].append(c.value)
                else:
                    other.append(c)
            for vn, values in eq_values.items():
                constraints.append(BranchConstraint(
                    var_name=vn, op='in',
                    value=values if len(values) > 1 else values[0]))
            constraints.extend(other)
            return constraints

        if op_text in ('==', '!='):
            var_name = _get_cs_var_name(left_node)
            if var_name:
                value = _get_cs_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
            else:
                var_name = _get_cs_var_name(right_node)
                if var_name:
                    value = _get_cs_literal_value(left_node)
                    neg_op = '!=' if op_text == '==' else '=='
                    constraints.append(BranchConstraint(var_name=var_name, op=neg_op, value=value))

    if node_type == 'unary_expression':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == '!' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                inner_constraints = _extract_constraints_from_cs_expr(inner)
                if inner_constraints:
                    constraints = [c.negate() for c in inner_constraints]
                    return constraints

    return constraints


def _find_enclosing_branch(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if/while/foreach/switch 语句节点。"""
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
                elif child.type == 'else_clause':
                    for ec in child.children:
                        if ec.type == 'block':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                                    best[0] = (node, 'if')
                                break
                        elif ec.type == 'if_statement':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                _search(ec)

        elif node.type in ('while_statement', 'for_statement', 'foreach_statement', 'do_statement'):
            for child in node.children:
                if child.type == 'block':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            branch_type = 'for' if node.type in ('for_statement', 'foreach_statement') else 'while'
                            best[0] = (node, branch_type)
                        break

        for child in node.children:
            _search(child)

    _search(root_node)
    return best[0]


def _check_cs_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。"""
    tree = _parse_csharp_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_branch(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_cs_if_constraint(node, vul_lineno, var_name)
    elif node_type in ('for', 'while'):
        return _check_cs_loop_constraint(node, vul_lineno, var_name)

    return False


def _check_cs_if_constraint(if_node, vul_lineno, var_name):
    """检查 C# if/else 分支约束。"""
    cond_node = None
    if_body = None
    else_body = None

    for child in if_node.children:
        if child.type == 'else_clause':
            for ec in child.children:
                if ec.type == 'block':
                    else_body = ec
                elif ec.type == 'if_statement':
                    return _check_cs_if_constraint(ec, vul_lineno, var_name)
        elif child.type == 'block' and if_body is None:
            if_body = child
        if child.type not in ('if', 'block', 'else_clause', '(', ')') and if_body is None:
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

    constraints = _extract_constraints_from_cs_expr(cond_node)

    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][C#] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!=', 'not in'):
            logger.info("[AST][C#] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_cs_loop_constraint(loop_node, vul_lineno, var_name):
    """检查 C# for/while 循环条件约束。"""
    cond_node = None
    body_node = None

    for child in loop_node.children:
        if child.type == 'block' and body_node is None:
            body_node = child
        elif child.type not in ('while', 'for', 'foreach', 'block',
                                 '(', ')', ';', 'var', 'in') and body_node is None:
            cond_node = child

    if body_node is None:
        return False

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return False

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_cs_expr(cond_node)

    for c in constraints:
        if c.var_name == var_name and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][C#] Loop constraint BLOCKS: ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


# ---------------------------------------------------------------------------
# 变量追踪
# ---------------------------------------------------------------------------

def _is_controlled_var(var_name, param_names, controlled_params, _depth=0):
    """检查变量是否可控（递归追踪赋值链）"""
    if var_name in controlled_params:
        return True
    if var_name in param_names:
        controlled_params.append(var_name)
        return True
    if _depth > 5:
        return False
    return False


# ---------------------------------------------------------------------------
# 主扫描入口
# ---------------------------------------------------------------------------

def scan_function(file_path, func_name, vul_function, param_names=None,
                  ban_params=None, repair_functions=None, _depth=0):
    """
    扫描单个函数，寻找从可控参数到敏感函数的数据流。

    :param file_path: 文件路径
    :param func_name: 当前函数名
    :param vul_function: 敏感函数名
    :param param_names: 函数形参列表
    :param ban_params: 已知不可控的参数
    :param repair_functions: 安全修复函数列表
    :param _depth: 递归深度
    :return: list[dict] 扫描结果
    """
    if _depth > 15:
        return []

    if func_name in _scan_function_stack:
        return []
    _scan_function_stack.append(func_name)

    results = []

    try:
        tree = _parse_csharp_ast(file_path)
        if tree is None:
            return []

        # 初始化函数摘要
        _init_function_summaries(file_path)

        # 初始化 Source Discovery
        global _sd_registry
        if _sd_registry is None:
            pt = _ast_object_singleton
            project_dir = os.path.dirname(file_path)
            if pt and hasattr(pt, 'target_directory'):
                project_dir = pt.target_directory
            _sd_registry = discover_sources(project_dir, tree, file_path, CSHARP_CONTROLLED_SOURCES)

        # 查找目标函数
        def _find_target(node):
            if node.type in ('method_declaration', 'constructor_declaration'):
                for child in node.children:
                    if child.type == 'identifier':
                        name = _get_node_text(child)
                        if name == func_name:
                            return node
            for child in node.children:
                result = _find_target(child)
                if result:
                    return result
            return None

        target_node = _find_target(tree.root_node)
        if target_node is None:
            return []

        # 提取参数
        actual_param_names = param_names or []
        if not actual_param_names:
            for child in target_node.children:
                if child.type == 'parameter_list':
                    actual_param_names = _get_formal_param_names(child)
                    break

        controlled = list(actual_param_names)
        if ban_params:
            controlled = [p for p in controlled if p not in ban_params]

        # 遍历函数体
        _scan_ast_node(target_node, file_path, func_name, vul_function,
                       controlled, results, repair_functions or [], _depth)

    except Exception as e:
        logger.warning(f"[AST][C#] scan_function error: {e}")
    finally:
        if func_name in _scan_function_stack:
            _scan_function_stack.remove(func_name)

    return results


def _scan_ast_node(node, file_path, func_name, vul_function,
                   controlled, results, repair_functions, depth):
    """递归扫描 AST 节点，寻找漏洞模式"""
    if node is None:
        return

    node_type = node.type

    # 检查 invocation_expression 是否匹配敏感函数
    if node_type == 'invocation_expression':
        _check_vul_invocation(node, file_path, func_name, vul_function,
                              controlled, results, repair_functions, depth)

    # 赋值追踪
    if node_type == 'assignment_expression':
        _track_assignment(node, controlled, depth)

    # 变量声明追踪
    if node_type == 'local_variable_declaration':
        _track_local_var_decl(node, controlled, depth)

    # 字段声明
    if node_type == 'field_declaration':
        _track_field_decl(node, controlled, depth)

    # 递归遍历子节点（不进入嵌套函数定义）
    if node_type not in ('method_declaration', 'constructor_declaration',
                         'destructor_declaration', 'property_declaration'):
        for child in node.children:
            _scan_ast_node(child, file_path, func_name, vul_function,
                           controlled, results, repair_functions, depth)


def _check_vul_invocation(node, file_path, func_name, vul_function,
                          controlled, results, repair_functions, depth):
    """检查 invocation_expression 是否匹配敏感函数"""
    # 提取调用者名称
    callee_name = ""
    for child in node.children:
        if child.type in ('identifier', 'member_access_expression', 'generic_name'):
            callee_name = _get_node_text(child)
            break

    if not callee_name:
        return

    short_name = callee_name.split('.')[-1]
    vul_short = vul_function.split('.')[-1]

    if vul_function not in callee_name and vul_short not in callee_name:
        return

    lineno = node.start_point[0] + 1

    # 检查参数
    arg_list = None
    for child in node.children:
        if child.type == 'argument_list':
            arg_list = child
            break

    if arg_list is None:
        return

    for child in arg_list.children:
        if child.type in ('(', ')', ','):
            continue

        arg_text = _get_node_text(child).strip()
        arg_vars = _extract_var_names_from_expr(arg_text)

        for var in arg_vars:
            if var in controlled:
                # 检查分支约束
                if _check_cs_branch_constraints(file_path, lineno, var):
                    continue

                result_item = {
                    'code': _cs_line_to_text(file_path, lineno),
                    'vul_func': callee_name,
                    'param': var,
                    'line': lineno,
                    'file_path': file_path,
                    'language': 'csharp',
                }
                results.append(result_item)
                logger.info(f"[AST][C#] Found vulnerability: {callee_name} at line {lineno}, "
                            f"controlled param: {var}")


def _track_assignment(node, controlled, depth):
    """追踪赋值表达式"""
    left_node = None
    right_node = None
    found_op = False
    for child in node.children:
        if child.type in ('=', '+=', '-=', '*=', '/=', '%=',
                          '&=', '|=', '^=', '<<=', '>>='):
            found_op = True
            continue
        if not found_op and left_node is None:
            left_node = child
        elif found_op and right_node is None:
            right_node = child

    if left_node is None or right_node is None:
        return

    left_text = _get_node_text(left_node).strip()
    right_text = _get_node_text(right_node).strip()
    right_vars = _extract_var_names_from_expr(right_text)

    # 简单标识符赋值
    var_match = re.match(r'^([a-zA-Z_]\w*)$', left_text)
    if var_match:
        var_name = var_match.group(1)
        # 如果右侧有任何可控变量，则左值也变为可控
        for rv in right_vars:
            if rv in controlled:
                if var_name not in controlled:
                    controlled.append(var_name)
                break


def _track_local_var_decl(node, controlled, depth):
    """追踪局部变量声明"""
    for child in node.children:
        if child.type == 'variable_declarator':
            for sc in child.children:
                if sc.type == 'identifier':
                    var_name = _get_node_text(sc)
                elif sc.type == 'equals_value_clause':
                    for ssc in sc.children:
                        if ssc.type not in ('=',):
                            rhs_vars = _extract_var_names_from_expr(_get_node_text(ssc))
                            for rv in rhs_vars:
                                if rv in controlled:
                                    if var_name not in controlled:
                                        controlled.append(var_name)
                                    break


def _track_field_decl(node, controlled, depth):
    """追踪字段声明"""
    for child in node.children:
        if child.type == 'variable_declarator':
            for sc in child.children:
                if sc.type == 'identifier':
                    var_name = _get_node_text(sc)
                elif sc.type == 'equals_value_clause':
                    for ssc in sc.children:
                        if ssc.type not in ('=',):
                            rhs_vars = _extract_var_names_from_expr(_get_node_text(ssc))
                            for rv in rhs_vars:
                                if rv in controlled:
                                    if var_name not in controlled:
                                        controlled.append(var_name)
                                    break


def scan_match(file_path, func_name, vul_function, match_str, param_names=None,
               ban_params=None, _depth=0):
    """基于正则的扫描入口"""
    # AST 扫描
    results = scan_function(file_path, func_name, vul_function, param_names,
                           ban_params, _depth=_depth)

    # 正则回退
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        lines = content.splitlines()

        short_name = vul_function.split('.')[-1]
        for i, line in enumerate(lines):
            line_no = i + 1
            if vul_function in line or short_name in line:
                for param in (param_names or []):
                    if param in line and param not in (ban_params or []):
                        if _check_cs_branch_constraints(file_path, line_no, param):
                            continue
                        result_item = {
                            'code': line.strip(),
                            'vul_func': vul_function,
                            'param': param,
                            'line': line_no,
                            'file_path': file_path,
                            'language': 'csharp',
                        }
                        results.append(result_item)
    except Exception as e:
        logger.warning(f"[AST][C#] scan_match regex error: {e}")

    return results
