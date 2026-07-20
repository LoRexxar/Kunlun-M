#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Go AST Parser — Go 反向污点追踪引擎
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Go 语言静态分析引擎，支持正则匹配和 AST 污点追踪。

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import re
import traceback
import ast
import tokenize
import io

from utils.log import logger
from core.pretreatment import ast_object as _ast_object_singleton
from core.core_engine.trace_cache import TraceCache
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.go.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.go.summary_generator import generate_file_summaries, lookup_summary, _summary_registry
from core.core_engine.function_summary import SummaryCacheManager
from core.core_engine.go.source_discovery import (
    SourceRegistry, SourceInfo, discover_sources
)

# tree-sitter Go AST 解析
import tree_sitter_go as _tsgo
from tree_sitter import Language as _TS_Language, Parser as _TS_Parser

_GO_TS_LANGUAGE = _TS_Language(_tsgo.language())
_ts_parser = _TS_Parser(_GO_TS_LANGUAGE)
_HAS_TREE_SITTER = True

scan_results = []
is_repair_functions = []
is_controlled_params = []
scan_chain = []

# 追踪缓存 + 内置知识库
_trace_cache = TraceCache("go")

# 跨函数追踪递归防护栈
_scan_function_stack = []

# 函数摘要状态
_summaries_initialized = False
_file_summaries = {}

# Source Discovery registry
_sd_registry = None

# Go 特有的可控输入源
GO_CONTROLLED_SOURCES = [
    "r.URL.Query()", "r.FormValue", "r.PostFormValue",
    "r.Header.Get", "r.Header.Get",
    "r.Body", "r.URL.Path", "r.URL.RawPath",
    "r.Host", "r.RemoteAddr", "r.UserAgent",
    "r.Referer", "r.Method",
    "os.Args",  # CLI-only, not web-controllable
    "os.Getenv",
    "flag.String", "flag.Int", "flag.Bool",
    "gin.Default", "c.Query", "c.Param", "c.PostForm",
    "c.ShouldBind", "c.ShouldBindJSON", "c.ShouldBindQuery",
    "c.GetHeader", "c.GetCookie",
    "echo.QueryParams", "echo.FormValue",
    "fiber.Query", "fiber.Params", "fiber.Body",
    "beego.Input", "beego.GetString", "beego.GetStrings",
]

# Go 特有的敏感函数列表
GO_SENSITIVE_SINKS = [
    "exec.Command", "exec.CommandContext",
    "os.Open", "os.Create", "os.Remove", "os.RemoveAll",
    "ioutil.ReadFile", "ioutil.WriteFile",
    "os.ReadFile", "os.WriteFile",
    "http.Get", "http.Post", "http.NewRequest",
    "sql.Open", "db.Query", "db.QueryRow", "db.Exec",
    "db.Prepare", "tx.Exec", "tx.Query",
    "template.HTML", "template.JS", "template.CSS",
    "template.URL", "template.HTMLAttr",
    "fmt.Sprintf", "fmt.Fprintf", "fmt.Printf",
    "log.Printf", "log.Fatalf",
    "net.Dial", "net.Listen",
    "xml.NewDecoder", "json.Unmarshal",
    "yaml.Unmarshal", "toml.Decode",
    "filepath.Join", "filepath.Abs",
    "regexp.Compile", "regexp.MustCompile",
]


def _extract_var_names_from_expr(expr):
    """
    从 Go 表达式中提取变量名（标识符），用于复合表达式的污点追踪。
    支持：字符串拼接 ("a" + var + "b")、fmt.Sprintf("...%s", var)、简单变量
    """
    if not expr or not expr.strip():
        return []

    expr = expr.strip()
    names = []

    # 字符串拼接: "SELECT..." + userId + "..." + name
    if '+' in expr:
        parts = expr.split('+')
        for part in parts:
            part = part.strip()
            # 跳过字符串字面量
            if (part.startswith('"') and part.endswith('"')) or \
               (part.startswith('`') and part.endswith('`')):
                continue
            # 跳过数字字面量
            if re.match(r'^\d+(\.\d+)?$', part):
                continue
            # 提取标识符（允许 a.b 形式的字段/方法调用）
            ident = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)', part)
            if ident:
                name = ident.group(1)
                # 排除 Go 内置常量/类型
                if name not in ('true', 'false', 'nil', 'int', 'string', 'bool',
                                'float32', 'float64', 'byte', 'rune', 'error',
                                'len', 'cap', 'make', 'new', 'append', 'copy',
                                'delete', 'panic', 'recover', 'print', 'println',
                                'complex', 'real', 'imag', 'close'):
                    names.append(name)
        return names

    # fmt.Sprintf / fmt.Fprintf 等格式化函数调用
    fmt_match = re.match(r'fmt\.\w+\s*\(\s*"[^"]*"(?:\s*,\s*(.+))?\)', expr)
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
        # 检查内置知识库
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


def _go_line_to_text(file_path, lineno):
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
        from core.core_engine.go.summary_generator import generate_file_summaries, generate_summaries_for_target

        # 确定缓存目录（扫描目标根目录下的 .kunlun_cache）
        target_dir = file_path
        pt = _ast_object_singleton
        if pt and hasattr(pt, 'target_directory'):
            target_dir = pt.target_directory
        elif pt and hasattr(pt, 'pre_result'):
            # 取公共前缀作为 target_dir
            paths = list(pt.pre_result.keys())
            if len(paths) > 1:
                target_dir = os.path.commonpath(paths)
            elif paths:
                target_dir = os.path.dirname(paths[0])

        cache_mgr = SummaryCacheManager()

        # 收集所有 Go 文件内容
        files_dict = {}
        if pt and hasattr(pt, 'pre_result'):
            for fp, data in pt.pre_result.items():
                if data.get('language') == 'go':
                    try:
                        with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                            files_dict[fp] = f.read()
                    except Exception:
                        pass
        # 也加入当前文件
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                files_dict[file_path] = f.read()
        except Exception:
            pass

        if files_dict:
            # 尝试从缓存加载
            cached = cache_mgr.load_or_generate(target_dir, files_dict)

            # 需要重新生成的文件
            need_generate = {fp: content for fp, content in files_dict.items()
                             if not cached.get(fp) or not cached[fp].functions}

            # 生成缺失的摘要
            if need_generate:
                new_summaries = generate_summaries_for_target(target_dir, need_generate)
                for fp, fs in new_summaries.items():
                    cached[fp] = fs
                    # 保存到缓存
                    cache_mgr.save_file_summary(target_dir, fp, fs)

            _file_summaries = cached
            logger.debug(f"[AST][Go] 摘要初始化完成: {len(_file_summaries)} 个文件"
                         f" (缓存命中 {len(files_dict) - len(need_generate)}/{len(files_dict)})")

        _summaries_initialized = True
    except Exception as e:
        logger.warning(f"[AST][Go] 摘要初始化失败: {e}")


# ---- tree-sitter AST 辅助函数 ----

_ast_cache = {}  # file_path → tree
_import_cache = {}  # file_path → {别名: [文件路径列表]}
_package_name_cache = {}  # file_path → package_name


# ---------------------------------------------------------------------------
# 分支约束追踪（if/for）
# ---------------------------------------------------------------------------

def _extract_constraints_from_go_expr(cond_node):
    """从 Go 条件表达式中提取 BranchConstraint 列表。

    支持的模式:
    - x == value         -> BranchConstraint(x, ==, value)
    - x != value         -> BranchConstraint(x, !=, value)
    - x && y / x || y    -> 递归拆分
    - unicode.IsDigit(x)  -> BranchConstraint(x, type_validated, unicode.IsDigit)
    """
    if cond_node is None:
        return []

    constraints = []
    node_type = cond_node.type

    def _node_text(n):
        return n.text.decode('utf-8', errors='ignore')

    def _get_go_var_name(n):
        """从 tree-sitter Go 节点提取变量名。"""
        if n is None:
            return None
        if n.type == 'identifier':
            return _node_text(n)
        if n.type == 'selector_expression':
            # a.b 形式取 a
            if n.children:
                return _get_go_var_name(n.children[0])
        if n.type == 'index_expression':
            if n.children:
                return _get_go_var_name(n.children[0])
        if n.type == 'call_expression':
            return None
        if n.type == 'parenthesized_expression':
            if n.children and len(n.children) >= 2:
                return _get_go_var_name(n.children[1])
        return None

    def _get_go_literal_value(n):
        """从 tree-sitter Go 节点提取字面量值。"""
        if n is None:
            return None
        if n.type in ('int_literal', 'float_literal', 'imaginary_literal'):
            try:
                return int(_node_text(n))
            except ValueError:
                return _node_text(n)
        if n.type in ('interpreted_string_literal', 'raw_string_literal', 'rune_literal'):
            return _node_text(n).strip('"').strip('`').strip("'")
        if n.type == 'true':
            return True
        if n.type == 'false':
            return False
        if n.type == 'nil':
            return None
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
                constraints.extend(_extract_constraints_from_go_expr(left_node))
            if right_node:
                constraints.extend(_extract_constraints_from_go_expr(right_node))
            return constraints

        if op_text == '||':
            or_constraints = []
            if left_node:
                or_constraints.extend(_extract_constraints_from_go_expr(left_node))
            if right_node:
                or_constraints.extend(_extract_constraints_from_go_expr(right_node))
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
            var_name = _get_go_var_name(left_node)
            if var_name:
                value = _get_go_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
            else:
                # 尝试右操作数为变量
                var_name = _get_go_var_name(right_node)
                if var_name:
                    value = _get_go_literal_value(left_node)
                    neg_op = '!=' if op_text == '==' else '=='
                    constraints.append(BranchConstraint(var_name=var_name, op=neg_op, value=value))

        return constraints

    if node_type == 'unary_expression':
        if cond_node.children:
            op_text = _node_text(cond_node.children[0])
            if op_text == '!' and len(cond_node.children) > 1:
                inner = cond_node.children[1]
                inner_constraints = _extract_constraints_from_go_expr(inner)
                if inner_constraints:
                    constraints = [c.negate() for c in inner_constraints]
                    return constraints
        return constraints

    if node_type == 'call_expression':
        func_node = None
        args = []
        for child in cond_node.children:
            if child.type in ('identifier', 'selector_expression'):
                func_node = child
            elif child.type == 'argument_list':
                args = [c for c in child.children if c.type not in ('(', ')', ',')]

        if func_node and args:
            func_name = _node_text(func_node)
            GO_TYPE_FUNCS = {
                'unicode.IsDigit', 'unicode.IsLetter', 'unicode.IsNumber',
                'unicode.IsUpper', 'unicode.IsLower', 'unicode.IsTitle',
                'unicode.IsPrint', 'unicode.IsPunct', 'unicode.IsSpace',
                'unicode.IsGraphic', 'unicode.IsControl',
                'unicode.IsMark', 'unicode.IsSymbol',
            }
            if func_name in GO_TYPE_FUNCS and len(args) >= 1:
                var_name = _get_go_var_name(args[0])
                if var_name:
                    constraints.append(BranchConstraint(var_name=var_name, op='type_validated', value=func_name))

        return constraints

    if node_type == 'parenthesized_expression':
        if cond_node.children and len(cond_node.children) >= 2:
            return _extract_constraints_from_go_expr(cond_node.children[1])

    return constraints


def _find_enclosing_if_for_go(root_node, vul_lineno):
    """找到包含 vul_lineno 的最近 if 或 for 语句节点。

    返回 (node, type_str) 或 None。type_str 为 'if' 或 'for'。
    使用深度优先遍历，返回最内层匹配。
    """
    best = [None]

    def _search(node):
        if node.type == 'if_statement':
            # 检查 if body 和 else body 的行范围
            for child in node.children:
                if child.type == 'block' or child.type == 'compound_statement':
                    start = child.start_point[0] + 1
                    end = child.end_point[0] + 1
                    if start <= vul_lineno <= end:
                        # 如果已有更内层的匹配，保留更内层的
                        if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                            best[0] = (node, 'if')
                        break
                elif child.type == 'else_clause':
                    for ec in child.children:
                        if ec.type == 'block' or ec.type == 'compound_statement':
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                if best[0] is None or (best[0][0].start_point[0] < node.start_point[0]):
                                    best[0] = (node, 'if')
                                break
                        elif ec.type == 'if_statement':
                            # else if 嵌套
                            start = ec.start_point[0] + 1
                            end = ec.end_point[0] + 1
                            if start <= vul_lineno <= end:
                                _search(ec)

        elif node.type == 'for_statement':
            for child in node.children:
                if child.type == 'block' or child.type == 'compound_statement':
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


def _check_go_branch_constraints(file_path, vul_lineno, var_name):
    """检查 vul_lineno 处的变量使用是否在受约束的分支中。

    返回 True（阻断）或 False（不阻断）。
    """
    tree = _parse_go_ast(file_path)
    if tree is None:
        return False

    result = _find_enclosing_if_for_go(tree.root_node, vul_lineno)
    if result is None:
        return False

    node, node_type = result

    if node_type == 'if':
        return _check_go_if_constraint(node, vul_lineno, var_name)
    elif node_type == 'for':
        return _check_go_for_constraint(node, vul_lineno, var_name)

    return False


def _check_go_if_constraint(if_node, vul_lineno, var_name):
    """检查 Go if/else 分支约束。

    Go if_statement 结构:
      if_statement
        ├── "if"
        ├── expression (或 simple_statement + ";" + expression)  ← 条件
        ├── block                                                ← if body
        └── else_clause (可选)
             ├── "else"
             ├── block                                           ← else body
             └── if_statement                                    ← else if

    返回 True（阻断）/ False（不阻断）。
    """
    cond_node = None
    if_body = None
    else_body = None

    # Go if 可能有 simple_statement; expression 的形式
    # 简单处理：找 block 和 else_clause
    saw_cond = False
    for child in if_node.children:
        if child.type == 'else_clause':
            for ec in child.children:
                if ec.type == 'block':
                    else_body = ec
                elif ec.type == 'if_statement':
                    return _check_go_if_constraint(ec, vul_lineno, var_name)
        elif child.type == 'block' and if_body is None:
            if_body = child
        # 条件节点：block 之前的非关键字节点
        if child.type not in ('if', 'block', 'else_clause') and if_body is None:
            cond_node = child

    if cond_node is None:
        return False

    # 处理带 simple_statement 的 if: if_stmt; expr
    # cond_node 可能是一个 expression_list 或 expression
    actual_cond = cond_node
    if cond_node.type == 'expression_list':
        # 取最后一个作为条件
        exprs = [c for c in cond_node.children if c.type != ';']
        if exprs:
            actual_cond = exprs[-1]

    if_start = if_body.start_point[0] + 1 if if_body else None
    if_end = if_body.end_point[0] + 1 if if_body else None
    else_start = else_body.start_point[0] + 1 if else_body else None
    else_end = else_body.end_point[0] + 1 if else_body else None

    in_if = if_start is not None and if_end is not None and if_start <= vul_lineno <= if_end
    in_else = else_start is not None and else_end is not None and else_start <= vul_lineno <= else_end

    if not in_if and not in_else:
        return False

    constraints = _extract_constraints_from_go_expr(actual_cond)

    for c in constraints:
        if c.var_name != var_name:
            continue
        if in_if and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][Go] Branch constraint BLOCKS: if ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True
        if in_else and c.op in ('!=', 'not in'):
            logger.info("[AST][Go] Branch constraint BLOCKS: else ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _check_go_for_constraint(for_node, vul_lineno, var_name):
    """检查 Go for 循环条件约束。

    返回 True（阻断）/ False（不阻断）。
    """
    cond_node = None
    body_node = None

    for child in for_node.children:
        if child.type == 'block' and body_node is None:
            body_node = child
        elif child.type not in ('for', 'block') and body_node is None:
            cond_node = child

    if body_node is None:
        return False

    body_start = body_node.start_point[0] + 1
    body_end = body_node.end_point[0] + 1

    if not (body_start <= vul_lineno <= body_end):
        return False

    if cond_node is None:
        return False

    constraints = _extract_constraints_from_go_expr(cond_node)

    for c in constraints:
        if c.var_name == var_name and c.op in ('==', 'in', 'type_validated', 'regex_validated'):
            logger.info("[AST][Go] For constraint BLOCKS: for ({} {} {}) at line {}".format(
                c.var_name, c.op, c.value, vul_lineno))
            return True

    return False


def _parse_go_ast(file_path):
    """用 tree-sitter 解析 Go 文件，返回 AST tree（带缓存）"""
    if file_path in _ast_cache:
        return _ast_cache[file_path]
    try:
        with open(file_path, 'rb') as f:
            source = f.read()
        tree = _ts_parser.parse(source)
        _ast_cache[file_path] = tree
        return tree
    except Exception as e:
        logger.warning(f"[AST][Go] Go AST 解析失败: file={file_path}, error={e}")
        return None


def _get_package_name(file_path):
    """从 AST 中获取 Go 文件的 package 名（带缓存）"""
    if file_path in _package_name_cache:
        return _package_name_cache[file_path]
    tree = _parse_go_ast(file_path)
    if not tree:
        _package_name_cache[file_path] = None
        return None
    for child in tree.root_node.children:
        if child.type == 'package_clause':
            for cc in child.children:
                if cc.type == 'package_identifier':
                    name = cc.text.decode('utf-8', errors='ignore')
                    _package_name_cache[file_path] = name
                    return name
    _package_name_cache[file_path] = None
    return None


def _parse_go_imports(file_path):
    """解析 Go import 语句，返回 {别名: [文件路径列表]} 映射（带缓存）

    Go import 路径不是本地文件路径，需要通过包名匹配：
    1. 解析当前文件的 import 语句，提取 import 路径和别名
    2. 从 pre_result 获取所有 Go 文件的包名
    3. import 路径最后一段 == 包名 → 匹配为本地文件
    """
    if file_path in _import_cache:
        return _import_cache[file_path]

    tree = _parse_go_ast(file_path)
    if not tree:
        _import_cache[file_path] = {}
        return {}

    # 第一步：从 AST 解析 import 声明，收集 (别名, import路径)
    raw_imports = []  # [(alias, import_path)]

    def _collect_imports(node):
        if node.type == 'import_declaration':
            for child in node.children:
                if child.type == 'import_spec':
                    _parse_single_import_spec(child)
                elif child.type == 'import_spec_list':
                    for spec_child in child.children:
                        if spec_child.type == 'import_spec':
                            _parse_single_import_spec(spec_child)

    def _parse_single_import_spec(spec_node):
        alias = None
        import_path = None
        is_blank = False

        for child in spec_node.children:
            if child.type == 'package_identifier':
                alias = child.text.decode('utf-8', errors='ignore')
            elif child.type == 'blank_identifier':
                is_blank = True
            elif child.type == 'interpreted_string_literal':
                # 提取引号内的文本
                text = child.text.decode('utf-8', errors='ignore')
                if text.startswith('"') and text.endswith('"'):
                    import_path = text[1:-1]
                elif text.startswith('`') and text.endswith('`'):
                    import_path = text[1:-1]

        # 跳过 blank import
        if is_blank:
            return
        if not import_path:
            return

        # 确定别名：显式别名 > 默认取路径最后一段
        if alias is None:
            alias = import_path.rsplit('/', 1)[-1] if '/' in import_path else import_path

        raw_imports.append((alias, import_path))

    _collect_imports(tree.root_node)

    # 第二步：从 pre_result 构建 包名 → [文件路径] 映射
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, 'pre_result'):
        _import_cache[file_path] = {}
        return {}

    pkg_to_files = {}  # 包名 → [文件路径列表]
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get('language') != 'go':
            continue
        pkg_name = _get_package_name(other_fp)
        if pkg_name:
            pkg_to_files.setdefault(pkg_name, []).append(other_fp)

    # 第三步：用 import 路径最后一段匹配包名
    import_map = {}  # {别名: [文件路径列表]}
    for alias, import_path in raw_imports:
        path_last_segment = import_path.rsplit('/', 1)[-1] if '/' in import_path else import_path
        matched_files = pkg_to_files.get(path_last_segment, [])
        if matched_files:
            existing = import_map.get(alias, [])
            for fp in matched_files:
                if fp not in existing:
                    existing.append(fp)
            import_map[alias] = existing

    _import_cache[file_path] = import_map
    return import_map


def _find_call_at_line(tree, lineno, func_name):
    """
    在 AST 中查找指定行号上的 call_expression 节点。
    匹配 func_name（支持 db.Query、exec.Command 等完整名称）。
    优先返回有参数的内层调用（如 exec.Command(...) 而非 .Output()）。
    """
    if tree is None:
        return None

    # func_name 的短名称（如 exec.Command → Command）
    short_name = func_name.split('.')[-1]

    def _get_args_text(node):
        """获取 call_expression 的参数文本"""
        for child in node.children:
            if child.type == 'argument_list':
                return child.text.decode('utf-8', errors='ignore')
        return ''

    def _search(node):
        if node.type == 'call_expression':
            node_line = node.start_point[0] + 1  # tree-sitter 0-indexed
            if node_line == lineno:
                # 先递归搜索所有子节点，找内层调用
                for child in node.children:
                    result = _search(child)
                    if result:
                        return result
                
                # 内层没有匹配，检查当前节点
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


def _get_call_func_text(call_node):
    """获取 call_expression 的函数名文本"""
    if call_node.children:
        return call_node.children[0].text.decode('utf-8', errors='ignore')
    return ''


def _get_call_args_from_ast(call_node):
    """
    从 call_expression 节点提取参数列表。
    返回 AST 节点列表（不含括号和逗号）。
    """
    for child in call_node.children:
        if child.type == 'argument_list':
            args = []
            for arg_child in child.children:
                if arg_child.type not in ('(', ')', ','):
                    args.append(arg_child)
            return args
    return []


def _collect_identifiers_from_ast(node):
    """
    从 AST 节点中递归收集所有 identifier（变量名）。
    排除包名（qualified_type 中的 package_identifier）和类型名。
    """
    identifiers = []

    def _walk(n):
        if n.type == 'identifier':
            name = n.text.decode('utf-8', errors='ignore')
            # 排除 Go 关键字和内置常量
            if name not in ('true', 'false', 'nil', 'int', 'string', 'bool',
                            'float32', 'float64', 'byte', 'rune', 'error',
                            'len', 'cap', 'make', 'new', 'append', 'copy',
                            'delete', 'panic', 'recover', 'print', 'println',
                            'complex', 'real', 'imag', 'close', 'iota',
                            'new', 'defer', 'go', 'select', 'case', 'default',
                            'func', 'return', 'if', 'else', 'for', 'range',
                            'switch', 'type', 'struct', 'interface', 'map',
                            'chan', 'package', 'import', 'const', 'var'):
                identifiers.append(name)
        elif n.type == 'selector_expression':
            # a.b → 收集基础变量 a（不收集 .b 因为它是属性/方法名）
            if n.children and n.children[0].type == 'identifier':
                base_name = n.children[0].text.decode('utf-8', errors='ignore')
                identifiers.append(base_name)
            # 也收集完整表达式文本（如 os.Args, r.URL.Query）
            full_text = n.text.decode('utf-8', errors='ignore')
            if full_text not in identifiers:
                identifiers.append(full_text)
            # 递归处理子节点（可能包含 call_expression）
            for child in n.children:
                _walk(child)
        elif n.type == 'call_expression':
            # 函数调用：只收集参数中的标识符，不收集函数名本身
            for child in n.children:
                if child.type == 'argument_list':
                    for arg_child in child.children:
                        _walk(arg_child)
        else:
            for child in n.children:
                _walk(child)

    _walk(node)
    # 去重保持顺序
    seen = set()
    unique = []
    for name in identifiers:
        if name not in seen:
            seen.add(name)
            unique.append(name)
    return unique


# ---- AST-based 赋值分析辅助函数 ----

_LITERAL_NODE_TYPES = frozenset([
    'interpreted_string_literal', 'raw_string_literal',
    'int_literal', 'float_literal',
    'true', 'false', 'nil',
    'composite_literal',  # struct/map/slice literals
    'rune_literal',
])


def _is_literal_node(node):
    """检查 AST 节点是否是字面量"""
    if node.type in _LITERAL_NODE_TYPES:
        return True
    # int/float with sign prefix: - 作为 unary_expression 也算
    if node.type == 'unary_expression' and node.children:
        op = node.children[0].text.decode('utf-8', errors='ignore') if node.children else ''
        if op in ('-', '+') and len(node.children) >= 2:
            return _is_literal_node(node.children[-1])
    return False


def _get_node_identifier(node):
    """从 AST 节点提取标识符文本（处理 selector_expression）"""
    if node.type == 'identifier':
        return node.text.decode('utf-8', errors='ignore')
    if node.type == 'selector_expression':
        return node.text.decode('utf-8', errors='ignore')
    if node.type == 'field_identifier':
        return node.text.decode('utf-8', errors='ignore')
    return None


def _find_assignment_rhs_at_line(tree, lineno, var_name):
    """
    在 AST 中查找指定行上 var_name 的赋值 RHS 节点。
    支持：
      - short_var_declaration (a := expr)
      - assignment_statement (a = expr)
      - var_declaration (var a Type = expr)
    返回 RHS expression_list 节点或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        # 检查行范围：节点必须在目标行上
        node_line = node.start_point[0] + 1
        if node_line > lineno:
            return  # 超过目标行，剪枝

        if node.type == 'short_var_declaration':
            if node_line == lineno:
                # 结构: expression_list (LHS) := expression_list (RHS)
                lhs_list = None
                rhs_list = None
                for child in node.children:
                    if child.type == 'expression_list':
                        if lhs_list is None:
                            lhs_list = child
                        else:
                            rhs_list = child
                if lhs_list and rhs_list:
                    # 检查 LHS 是否包含 var_name
                    for lhs_child in lhs_list.children:
                        if lhs_child.type == 'identifier':
                            name = lhs_child.text.decode('utf-8', errors='ignore')
                            if name == var_name:
                                # RHS 的 expression_list 中取第一个表达式
                                if rhs_list.children:
                                    # 取 expression_list 的第一个非逗号子节点
                                    for rc in rhs_list.children:
                                        if rc.type != ',':
                                            result[0] = rc
                                            return
                                result[0] = rhs_list
                                return

        elif node.type == 'assignment_statement':
            if node_line == lineno:
                lhs_list = None
                rhs_list = None
                for child in node.children:
                    if child.type == 'expression_list':
                        if lhs_list is None:
                            lhs_list = child
                        else:
                            rhs_list = child
                if lhs_list and rhs_list:
                    for lhs_child in lhs_list.children:
                        if lhs_child.type == 'identifier':
                            name = lhs_child.text.decode('utf-8', errors='ignore')
                            if name == var_name:
                                if rhs_list.children:
                                    for rc in rhs_list.children:
                                        if rc.type != ',':
                                            result[0] = rc
                                            return
                                result[0] = rhs_list
                                return

        elif node.type == 'var_declaration':
            if node_line == lineno:
                # var a Type = expr  →  var_spec 内部
                for child in node.children:
                    if child.type == 'var_spec':
                        # var_spec: name type = value
                        name_node = None
                        value_list = None
                        for sc in child.children:
                            if sc.type == 'identifier':
                                name_node = sc
                            elif sc.type == 'expression_list':
                                value_list = sc
                        if name_node:
                            name = name_node.text.decode('utf-8', errors='ignore')
                            if name == var_name and value_list:
                                if value_list.children:
                                    for vc in value_list.children:
                                        if vc.type != ',':
                                            result[0] = vc
                                            return
                                result[0] = value_list
                                return

        # 继续递归子节点
        for child in node.children:
            _search(child)
            if result[0] is not None:
                return

    _search(tree.root_node)
    return result[0]


def _get_call_expr_from_node(node):
    """
    从节点中查找第一个 call_expression。
    用于处理 expression_list 包裹的情况。
    """
    if node.type == 'call_expression':
        return node
    for child in node.children:
        result = _get_call_expr_from_node(child)
        if result:
            return result
    return None


def _find_enclosing_function(tree, lineno):
    """
    在 AST 中查找包含指定行的函数定义。
    返回函数的 parameter_list 节点和函数名，或 None。
    """
    if tree is None:
        return None

    result = [None]

    def _search(node):
        if result[0] is not None:
            return
        if node.type in ('function_declaration', 'method_declaration'):
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            if start_line <= lineno <= end_line:
                func_name = None
                params = None
                for child in node.children:
                    if child.type == 'identifier':
                        func_name = child.text.decode('utf-8', errors='ignore')
                    elif child.type == 'parameter_list' and params is None:
                        params = child
                    elif child.type == 'field_identifier':
                        func_name = child.text.decode('utf-8', errors='ignore')
                result[0] = (func_name, params, start_line, end_line)
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
        if child.type == 'parameter_declaration':
            for sc in child.children:
                if sc.type == 'identifier':
                    names.append(sc.text.decode('utf-8', errors='ignore'))
                    break
    return names


def _find_return_nodes(tree, start_line, end_line):
    """
    在 AST 中查找指定行范围内的 return_statement 节点列表。
    """
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
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[start:i]
    return None


def _extract_function_name(line_text):
    """从 Go 代码行提取函数调用名"""
    if not line_text:
        return None

    # 匹配常见 Go 函数调用模式
    # 如: exec.Command(...), os.Open(...), r.URL.Query().Get(...)
    patterns = [
        r'(\w+(?:\.\w+)+)\s*\(',  # pkg.Func( or obj.Method(
        r'(\w+)\s*\(',              # Func(
    ]

    for pattern in patterns:
        m = re.search(pattern, line_text)
        if m:
            return m.group(1)
    return None


def _is_controllable_source(expr_str, controlled_params=None):
    """检查表达式是否是可控输入源"""
    if controlled_params is None:
        controlled_params = is_controlled_params

    for cp in controlled_params:
        if cp in expr_str:
            return True

    for src in GO_CONTROLLED_SOURCES:
        if src in expr_str:
            return True

    # Source Discovery: 检查用户自定义 source
    if _sd_registry and _sd_registry.is_source_member(expr_str):
        return True

    return False


def _is_repair_function(expr_str, repair_functions=None):
    """
    检查表达式是否包含修复函数 — 精确匹配函数名。
    Go 修复函数名格式为 "pkg.Func"（如 "html.EscapeString"）。
    """
    if repair_functions is None:
        repair_functions = is_repair_functions

    if not repair_functions:
        return False

    for rf in repair_functions:
        # 精确匹配：expr_str 就是函数名、或以 "func_name(" 开头
        if expr_str == rf or expr_str.startswith(rf + "("):
            return True
    return False


def _split_args_respecting_parens(args_str):
    """
    分割函数参数，正确处理嵌套括号和引号内的逗号
    """
    if not args_str or not args_str.strip():
        return []
    args = []
    current = ''
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if in_string:
            current += ch
            if ch == '\\' and i + 1 < len(args_str):
                current += args_str[i + 1]
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            current += ch
        elif ch == '(':
            depth += 1
            current += ch
        elif ch == ')':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            args.append(current.strip())
            current = ''
        else:
            current += ch
        i += 1
    if current.strip():
        args.append(current.strip())
    return args


def _parse_func_call_from_expr(expr):
    """
    从表达式中提取第一个函数调用的函数名和参数字符串。
    支持嵌套括号和引号内的括号。
    返回 (func_name, args_str) 或 None
    """
    if not expr:
        return None
    # 找到第一个 '(' 的位置
    idx = expr.find('(')
    if idx <= 0:
        return None
    # 提取函数名：前一个 token
    prefix = expr[:idx].strip()
    # 函数名可能是 a.b.c 格式
    m = re.match(r'^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)$', prefix)
    if not m:
        return None
    func_name = m.group(1)
    # 用括号计数法提取参数
    depth = 0
    in_string = False
    string_char = None
    start = idx + 1
    for j in range(idx, len(expr)):
        ch = expr[j]
        if in_string:
            if ch == '\\' and j + 1 < len(expr):
                continue
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'", '`'):
            in_string = True
            string_char = ch
            continue
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return (func_name, expr[start:j])
    return None


# ---- 函数定义索引 ----
# _func_def_index[(file_path, func_name)] = (formal_params, body_lines, def_lineno)
# 在 scan_parser 入口构建，function_back_go 查表
_func_def_index = {}
_func_def_indexed_files = set()


def _build_func_def_index(file_path):
    """预扫描文件，索引所有 func 定义"""
    if file_path in _func_def_indexed_files:
        return
    _func_def_indexed_files.add(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return

    pat_func = re.compile(r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(')
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = pat_func.match(stripped)
        if m:
            func_name = m.group(1)
            # 避免重复索引（同名方法可能有 receiver 变体）
            if (file_path, func_name) in _func_def_index:
                continue
            result = _find_function_def_in_lines(lines, func_name, from_line=i + 2)
            if result is not None:
                _func_def_index[(file_path, func_name)] = result


def _build_func_def_index_cross_file():
    """预扫描所有 Go 文件的函数定义（跨文件索引）"""
    pt = _ast_object_singleton
    if not pt or not hasattr(pt, 'pre_result'):
        return
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get('language') == 'go':
            _build_func_def_index(other_fp)


def _find_function_def_in_lines(lines, func_name, from_line=None):
    """
    在代码行列表中搜索 Go 函数定义。
    支持：func Name(...) 和 func (receiver) Name(...)
    返回 (formal_params, func_body_lines, def_lineno) 或 None
    """
    # 搜索范围：from_line 之前的所有行（向后搜索）
    search_range = from_line if from_line else len(lines)

    # 模式1: func (receiver) Name(
    # 模式2: func Name(
    pat_method = re.compile(r'^func\s*\([^)]+\)\s*' + re.escape(func_name) + r'\s*\(')
    pat_func = re.compile(r'^func\s+' + re.escape(func_name) + r'\s*\(')

    for i in range(search_range - 1, -1, -1):
        line = lines[i].strip()
        if pat_method.match(line) or pat_func.match(line):
            # 提取参数列表
            paren_idx = line.find('(')
            if paren_idx < 0:
                continue

            # 对于方法定义 func (r *T) Name(...，需要跳过 receiver 的括号
            if line.startswith('func') and paren_idx > 4:
                prefix = line[:paren_idx].strip()
                # 检查是否有 receiver
                receiver_match = re.match(r'^func\s*\(([^)]*)\)\s*' + re.escape(func_name), line)
                if receiver_match:
                    # 找到参数的 '(' (receiver 之后的)
                    after_receiver = line[receiver_match.end():]
                    param_start = after_receiver.find('(')
                    if param_start < 0:
                        continue
                    # 完整行中找到参数的括号对
                    # receiver_match.end() 在完整行中指向 receiver 之后的位置
                    full_param_start = receiver_match.end() + param_start
                else:
                    full_param_start = paren_idx
            else:
                full_param_start = paren_idx

            # 提取参数（可能跨多行）
            full_line = line
            # 如果行中没有闭合括号，继续读下一行
            j = i
            while full_line.count('(') > full_line.count(')') and j + 1 < len(lines):
                j += 1
                full_line += ' ' + lines[j].strip()

            # 找到参数列表的括号对
            param_start = full_line.find('(', full_param_start)
            if param_start < 0:
                continue
            depth = 0
            param_end = -1
            for k in range(param_start, len(full_line)):
                if full_line[k] == '(':
                    depth += 1
                elif full_line[k] == ')':
                    depth -= 1
                    if depth == 0:
                        param_end = k
                        break
            if param_end < 0:
                continue

            param_text = full_line[param_start + 1:param_end]
            # 解析形参名
            formal_params = []
            for part in _split_args_respecting_parens(param_text):
                # "name type" 格式
                tokens = part.strip().rsplit(' ', 1)
                if len(tokens) >= 2:
                    formal_params.append(tokens[0].strip())

            # 找到函数体的开始 '{' 和结束 '}'
            brace_idx = full_line.find('{', param_end)
            if brace_idx < 0:
                continue
            body_start_line = j + 1  # 从函数定义行之后开始（0-indexed）
            # 对于跨行的情况，body_start_line 需要准确
            # 简单方案：用 brace 计数从 brace_idx 开始
            brace_depth = 0
            body_lines = []
            started = False
            # 从定义行的 '{' 开始
            for bi in range(i, len(lines)):
                bl = lines[bi].strip()
                for ch in bl:
                    if ch == '{':
                        brace_depth += 1
                        if not started:
                            started = True
                    elif ch == '}':
                        brace_depth -= 1
                        if started and brace_depth == 0:
                            return (formal_params, body_lines, i + 1)  # 1-indexed
                if started:
                    body_lines.append(bl)
            # 如果没找到闭合括号，返回已有内容
            if body_lines:
                return (formal_params, body_lines, i + 1)
            break
    return None


def _text_trace_variable(file_path, var_name, vul_lineno,
                          repair_functions=None, controlled_params=None):
    """
    纯文本 fallback 追踪：不依赖 tree-sitter AST。
    从 vul_lineno 向上逐行查找 var_name 的赋值，判断是否来自可控源。
    返回: (code, source_lineno)
    """
    import re as _re
    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        logger.warning('[AST][Go] _text_trace_variable failed to read {}: {}'.format(file_path, e))
        return (-1, 0)

    # 向上查找赋值
    for i in range(vul_lineno - 2, -1, -1):
        line = lines[i].strip()
        # 匹配 var_name := ... 或 var_name = ...
        m = _re.match(r'(?:' + _re.escape(var_name) + r')\s*(?::=|=)\s*(.+)', line)
        if not m:
            # 短变量声明 x, y := ... 形式
            m2 = _re.match(r'[\w,\s]*\b' + _re.escape(var_name) + r'\b\s*:=\s*(.+)', line)
            if not m2:
                continue
            rhs = m2.group(1).strip()
        else:
            rhs = m.group(1).strip()

        src_lineno = i + 1

        # 检查是否是函数调用结果
        # fmt.Fprintf(os.Stdin, ..., r.FormValue(...)) 等
        # r.FormValue / r.URL.Query / req.FormValue 等 HTTP source
        http_patterns = [
            r'\.FormValue\s*\(', r'\.Query\s*\(\)', r'\.Get\s*\(',
            r'\.URL\.Query', r'\.PostFormValue', r'\.Form\s*\[',
            r'\.Cookie\s*\(', r'\.Cookies\s*\(',
        ]
        for pat in http_patterns:
            if _re.search(pat, rhs):
                return (1, src_lineno)

        # 检查是否来自其他变量赋值 → 递归追踪
        sub_vars = _re.findall(r'[a-zA-Z_]\w*', rhs)
        for sv in sub_vars:
            if sv in ('true', 'false', 'nil', 'string', 'int', 'fmt', 'err', 'nil'):
                continue
            if sv == var_name:
                continue
            # 可控参数列表
            if sv in controlled_params:
                return (1, src_lineno)
            # 递归追踪子变量
            sub_code, sub_line = _text_trace_variable(
                file_path, sv, src_lineno, repair_functions, controlled_params
            )
            if sub_code == 1:
                return (1, sub_line)

        # 没有子变量，不可控
        return (-1, src_lineno)

    return (-1, 0)


def _trace_variable_in_lines(file_path, var_name, from_line, to_line,
                              repair_functions=None, controlled_params=None,
                              depth=0, max_depth=5):
    """
    在指定行范围内追踪变量的数据流（缓存包装层）

    入口查缓存，出口写缓存（仅缓存 depth=0 的顶层调用）。
    实际逻辑在 _trace_variable_in_lines_impl 中。

    返回: (code, source_lineno) 元组
    """
    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    # 顶层调用才查/写缓存
    if depth == 0 and file_path and to_line:
        cached = _trace_cache.get(file_path, var_name, int(to_line))
        if cached is not None:
            # cached 格式: (code, [], to_line) → 返回 (code, source_lineno)
            return (cached[0], cached[2] if len(cached) > 2 else to_line)

    code, source_lineno = _trace_variable_in_lines_impl(
        file_path, var_name, from_line, to_line,
        repair_functions, controlled_params, depth, max_depth
    )

    # 顶层调用写缓存（仅确定性结果）
    if depth == 0 and file_path and to_line and code in (1, 2, -1):
        _trace_cache.put(file_path, var_name, int(to_line), (code, [], source_lineno))

    return (code, source_lineno)


def _analyze_rhs_node(rhs_node, var_name, file_path, lineno, to_line,
                      repair_functions, controlled_params, depth, max_depth):
    """
    根据 RHS AST 节点类型分派分析。
    返回: (code, source_lineno) 如果确定，None 如果需要继续扫描。
    """
    rhs_text = rhs_node.text.decode('utf-8', errors='ignore')

    # 快速检查：可控源
    if _is_controllable_source(rhs_text, controlled_params):
        logger.debug("[AST][Go] Variable {} RHS is controllable source: {}".format(var_name, rhs_text[:80]))
        return (1, lineno)

    # 快速检查：修复函数
    if _is_repair_function(rhs_text, repair_functions):
        logger.debug("[AST][Go] Variable {} RHS is repaired: {}".format(var_name, rhs_text[:80]))
        return (2, lineno)

    node_type = rhs_node.type

    # 字面量 → 安全
    if _is_literal_node(rhs_node):
        return (-1, 0)

    # 函数调用
    if node_type == 'call_expression':
        return _handle_call_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 字符串拼接 (binary_expression with +)
    if node_type == 'binary_expression':
        return _handle_binary_expression_rhs(
            rhs_node, var_name, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth
        )

    # 简单变量赋值 a = b
    if node_type == 'identifier':
        name = rhs_node.text.decode('utf-8', errors='ignore')
        if name == var_name:
            return None  # 自赋值，跳过
        if _is_controllable_source(name, controlled_params):
            return (1, lineno)
        return _trace_variable_in_lines(
            file_path, name, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )

    # selector_expression (如 r.URL.Query().Get("key"))
    # 这通常包含在 call_expression 中，但如果是裸的 selector，检查可控源
    if node_type == 'selector_expression':
        if _is_controllable_source(rhs_text, controlled_params):
            return (1, lineno)
        # 检查基础变量
        if rhs_node.children and rhs_node.children[0].type == 'identifier':
            base = rhs_node.children[0].text.decode('utf-8', errors='ignore')
            if _is_controllable_source(base, controlled_params):
                return (1, lineno)

    # parenthesized_expression → 解包
    if node_type == 'parenthesized_expression':
        for child in rhs_node.children:
            if child.type not in ('(', ')'):
                return _analyze_rhs_node(
                    child, var_name, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth
                )

    # type_conversion_expression (如 string(body))
    if node_type == 'type_conversion_expression':
        args = [c for c in rhs_node.children if c.type not in ('(', ')') and not c.type.endswith('_type')]
        for arg in args:
            result = _analyze_rhs_node(
                arg, var_name, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth
            )
            if result is not None:
                return result

    # 其他类型：收集标识符逐一追踪
    var_names = _collect_identifiers_from_ast(rhs_node)
    for vn in var_names:
        if vn == var_name:
            continue
        if _is_controllable_source(vn, controlled_params):
            return (1, lineno)
        r = _trace_variable_in_lines(
            file_path, vn, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )
        if r[0] in (1, 2):
            return r

    return None  # 未确定，继续扫描


def _handle_call_expression_rhs(call_node, var_name, file_path, lineno, to_line,
                                 repair_functions, controlled_params, depth, max_depth):
    """处理函数调用赋值的 RHS 分析，返回 (code, source_lineno) 或 None"""
    func_text = _get_call_func_text(call_node)
    args = _get_call_args_from_ast(call_node)

    # 检查内置知识库
    knowledge = lookup_builtin(func_text)
    if knowledge:
        if knowledge.get("safe") and not knowledge.get("passthrough") and not knowledge.get("param_flow"):
            logger.debug("[AST][Go] RHS call {} is safe per knowledge base".format(func_text))
            return (-1, 0)
        if knowledge.get("passthrough") or knowledge.get("param_flow"):
            # 关键修复：追踪 ALL 非字面量参数，不只是 passthrough 索引
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
                        repair_functions, controlled_params, depth + 1, max_depth
                    )
                    if r[0] in (1, 2):
                        return r
            return None  # passthrough 但参数都安全

    # 未知函数 → NewCore
    args_str = ', '.join(a.text.decode('utf-8', errors='ignore') for a in args)
    logger.debug("[AST][Go] Unknown function call {} → NewCore".format(func_text))
    return (5, func_text)


def _handle_binary_expression_rhs(bin_node, var_name, file_path, lineno, to_line,
                                   repair_functions, controlled_params, depth, max_depth):
    """处理字符串拼接 (binary_expression with +) 的 RHS 分析，返回 (code, source_lineno) 或 None"""
    for child in bin_node.children:
        if child.type in ('+', '-', '||', '&&'):
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
                repair_functions, controlled_params, depth + 1, max_depth
            )
            if r[0] in (1, 2):
                return r
    return None


def _trace_variable_in_lines_impl(file_path, var_name, from_line, to_line,
                                   repair_functions, controlled_params,
                                   depth, max_depth):
    """
    在指定行范围内追踪变量的数据流（纯 AST 版本）

    使用 tree-sitter AST 查找 var_name 的赋值，按节点类型分派分析。
    完全移除正则，参考 Python 引擎的 _trace_stmt / _trace_expr 模式。

    返回值:
        (code, source_lineno) 元组
        code: 1 (可控), 2 (已修复), 3 (未确认), -1 (不可控)
        source_lineno: source 赋值行号
    """
    from core.core_engine.go._ast_trace import (
        trace_go_stmt, trace_go_expr, _find_assignment_in_block,
        _get_node_text, _is_controlled_source_node,
        _get_formal_param_names as _get_formal_param_names_ast,
        ASSIGNMENT_TYPES,
    )

    if repair_functions is None:
        repair_functions = is_repair_functions
    if controlled_params is None:
        controlled_params = is_controlled_params

    if depth > max_depth:
        return (-1, 0)

    # 用 tree-sitter 解析文件
    tree = _parse_go_ast(file_path)
    if not tree:
        return (-1, 0)  # 无 AST，无法分析

    # 获取函数体（block 节点）
    func_info = _find_enclosing_function(tree, to_line)
    if not func_info:
        return (-1, 0)

    func_name, params_node, func_start, func_end = func_info

    # 在函数体内查找 var_name 的赋值
    # 找到函数体的 block 节点
    candidates = []

    def _find_func(node):
        if node.type in ('function_declaration', 'method_declaration', 'func_literal'):
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= to_line <= end:
                candidates.append(node)
        for child in node.children:
            _find_func(child)

    _find_func(tree.root_node)
    if candidates:
        func_node = min(candidates, key=lambda n: n.end_point[0] - n.start_point[0])
    else:
        func_node = None

    if not func_node:
        return (-1, 0)

    # 获取函数体 block
    body_block = None
    for child in func_node.children:
        if child.type == 'block':
            body_block = child
            break

    if not body_block:
        return (-1, 0)

    # 在函数体中查找赋值（使用 trace_go_stmt 以支持分支约束）
    stmt_list = None
    for child in body_block.children:
        if child.type == 'statement_list':
            stmt_list = child
            break
    if stmt_list:
        # 反向遍历（最近赋值优先）
        for i in range(len(stmt_list.children) - 1, -1, -1):
            stmt = stmt_list.children[i]
            result = trace_go_stmt(
                var_name, stmt, file_path, to_line, to_line,
                repair_functions, controlled_params, depth, max_depth,
                _trace_variable_in_lines
            )
            if result is not None:
                return result

    # ---- 未找到赋值来源：检查 var_name 是否是函数形参 ----
    if params_node:
        formal_param_names = _get_formal_param_names_ast(params_node)
        if var_name in formal_param_names:
            logger.debug("[AST][Go] Variable {} is function param of {} → NewCore".format(var_name, func_name))
            return (5, func_name)

    return (-1, 0)


def scan_parser(rule_match, vul_lineno, file_path,
                repair_functions=None, controlled_params=None,
                svid=None, is_config_vuln=False, indirect_map=None):
    """
    Go AST 扫描入口

    :param rule_match: 规则匹配的函数名列表
    :param vul_lineno: 漏洞行号
    :param file_path: 文件路径
    :param repair_functions: 修复函数列表
    :param controlled_params: 可控参数列表
    :param svid: 规则编号
    :param is_config_vuln: 是否配置型漏洞
    :param indirect_map: 间接调用映射 {变量名: sink函数名}，用于替换行文本中的变量名做匹配
    :return: 扫描结果列表
    """
    # 清除上次扫描残留，重建 GO_CONTROLLED_SOURCES 初始列表（防止跨项目污染）
    global GO_CONTROLLED_SOURCES
    GO_CONTROLLED_SOURCES = [
        "r.URL.Query()", "r.FormValue", "r.PostFormValue",
        "r.Header.Get", "r.Header.Get",
        "r.Body", "r.URL.Path", "r.URL.RawPath",
        "r.Host", "r.RemoteAddr", "r.UserAgent",
        "r.Referer", "r.Method",
        "os.Args",  # CLI-only, not web-controllable
        "os.Getenv",
        "flag.String", "flag.Int", "flag.Bool",
        "gin.Default", "c.Query", "c.Param", "c.PostForm",
        "c.ShouldBind", "c.ShouldBindJSON", "c.ShouldBindQuery",
        "c.GetHeader", "c.GetCookie",
        "echo.QueryParams", "echo.FormValue",
        "fiber.Query", "fiber.Params", "fiber.Body",
        "beego.Input", "beego.GetString", "beego.GetStrings",
    ]
    _trace_cache.clear()

    if repair_functions is None:
        repair_functions = []
    if controlled_params is None:
        controlled_params = []

    # ---- 预建函数定义索引（仅首次调用时构建） ----
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
        logger.warning("[AST][Go] Invalid vul_lineno: {}".format(vul_lineno))
        return results

    # 获取源码行
    line_text = _go_line_to_text(file_path, vul_lineno)
    if not line_text:
        logger.warning("[AST][Go] Cannot read line {} from {}".format(vul_lineno, file_path))
        return results

    logger.debug("[AST][Go] Scanning line {}: {}".format(vul_lineno, line_text))

    # 间接调用：替换行文本中的变量名为实际 sink 函数名（仅用于匹配，不影响 AST 分析）
    match_line_text = line_text
    if indirect_map:
        for var_name, sink_name in indirect_map.items():
            if var_name in line_text:
                match_line_text = line_text.replace(var_name, sink_name, 1)
                logger.debug("[AST][Go] Indirect call: replaced '{}' -> '{}' in match text".format(var_name, sink_name))
                break

    # 检查行中是否包含规则匹配的函数
    matched_func = None
    for func in rule_match:
        # 清理正则转义
        clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
        if clean_func in match_line_text:
            matched_func = clean_func
            break

    if not matched_func:
        # 模糊匹配
        for func in rule_match:
            clean_func = func.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')')
            parts = clean_func.split('.')
            if any(p in match_line_text for p in parts if len(p) > 2):
                matched_func = clean_func
                break

    if not matched_func:
        logger.debug("[AST][Go] No matching function found in line")
        return results

    # ---- tree-sitter 解析整个文件，获取 AST ----
    ast_tree = _parse_go_ast(file_path)

    # ---- Source Discovery 预处理 ----
    global _sd_registry
    # 将 tamper 框架的 controlled_params 注入到 GO_CONTROLLED_SOURCES
    for cp in controlled_params:
        if cp not in GO_CONTROLLED_SOURCES:
            GO_CONTROLLED_SOURCES.append(cp)
    _sd_registry = discover_sources(file_path, ast_tree, file_path, extra_sources=GO_CONTROLLED_SOURCES)
    # 注入 user source producers 到 GO_CONTROLLED_SOURCES
    for func_name in _sd_registry.user_source_functions:
        if func_name not in GO_CONTROLLED_SOURCES:
            GO_CONTROLLED_SOURCES.append(func_name)

    call_node = None
    ast_args = []  # AST 节点列表

    if ast_tree is not None:
        # 在 AST 中查找 vul_lineno 上的 call_expression
        call_node = _find_call_at_line(ast_tree, vul_lineno, matched_func)
        # 间接调用：如果按 sink 名找不到，用变量名查找
        if call_node is None and indirect_map:
            for var_name in indirect_map:
                call_node = _find_call_at_line(ast_tree, vul_lineno, var_name)
                if call_node is not None:
                    break
        if call_node is not None:
            ast_args = _get_call_args_from_ast(call_node)

    # AST 提取成功 → 用 AST 节点分析参数
    if ast_args:
        # 检查内置知识库
        knowledge = lookup_builtin(matched_func)
        if knowledge and knowledge.get("safe"):
            results.append({'code': -1, 'chain': []})
            return results

        for arg_idx, arg_node in enumerate(ast_args):
            arg_text = arg_node.text.decode('utf-8', errors='ignore')

            # 字符串字面量 → 跳过
            if arg_node.type in ('interpreted_string_literal', 'raw_string_literal',
                                  'int_literal', 'float_literal', 'true', 'false', 'nil'):
                logger.debug("[AST][Go] Arg[{}] is literal: {}".format(arg_idx, arg_text))
                continue

            # 提取参数中的所有标识符
            var_names = _collect_identifiers_from_ast(arg_node)

            for var_name in var_names:
                # 直接可控源
                if _is_controllable_source(var_name, controlled_params):
                    logger.debug("[AST][Go] Variable {} controllable".format(var_name))
                    # 分支约束检查
                    if _check_go_branch_constraints(file_path, vul_lineno, var_name):
                        logger.info("[AST][Go] Branch constraint BLOCKS var {} at line {}".format(var_name, vul_lineno))
                        continue
                    results.append({'code': 1, 'chain': [
                        ('source', var_name, file_path, vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results

                # 反向追踪
                trace_code, src_lineno = _trace_variable_in_lines(
                    file_path, var_name, vul_lineno, vul_lineno,
                    repair_functions, controlled_params
                )
                if trace_code == 1:
                    # 分支约束检查
                    if _check_go_branch_constraints(file_path, vul_lineno, var_name):
                        logger.info("[AST][Go] Branch constraint BLOCKS var {} at line {}".format(var_name, vul_lineno))
                        continue
                    results.append({'code': 1, 'chain': [
                        ('source', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results
                elif trace_code == 2:
                    results.append({'code': 2, 'chain': [
                        ('repair', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results
                elif trace_code == 3:
                    results.append({'code': 3, 'chain': [
                        ('unconfirmed', var_name, file_path, src_lineno if src_lineno else vul_lineno),
                        ('sink', matched_func, file_path, vul_lineno)
                    ]})
                    return results
                elif trace_code == 5:
                    wrapper_func = src_lineno  # code=5 时 src_lineno 存 func_name 字符串
                    wrapper_file = file_path
                    wrapper_lineno = 0
                    lookup_name = wrapper_func.split('.')[-1] if '.' in wrapper_func else wrapper_func
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
                    return results

        results.append({'code': -1, 'chain': []})
        return results

    if is_config_vuln:
        results.append({
            'code': 4,
            'source': matched_func,
            'chain': [('sink', matched_func, file_path, vul_lineno)]
        })
    else:
        results.append({'code': -1, 'chain': []})

    return results


def _find_indirect_calls_in_func(block_node, sink_names, file_path):
    """
    在函数体内检测基于赋值关系的间接调用。
    遍历函数体语句，追踪"变量 = sink_func"模式，然后检测对该变量的调用。

    :param block_node: 函数体的 block AST 节点
    :param sink_names: list of SinkName(class_, method)
    :param file_path: 文件路径
    :return: list of dict（间接调用结果）
    """
    from core.utils import SinkName

    results = []
    var_to_sink = {}  # 变量名 -> matched SinkName

    def _extract_left_identifiers(expr_list_node):
        """从 expression_list 提取所有 identifier 的文本"""
        ids = []
        for child in expr_list_node.children:
            if child.type == 'identifier':
                ids.append(child.text.decode('utf-8', errors='ignore'))
        return ids

    def _check_right_side_sink(expr_list_node):
        """检查右侧 expression_list 中是否有 selector_expression 匹配某个 sink"""
        for child in expr_list_node.children:
            if child.type == 'selector_expression':
                # selector_expression: operand.field
                operand = child.child_by_field_name('operand')
                field = child.child_by_field_name('field')
                if operand and field:
                    obj = operand.text.decode('utf-8', errors='ignore')
                    method = field.text.decode('utf-8', errors='ignore')
                    for sink in sink_names:
                        if sink.class_ and obj == sink.class_ and method == sink.method:
                            return sink
            elif child.type == 'identifier':
                # 纯函数名赋值：f := system
                id_text = child.text.decode('utf-8', errors='ignore')
                for sink in sink_names:
                    if sink.class_ is None and id_text == sink.method:
                        return sink
        return None

    def _scan_statements(node):
        """递归扫描语句节点"""
        for child in node.children:
            # short_var_declaration: f := exec.Command
            if child.type == 'short_var_declaration':
                left_ids = []
                right_sink = None
                right_expr_list = None
                for part in child.children:
                    if part.type == 'expression_list':
                        # 第一个 expression_list 是左侧，第二个是右侧
                        if not left_ids:
                            left_ids = _extract_left_identifiers(part)
                        else:
                            right_sink = _check_right_side_sink(part)
                            right_expr_list = part
                    elif part.type == 'identifier' and not left_ids:
                        # 短变量声明可能没有 expression_list 包装
                        left_ids.append(part.text.decode('utf-8', errors='ignore'))
                    elif right_sink is None and part.type not in (':=', 'expression_list', 'identifier'):
                        right_sink = _check_right_side_sink_in_expr(part)
                if left_ids and right_sink:
                    for var_name in left_ids:
                        var_to_sink[var_name] = right_sink
                elif left_ids and not right_sink and right_expr_list:
                    # 多层间接调用：右侧是 identifier 且在 var_to_sink 中，继承映射
                    for sub in right_expr_list.children:
                        if sub.type == 'identifier':
                            id_text = sub.text.decode('utf-8', errors='ignore')
                            if id_text in var_to_sink:
                                for var_name in left_ids:
                                    var_to_sink[var_name] = var_to_sink[id_text]
                            break  # 只检查第一个 identifier

                # 检查右侧 expression_list 中嵌套的间接调用
                if right_expr_list and var_to_sink:
                    for sub in right_expr_list.children:
                        if sub.type == 'call_expression':
                            callee = sub.children[0] if sub.children else None
                            if callee and callee.type == 'identifier':
                                vname = callee.text.decode('utf-8', errors='ignore')
                                if vname in var_to_sink:
                                    matched_sink = var_to_sink[vname]
                                    lineno = sub.start_point[0] + 1
                                    results.append({
                                        'file_path': file_path,
                                        'lineno': lineno,
                                        'node': sub,
                                        'is_indirect': True,
                                        'callee_name': vname,
                                        'class_name': None,
                                        'matched_sink': matched_sink,
                                    })

            # assignment_statement: f = exec.Command
            elif child.type == 'assignment_statement':
                left_ids = []
                right_sink = None
                expr_lists = []
                for part in child.children:
                    if part.type == 'expression_list':
                        expr_lists.append(part)
                if len(expr_lists) >= 2:
                    left_ids = _extract_left_identifiers(expr_lists[0])
                    right_sink = _check_right_side_sink(expr_lists[1])
                elif len(expr_lists) == 1:
                    # 可能左侧是单个 identifier（无 expression_list 包装）
                    for part in child.children:
                        if part.type == 'identifier' and part not in expr_lists:
                            left_ids.append(part.text.decode('utf-8', errors='ignore'))
                    right_sink = _check_right_side_sink(expr_lists[0])
                # 确定右侧 expression_list
                right_expr_list = None
                if len(expr_lists) >= 2:
                    right_expr_list = expr_lists[1]
                elif len(expr_lists) == 1:
                    right_expr_list = expr_lists[0]

                if left_ids and right_sink:
                    for var_name in left_ids:
                        var_to_sink[var_name] = right_sink
                elif left_ids and not right_sink:
                    # 多层间接调用：仅检查右侧 expression_list 的 identifier 是否在 var_to_sink 中
                    propagated = False
                    if len(expr_lists) >= 2:
                        # 左右分离：只检查右侧
                        right_exprs = expr_lists[1:]
                    elif len(expr_lists) == 1:
                        # 只有一个 expr_list（可能是左侧单 identifier 的情况），不检查
                        right_exprs = []
                    else:
                        right_exprs = []
                    for expr_list in right_exprs:
                        for sub in expr_list.children:
                            if sub.type == 'identifier':
                                id_text = sub.text.decode('utf-8', errors='ignore')
                                if id_text in var_to_sink:
                                    for var_name in left_ids:
                                        var_to_sink[var_name] = var_to_sink[id_text]
                                    propagated = True
                                break
                    if not propagated:
                        for var_name in left_ids:
                            var_to_sink.pop(var_name, None)

                # 检查右侧 expression_list 中嵌套的间接调用
                if right_expr_list and var_to_sink:
                    for sub in right_expr_list.children:
                        if sub.type == 'call_expression':
                            callee = sub.children[0] if sub.children else None
                            if callee and callee.type == 'identifier':
                                vname = callee.text.decode('utf-8', errors='ignore')
                                if vname in var_to_sink:
                                    matched_sink = var_to_sink[vname]
                                    lineno = sub.start_point[0] + 1
                                    results.append({
                                        'file_path': file_path,
                                        'lineno': lineno,
                                        'node': sub,
                                        'is_indirect': True,
                                        'callee_name': vname,
                                        'class_name': None,
                                        'matched_sink': matched_sink,
                                    })

            # call_expression: f(userInput)
            elif child.type == 'call_expression':
                callee = child.children[0] if child.children else None
                if callee and callee.type == 'identifier':
                    var_name = callee.text.decode('utf-8', errors='ignore')
                    if var_name in var_to_sink:
                        matched_sink = var_to_sink[var_name]
                        lineno = child.start_point[0] + 1
                        results.append({
                            'file_path': file_path,
                            'lineno': lineno,
                            'node': child,
                            'is_indirect': True,
                            'callee_name': var_name,
                            'class_name': None,
                            'matched_sink': matched_sink,
                        })

            # 递归进入嵌套 block（if/for/switch 等）
            elif child.child_count > 0 and child.type not in (
                'short_var_declaration', 'assignment_statement', 'call_expression'
            ):
                _scan_statements(child)

    def _check_right_side_sink_in_expr(node):
        """在任意表达式中查找 selector_expression 匹配 sink"""
        if node.type == 'selector_expression':
            operand = node.child_by_field_name('operand')
            field = node.child_by_field_name('field')
            if operand and field:
                obj = operand.text.decode('utf-8', errors='ignore')
                method = field.text.decode('utf-8', errors='ignore')
                for sink in sink_names:
                    if sink.class_ and obj == sink.class_ and method == sink.method:
                        return sink
        for c in node.children:
            result = _check_right_side_sink_in_expr(c)
            if result:
                return result
        return None

    _scan_statements(block_node)
    return results


def find_sinks(sink_names, files):
    """
    AST-based sink 查找。遍历所有文件的 tree-sitter AST 节点，查找匹配的函数调用。
    支持直接调用匹配和间接调用检测。

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
        tree = _parse_go_ast(file_path)
        if not tree:
            continue

        def _walk_for_calls(node):
            if node.type == 'call_expression':
                func_text = _get_call_func_text(node)
                if not func_text:
                    return

                # 提取函数名的短名（如 exec.Command → Command）
                short_name = func_text.split('.')[-1] if '.' in func_text else func_text
                # 提取包名/对象名（如 exec.Command → exec）
                obj_name = func_text.rsplit('.', 1)[0] if '.' in func_text else None

                for sink in sink_names:
                    if sink.class_ is None:
                        # 模糊匹配
                        if func_text == sink.method or short_name == sink.method or func_text.endswith('.' + sink.method):
                            lineno = node.start_point[0] + 1
                            results.append({
                                'file_path': file_path,
                                'lineno': lineno,
                                'node': node,
                                'is_indirect': False,
                                'callee_name': func_text,
                                'class_name': obj_name,
                                'matched_sink': sink,
                            })
                            break
                    else:
                        # 精确匹配
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

        _walk_for_calls(tree.root_node)

        # 基于赋值关系的间接调用检测
        def _walk_for_func_decls(node):
            if node.type in ('function_declaration', 'method_declaration'):
                body = node.child_by_field_name('body')
                if body and body.type == 'block':
                    indirect_results = _find_indirect_calls_in_func(body, sink_names, file_path)
                    results.extend(indirect_results)
            for child in node.children:
                _walk_for_func_decls(child)

        _walk_for_func_decls(tree.root_node)

    return results


def analysis_params(param_name, parent_func_names, vul_function, lineno, file_path,
                    repair_functions=None, controlled_params=None, isexternal=False):
    """
    Go 变量可控性分析（供 CAST 跨文件分析调用）

    :param param_name: 要追踪的变量名
    :param parent_func_names: 父函数名列表（Go 中暂不使用）
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

    # ---- 预建函数定义索引 ----
    _build_func_def_index(file_path)

    try:
        lineno = int(lineno)
    except (ValueError, TypeError):
        return -1, [], 0, []

    # 分支约束检查：如果变量在受约束的分支中使用，直接返回不可控
    if _check_go_branch_constraints(file_path, lineno, param_name):
        return -1, [], 0, []

    # 追踪变量
    trace_code, src_lineno = _trace_variable_in_lines(
        file_path, param_name, lineno, lineno,
        repair_functions, controlled_params
    )

    if trace_code == 1:
        return 1, controlled_params, lineno, [('source', param_name, file_path, src_lineno if src_lineno else lineno)]
    elif trace_code == 2:
        return 2, controlled_params, lineno, [('repair', param_name, file_path, src_lineno if src_lineno else lineno)]
    elif trace_code == 3:
        return 3, controlled_params, lineno, [('unconfirmed', param_name, file_path, src_lineno if src_lineno else lineno)]
    elif trace_code == 5:
        wrapper_func = src_lineno
        wrapper_file = file_path
        wrapper_lineno = 0
        lookup_name = wrapper_func.split('.')[-1] if '.' in wrapper_func else wrapper_func
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
