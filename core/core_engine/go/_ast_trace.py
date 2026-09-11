"""
Go AST 纯追踪引擎 — 基于 tree-sitter 的污点分析
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

完全移除正则，所有分析基于 AST 节点类型。
参考 Python 引擎的 _trace_stmt / _trace_expr 模式。
"""

import re
from utils.log import logger
from core.core_engine.branch_constraint import BranchConstraint
from core.core_engine.go.builtin_knowledge import lookup as lookup_builtin
from core.core_engine.go.summary_generator import lookup_summary


# ---- AST 节点类型常量 ----

# 赋值相关
ASSIGNMENT_TYPES = ('short_var_declaration', 'assignment_statement', 'var_declaration')

# 语句类型
STATEMENT_TYPES = (
    'short_var_declaration', 'assignment_statement', 'var_declaration',
    'if_statement', 'for_statement', 'expression_switch_statement', 'type_switch_statement', 'select_statement',
    'return_statement', 'expression_statement', 'block',
    'defer_statement', 'go_statement', 'send_statement',
    'inc_statement', 'dec_statement',
)

# 表达式类型
EXPRESSION_TYPES = (
    'call_expression', 'binary_expression', 'identifier',
    'selector_expression', 'index_expression', 'slice_expression',
    'composite_literal', 'type_conversion_expression',
    'unary_expression', 'parenthesized_expression',
    'interpreted_string_literal', 'raw_string_literal',
    'int_literal', 'float_literal', 'true', 'false', 'nil',
    'func_literal', 'map_literal', 'channel_type',
)


def _get_node_text(node):
    """获取节点文本"""
    return node.text.decode('utf-8', errors='ignore')


def _get_node_name(node):
    """获取标识符节点名称"""
    if node.type == 'identifier':
        return _get_node_text(node)
    if node.type == 'selector_expression':
        # a.b → 返回完整名
        return _get_node_text(node)
    return None


def _is_controlled_source_node(node, controlled_params):
    """检查节点是否是可控输入源"""
    text = _get_node_text(node)
    
    # 检查 controlled_params（Fix 21g: standalone-token matching — see
    # parser._is_controllable_source for the receiver-mention FP rationale）
    for cp in controlled_params:
        if re.search(r"\b" + re.escape(cp) + r"\b(?!\s*\.)", text):
            return True
    
    # 检查内置可控源（Fix 21g: position-aware matching via parser helper —
    # substring containment matched comments/declarations/suffixes and
    # mis-attributed receiver mentions as taint sources）
    from core.core_engine.go.parser import GO_CONTROLLED_SOURCES, _source_hit
    for src in GO_CONTROLLED_SOURCES:
        if _source_hit(text, src):
            return True
    
    # 检查 selector_expression 结构
    if node.type == 'selector_expression':
        # r.URL.Query() → 检查基础变量 r
        if node.children and node.children[0].type == 'identifier':
            base = _get_node_text(node.children[0])
            if base in ('r', 'req', 'request'):
                return True
    
    return False


def _is_repair_node(node, repair_functions):
    """检查节点是否包含修复函数"""
    text = _get_node_text(node)
    for rf in repair_functions:
        if rf in text:
            return True
    return False


def _is_literal_node_safe(node):
    """检查节点是否是字面量（安全）"""
    return node.type in (
        'interpreted_string_literal', 'raw_string_literal',
        'int_literal', 'float_literal', 'true', 'false', 'nil',
        'composite_literal',  # 结构体/数组字面量通常安全
    )


def _collect_identifiers(node):
    """从节点递归收集所有标识符"""
    identifiers = []
    
    def _walk(n):
        if n.type == 'identifier':
            name = _get_node_text(n)
            # 排除 Go 关键字和内置
            if name not in ('true', 'false', 'nil', 'int', 'string', 'bool',
                           'float32', 'float64', 'byte', 'rune', 'error',
                           'len', 'cap', 'make', 'new', 'append', 'copy',
                           'delete', 'panic', 'recover', 'print', 'println',
                           'complex', 'real', 'imag', 'close', 'iota',
                           'defer', 'go', 'select', 'case', 'default',
                           'func', 'return', 'if', 'else', 'for', 'range',
                           'switch', 'type', 'struct', 'interface', 'map',
                           'chan', 'package', 'import', 'const', 'var'):
                identifiers.append(name)
        elif n.type == 'selector_expression':
            # a.b → 收集基础变量 a
            if n.children and n.children[0].type == 'identifier':
                base = _get_node_text(n.children[0])
                if base not in identifiers:
                    identifiers.append(base)
        elif n.type == 'call_expression':
            # 函数调用：只收集参数中的标识符
            for child in n.children:
                if child.type == 'argument_list':
                    for arg_child in child.children:
                        _walk(arg_child)
        else:
            for child in n.children:
                _walk(child)
    
    _walk(node)
    return list(dict.fromkeys(identifiers))  # 去重保序


def _get_call_func_name(call_node):
    """从 call_expression 获取函数名"""
    if not call_node or call_node.type != 'call_expression':
        return None
    
    func_node = call_node.children[0] if call_node.children else None
    if not func_node:
        return None
    
    if func_node.type == 'selector_expression':
        # fmt.Sprintf → "fmt.Sprintf"
        return _get_node_text(func_node)
    elif func_node.type == 'identifier':
        # println → "println"
        return _get_node_text(func_node)
    
    return None


def _get_call_args(call_node):
    """从 call_expression 获取参数节点列表"""
    if not call_node or call_node.type != 'call_expression':
        return []
    
    for child in call_node.children:
        if child.type == 'argument_list':
            args = []
            for arg_child in child.children:
                if arg_child.type not in ('(', ')', ','):
                    args.append(arg_child)
            return args
    
    return []


def _find_assignment_in_block(block_node, var_name):
    """
    在 block/statement_list 中查找 var_name 的赋值，返回 (rhs_node, lineno) 或 None。
    从后向前搜索（最近的赋值优先）。
    """
    if not block_node:
        return None
    
    # 获取 statement_list
    stmt_list = None
    for child in block_node.children:
        if child.type == 'statement_list':
            stmt_list = child
            break
    
    if not stmt_list:
        # 可能是单个语句
        if block_node.type in ASSIGNMENT_TYPES:
            return _check_assignment_node(block_node, var_name)
        return None
    
    # 从后向前遍历语句
    for stmt in reversed(stmt_list.children):
        if stmt.type in ('{', '}'):
            continue
        
        result = _check_assignment_node(stmt, var_name)
        if result:
            return result
        
        # 递归搜索子块（if/for/switch）
        if stmt.type == 'if_statement':
            result = _search_in_if(stmt, var_name)
            if result:
                return result
        elif stmt.type == 'for_statement':
            result = _search_in_for(stmt, var_name)
            if result:
                return result
        elif stmt.type in ('expression_switch_statement', 'type_switch_statement'):
            result = _search_in_switch(stmt, var_name)
            if result:
                return result
    
    return None


def _check_assignment_node(node, var_name):
    """检查节点是否是对 var_name 的赋值，返回 (rhs_node, lineno) 或 None"""
    if node.type == 'short_var_declaration':
        # a := expr
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
                if lhs_child.type == 'identifier' and _get_node_text(lhs_child) == var_name:
                    # 返回 RHS 的第一个非逗号节点
                    for rc in rhs_list.children:
                        if rc.type != ',':
                            return (rc, node.start_point[0] + 1)
                    return (rhs_list, node.start_point[0] + 1)
    
    elif node.type == 'assignment_statement':
        # a = expr
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
                if lhs_child.type == 'identifier' and _get_node_text(lhs_child) == var_name:
                    for rc in rhs_list.children:
                        if rc.type != ',':
                            return (rc, node.start_point[0] + 1)
                    return (rhs_list, node.start_point[0] + 1)
    
    elif node.type == 'var_declaration':
        # var a Type = expr
        for child in node.children:
            if child.type == 'var_spec':
                name_node = None
                value_list = None
                for sc in child.children:
                    if sc.type == 'identifier':
                        name_node = sc
                    elif sc.type == 'expression_list':
                        value_list = sc
                if name_node and _get_node_text(name_node) == var_name and value_list:
                    for vc in value_list.children:
                        if vc.type != ',':
                            return (vc, node.start_point[0] + 1)
                    return (value_list, node.start_point[0] + 1)
    
    elif node.type == 'expression_statement':
        # 可能是 a = expr 包装在 expression_statement 中
        for child in node.children:
            if child.type == 'assignment_statement':
                return _check_assignment_node(child, var_name)
    
    return None


def _search_in_if(if_node, var_name):
    """在 if 语句中搜索赋值"""
    for child in if_node.children:
        if child.type == 'block':
            result = _find_assignment_in_block(child, var_name)
            if result:
                return result
        elif child.type == 'else_clause':
            # else { ... } 或 else if ... { ... }
            for ec_child in child.children:
                if ec_child.type == 'block':
                    result = _find_assignment_in_block(ec_child, var_name)
                    if result:
                        return result
                elif ec_child.type == 'if_statement':
                    result = _search_in_if(ec_child, var_name)
                    if result:
                        return result
    return None


def _search_in_for(for_node, var_name):
    """在 for 语句中搜索赋值"""
    for child in for_node.children:
        if child.type == 'block':
            result = _find_assignment_in_block(child, var_name)
            if result:
                return result
        elif child.type == 'range_clause':
            # for i, v := range expr
            lhs_list = None
            range_expr = None
            for rc in child.children:
                if rc.type == 'expression_list' and lhs_list is None:
                    lhs_list = rc
                elif rc.type not in (':=', 'range', ','):
                    range_expr = rc
            if lhs_list:
                for lc in lhs_list.children:
                    if lc.type == 'identifier' and _get_node_text(lc) == var_name and range_expr:
                        return (range_expr, child.start_point[0] + 1)
    return None


def _search_in_switch(switch_node, var_name):
    """在 switch 语句中搜索赋值"""
    for child in switch_node.children:
        if child.type in ('expression_case', 'type_case', 'default_case'):
            for cc in child.children:
                if cc.type == 'block':
                    result = _find_assignment_in_block(cc, var_name)
                    if result:
                        return result
    return None


def _find_sink_branch_go(if_node, vul_lineno):
    """判断 sink 在 Go if/else 的哪个分支"""
    if not vul_lineno:
        return 'outside'
    vul_lineno = int(vul_lineno)

    found_else = False
    for child in if_node.children:
        if child.type == 'else':
            found_else = True
            continue
        if child.type == 'block':
            if hasattr(child, 'start_point') and hasattr(child, 'end_point'):
                if child.start_point[0] <= vul_lineno <= child.end_point[0]:
                    return 'else' if found_else else 'if'
        elif child.type == 'if_statement' and found_else:
            return _find_sink_branch_go(child, vul_lineno)

    return 'outside'


def extract_constraints_from_go_expr(expr_node):
    """
    从 Go if 条件表达式中提取 BranchConstraint 列表。

    tree-sitter Go AST:
    - x == value       -> binary_expression(op='==', left=identifier, right=literal/identifier)
    - x != nil         -> binary_expression(op='!=', left=identifier, right=nil)
    - x != ""           -> binary_expression(op='!=', left=identifier, right=interpreted_string_literal)
    - len(x) > 0        -> binary_expression(op='>', left=call_expression, right=int_literal)
    - x && y            -> binary_expression(op='&&')  注意：tree-sitter Go 把逻辑运算也映射为 binary_expression
    - x || y            -> binary_expression(op='||')
    - !expr             -> unary_expression(op='!')
    """
    if expr_node is None:
        return []

    constraints = []
    node_type = expr_node.type if hasattr(expr_node, 'type') else ''

    # Go tree-sitter 中 && 和 || 是 binary_expression
    if node_type == 'binary_expression':
        # 获取操作符
        op_text = ''
        for child in expr_node.children:
            if child.type not in ('identifier', 'literal', 'nil', 'interpreted_string_literal',
                                  'raw_string_literal', 'int_literal', 'float_literal',
                                  'call_expression', 'parenthesized_expression',
                                  'unary_expression', 'selector_expression',
                                  'composite_literal', 'index_expression',
                                  'type_assertion', 'slice_expression',
                                  'qualified_type', 'array_type',
                                  'binary_expression'):
                op_text = _get_node_text(child)
                break

        if op_text == '&&':
            # AND: 分别提取左右
            children = expr_node.children
            left_node = None
            right_node = None
            found_op = False
            for child in children:
                if _get_node_text(child) == '&&':
                    found_op = True
                    continue
                if not found_op and left_node is None:
                    left_node = child
                elif found_op and right_node is None:
                    right_node = child
            if left_node:
                constraints.extend(extract_constraints_from_go_expr(left_node))
            if right_node:
                constraints.extend(extract_constraints_from_go_expr(right_node))
            return constraints

        if op_text == '||':
            # OR: x == "a" || x == "b" → 收集同一变量的枚举约束
            children = expr_node.children
            left_node = None
            right_node = None
            found_op = False
            for child in children:
                if _get_node_text(child) == '||':
                    found_op = True
                    continue
                if not found_op and left_node is None:
                    left_node = child
                elif found_op and right_node is None:
                    right_node = child
            or_constraints = []
            if left_node:
                or_constraints.extend(extract_constraints_from_go_expr(left_node))
            if right_node:
                or_constraints.extend(extract_constraints_from_go_expr(right_node))
            # 收集同一变量的所有 == 值
            from collections import defaultdict
            eq_values = defaultdict(list)
            for c in or_constraints:
                if c.op == '==' and c.var_name:
                    eq_values[c.var_name].append(c.value)
            for var_name, values in eq_values.items():
                if values:
                    constraints.append(BranchConstraint(
                        var_name=var_name, op='in',
                        value=values if len(values) > 1 else values[0]))
            return constraints

        # 比较运算
        if op_text in ('==', '!=', '>=', '<=', '>', '<'):
            children = expr_node.children
            left_node = None
            right_node = None
            found_op = False
            for child in children:
                if _get_node_text(child) == op_text:
                    found_op = True
                    continue
                if not found_op and left_node is None:
                    left_node = child
                elif found_op and right_node is None:
                    right_node = child
            var_name = _get_go_var_name(left_node)
            if var_name:
                value = _get_go_literal_value(right_node)
                constraints.append(BranchConstraint(var_name=var_name, op=op_text, value=value))
        return constraints

    if node_type == 'unary_expression':
        op_text = _get_node_text(expr_node.children[0]) if expr_node.children else ''
        if op_text == '!':
            inner = expr_node.children[1] if len(expr_node.children) > 1 else None
            if inner:
                inner_constraints = extract_constraints_from_go_expr(inner)
                constraints = [c.negate() for c in inner_constraints]
        return constraints

    return constraints


def _get_go_var_name(node):
    """从 tree-sitter 节点提取变量名（字符串形式）。"""
    if node is None:
        return None
    if hasattr(node, 'type'):
        if node.type == 'identifier':
            return _get_node_text(node)
        if node.type == 'selector_expression':
            # x.Method 或 pkg.Var
            obj = node.children[0] if node.children else None
            sel = node.children[2] if len(node.children) > 2 else None
            obj_name = _get_go_var_name(obj) if obj else ''
            sel_name = _get_go_var_name(sel) if sel else ''
            if obj_name and sel_name:
                return f"{obj_name}.{sel_name}"
    return None


def _get_go_literal_value(node):
    """从 tree-sitter 节点提取字面量值。"""
    if node is None:
        return None
    if hasattr(node, 'type'):
        if node.type == 'nil':
            return None
        if node.type in ('int_literal', 'float_literal'):
            text = _get_node_text(node).strip()
            try:
                if '.' in text:
                    return float(text)
                return int(text)
            except (ValueError, TypeError):
                return text
        if node.type in ('interpreted_string_literal', 'raw_string_literal'):
            text = _get_node_text(node)
            # 去除引号
            if text.startswith('"') and text.endswith('"'):
                return text[1:-1]
            if text.startswith('`') and text.endswith('`'):
                return text[1:-1]
            return text
        if node.type == 'true':
            return True
        if node.type == 'false':
            return False
        if node.type == 'identifier' and _get_node_text(node) == 'nil':
            return None
    return None


def trace_go_expr(var_name, expr_node, file_path, lineno, to_line,
                  repair_functions, controlled_params, depth, max_depth,
                  trace_variable_fn):
    """
    追踪 Go 表达式节点的来源（纯 AST 版本）

    参考 Python 引擎的 _trace_expr 模式，按节点类型分派。

    返回: (code, source_lineno) 元组
        code: 1 (可控), 2 (已修复), 3 (未确认), -1 (不可控)
        source_lineno: source 赋值行号（0 表示无行号）
    """
    if depth > max_depth:
        return (-1, 0)

    expr_text = _get_node_text(expr_node)

    # 1. 快速检查：可控源
    if _is_controlled_source_node(expr_node, controlled_params):
        logger.debug("[AST][Go] Controllable source: {} at L{}".format(expr_text[:60], lineno))
        return (1, lineno)

    # 2. 快速检查：修复函数
    if _is_repair_node(expr_node, repair_functions):
        logger.debug("[AST][Go] Repair function: {} at L{}".format(expr_text[:60], lineno))
        return (2, lineno)

    node_type = expr_node.type

    # 3. 字面量 → 安全
    if _is_literal_node_safe(expr_node):
        return (-1, 0)

    # 4. 函数调用
    if node_type == 'call_expression':
        return _trace_call_expr(
            var_name, expr_node, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth,
            trace_variable_fn
        )

    # 5. 字符串拼接 (binary_expression with +)
    if node_type == 'binary_expression':
        return _trace_binary_expr(
            var_name, expr_node, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth,
            trace_variable_fn
        )

    # 6. 简单变量
    if node_type == 'identifier':
        name = _get_node_text(expr_node)
        if name == var_name:
            return (-1, 0)  # 自赋值
        if _is_controlled_source_node(expr_node, controlled_params):
            return (1, lineno)
        # 继续追踪变量
        return trace_variable_fn(
            file_path, name, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )

    # 7. selector_expression (如 r.URL.Query)
    if node_type == 'selector_expression':
        if _is_controlled_source_node(expr_node, controlled_params):
            return (1, lineno)
        # 检查基础变量
        if expr_node.children and expr_node.children[0].type == 'identifier':
            base = _get_node_text(expr_node.children[0])
            if _is_controlled_source_node(expr_node.children[0], controlled_params):
                return (1, lineno)
            # 追踪基础变量
            return trace_variable_fn(
                file_path, base, lineno, to_line,
                repair_functions, controlled_params, depth + 1, max_depth
            )

    # 8. index_expression (如 x[0])
    if node_type == 'index_expression':
        # 追踪基础对象
        if expr_node.children:
            base = expr_node.children[0]
            return trace_go_expr(
                var_name, base, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth,
                trace_variable_fn
            )

    # 9. type_conversion_expression (如 string(body))
    if node_type == 'type_conversion_expression':
        for child in expr_node.children:
            if child.type not in ('(', ')') and not child.type.endswith('_type'):
                result = trace_go_expr(
                    var_name, child, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth,
                    trace_variable_fn
                )
                if result[0] in (1, 2):
                    return result

    # 10. unary_expression (如 !x)
    if node_type == 'unary_expression':
        for child in expr_node.children:
            if child.type not in ('!', '-', '+', '^', '&', '*'):
                result = trace_go_expr(
                    var_name, child, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth,
                    trace_variable_fn
                )
                if result[0] in (1, 2):
                    return result

    # 11. parenthesized_expression → 解包
    if node_type == 'parenthesized_expression':
        for child in expr_node.children:
            if child.type not in ('(', ')'):
                return trace_go_expr(
                    var_name, child, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth,
                    trace_variable_fn
                )

    # 12. fallback: 收集标识符逐一追踪
    identifiers = _collect_identifiers(expr_node)
    for ident in identifiers:
        if ident == var_name:
            continue
        if _is_controlled_source_node(expr_node, controlled_params):
            return (1, lineno)
        result = trace_variable_fn(
            file_path, ident, lineno, to_line,
            repair_functions, controlled_params, depth + 1, max_depth
        )
        if result[0] in (1, 2):
            return result

    return (-1, 0)


def _trace_call_expr(var_name, call_node, file_path, lineno, to_line,
                     repair_functions, controlled_params, depth, max_depth,
                     trace_variable_fn):
    """追踪函数调用表达式，返回 (code, source_lineno)"""
    func_name = _get_call_func_name(call_node)
    args = _get_call_args(call_node)

    if not func_name:
        return (-1, 0)

    # 检查内置知识库
    knowledge = lookup_builtin(func_name)
    if knowledge:
        if knowledge.get("safe") and not knowledge.get("passthrough"):
            logger.debug("[AST][Go] Safe function: {}".format(func_name))
            return (-1, 0)

        if knowledge.get("passthrough"):
            # 关键：追踪 ALL 非字面量参数
            logger.debug("[AST][Go] Passthrough function: {}, tracing all args".format(func_name))
            for arg_node in args:
                if _is_literal_node_safe(arg_node):
                    continue
                result = trace_go_expr(
                    var_name, arg_node, file_path, lineno, to_line,
                    repair_functions, controlled_params, depth + 1, max_depth,
                    trace_variable_fn
                )
                if result[0] in (1, 2):
                    return result
            return (-1, 0)  # 所有参数都安全

    # 查函数摘要
    callee_summary = lookup_summary(func_name)
    if callee_summary and callee_summary.return_flow:
        for rf in callee_summary.return_flow:
            if rf.origin_type == "param":
                for param_idx in rf.dep_params:
                    if param_idx < len(args):
                        arg_node = args[param_idx]
                        arg_text = _get_node_text(arg_node)
                        if _is_controlled_source_node(arg_node, controlled_params):
                            logger.debug("[AST][Go] Summary: {} param {} is controllable".format(func_name, param_idx))
                            return (1, lineno)
            elif rf.origin_type == "call":
                if controlled_params and rf.origin in controlled_params:
                    logger.debug("[AST][Go] Summary: {} call origin {} is controllable".format(func_name, rf.origin))
                    return (1, lineno)
        # 摘要有 return_flow 但未匹配到可控源 → 不可控
        logger.debug("[AST][Go] Summary: {} has return_flow but no controllable source".format(func_name))
        return (-1, 0)

    # builtin 和 summary 都没有 → 未确认
    logger.debug("[AST][Go] [ast_trace] Unknown function {} → unconfirmed".format(func_name))
    return (3, func_name)


def _trace_binary_expr(var_name, bin_node, file_path, lineno, to_line,
                       repair_functions, controlled_params, depth, max_depth,
                       trace_variable_fn):
    """追踪二元表达式（字符串拼接），返回 (code, source_lineno)"""
    for child in bin_node.children:
        if child.type in ('+', '-', '||', '&&', '==', '!=', '<', '>', '<=', '>='):
            continue
        if _is_literal_node_safe(child):
            continue

        result = trace_go_expr(
            var_name, child, file_path, lineno, to_line,
            repair_functions, controlled_params, depth, max_depth,
            trace_variable_fn
        )
        if result[0] in (1, 2):
            return result

    return (-1, 0)


def _get_formal_param_names(params_node):
    """从 parameter_list 节点提取形参名列表"""
    names = []
    if not params_node or params_node.type != 'parameter_list':
        return names
    
    for child in params_node.children:
        if child.type == 'parameter_declaration':
            # parameter_declaration: identifier type
            for sub in child.children:
                if sub.type == 'identifier':
                    names.append(_get_node_text(sub))
                    break
        elif child.type == 'variadic_parameter_declaration':
            # variadic_parameter_declaration: identifier ... type
            for sub in child.children:
                if sub.type == 'identifier':
                    names.append(_get_node_text(sub))
                    break
    
    return names


def trace_go_stmt(var_name, stmt_node, file_path, vul_lineno, to_line,
                  repair_functions, controlled_params, depth, max_depth,
                  trace_variable_fn):
    """
    追踪 Go 语句中的变量赋值（纯 AST 版本）

    参考 Python 引擎的 _trace_stmt 模式，按语句类型分派。

    返回: (code, source_lineno) 元组或 None (未找到)
    """
    if depth > max_depth:
        return (-1, 0)
    
    # 赋值语句
    if stmt_node.type in ASSIGNMENT_TYPES:
        result = _check_assignment_node(stmt_node, var_name)
        if result:
            rhs_node, lineno = result
            return trace_go_expr(
                var_name, rhs_node, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth,
                trace_variable_fn
            )
    
    # if 语句
    elif stmt_node.type == 'if_statement':
        # 提取 if 条件（Go tree-sitter: 条件是 if_statement 的直接子节点，
        # 类型可能是 binary_expression / unary_expression / call_expression / parenthesized_expression 等）
        if_expr_node = None
        for child in stmt_node.children:
            if child.type in ('binary_expression', 'unary_expression', 'call_expression',
                              'parenthesized_expression', 'identifier', 'expression'):
                if_expr_node = child
                break
        go_constraints = extract_constraints_from_go_expr(if_expr_node)

        sink_branch = _find_sink_branch_go(stmt_node, vul_lineno)
        logger.debug("[AST][Go] sink_branch={} for var {} lineno {}".format(sink_branch, var_name, vul_lineno))

        if sink_branch == 'if':
            for c in go_constraints:
                if c.var_name == var_name and c.op in ('==', '===', 'in'):
                    logger.info("[AST][Go] Branch constraint BLOCKS var {}: {} {}".format(var_name, c.op, c.value))
                    return (-1, 0)
            # 回溯 if 体
            for child in stmt_node.children:
                if child.type == 'block':
                    result = _find_assignment_in_block(child, var_name)
                    if result:
                        rhs_node, lineno = result
                        return trace_go_expr(var_name, rhs_node, file_path, lineno, to_line,
                                             repair_functions, controlled_params, depth, max_depth,
                                             trace_variable_fn)
                    break

        elif sink_branch == 'else':
            else_constraints = [c.negate() for c in go_constraints]
            for c in else_constraints:
                if c.var_name == var_name and c.op in ('==', '===', 'in'):
                    logger.info("[AST][Go] Branch constraint BLOCKS var {}: {} {}".format(var_name, c.op, c.value))
                    return (-1, 0)
            # 回溯 else 体
            found_else = False
            for child in stmt_node.children:
                if child.type == 'else':
                    found_else = True
                    continue
                if found_else:
                    if child.type == 'block':
                        result = _find_assignment_in_block(child, var_name)
                        if result:
                            rhs_node, lineno = result
                            return trace_go_expr(var_name, rhs_node, file_path, lineno, to_line,
                                                 repair_functions, controlled_params, depth, max_depth,
                                                 trace_variable_fn)
                    elif child.type == 'if_statement':
                        return trace_go_stmt(var_name, child, file_path, vul_lineno, to_line,
                                            repair_functions, controlled_params, depth, max_depth,
                                            trace_variable_fn)
                    break

        else:
            # outside: 遍历所有分支（if 体 + else 体）
            for child in stmt_node.children:
                if child.type == 'block':
                    result = _find_assignment_in_block(child, var_name)
                    if result:
                        rhs_node, lineno = result
                        return trace_go_expr(var_name, rhs_node, file_path, lineno, to_line,
                                             repair_functions, controlled_params, depth, max_depth,
                                             trace_variable_fn)
                elif child.type == 'if_statement':
                    return trace_go_stmt(var_name, child, file_path, vul_lineno, to_line,
                                        repair_functions, controlled_params, depth, max_depth,
                                        trace_variable_fn)

    # for 语句
    elif stmt_node.type == 'for_statement':
        # 检测是否为 while 形式的 for（有 condition 但没有 init/update）
        _is_while_form = True
        _for_condition = None
        _for_block = None
        for child in stmt_node.children:
            if child.type == ';':
                _is_while_form = False
            elif child.type == 'range_clause':
                _is_while_form = False
            elif child.type == 'block':
                _for_block = child
            elif child.type != 'for':
                if _for_condition is None:
                    _for_condition = child

        # while 形式的 for 条件等值约束检查：如果条件中 var_name 有 == 约束，且 sink 在 for 体内 → 阻断
        if _is_while_form and _for_condition and _for_block and vul_lineno:
            target_line = int(vul_lineno)
            block_start = _for_block.start_point[0] + 1
            block_end = _for_block.end_point[0] + 1
            if block_start <= target_line <= block_end:
                constraints = extract_constraints_from_go_expr(_for_condition)
                for c in constraints:
                    if c.var_name == var_name and c.op in ('==', '===', 'in'):
                        logger.info("[AST][Go] While constraint BLOCKS var {}: {} {}".format(var_name, c.op, c.value))
                        return (-1, 0)

        for child in stmt_node.children:
            if child.type == 'block':
                result = _find_assignment_in_block(child, var_name)
                if result:
                    rhs_node, lineno = result
                    return trace_go_expr(
                        var_name, rhs_node, file_path, lineno, to_line,
                        repair_functions, controlled_params, depth, max_depth,
                        trace_variable_fn
                    )
            elif child.type == 'range_clause':
                # for i, v := range expr
                result = _search_in_for(stmt_node, var_name)
                if result:
                    rhs_node, lineno = result
                    return trace_go_expr(
                        var_name, rhs_node, file_path, lineno, to_line,
                        repair_functions, controlled_params, depth, max_depth,
                        trace_variable_fn
                    )

    # switch 语句 (expression_switch_statement)
    elif stmt_node.type == 'expression_switch_statement' or stmt_node.type == 'type_switch_statement':
        # switch/case 分支约束追踪
        sink_in_case = False
        sink_case_is_default = False
        target_line = int(vul_lineno) if vul_lineno else 0

        for child in stmt_node.children:
            if child.type in ('expression_case', 'type_case', 'default_case'):
                case_start = child.start_point[0] + 1
                case_end = child.end_point[0] + 1
                if target_line and case_start <= target_line <= case_end:
                    if child.type == 'default_case':
                        sink_case_is_default = True
                    else:
                        sink_in_case = True
                    break

        if sink_in_case:
            # sink 在非 default case 中 → switch expr == case_value → 阻断
            logger.info("[AST][Go] Switch constraint BLOCKS: sink in non-default case (line {})".format(lineno))
            return (-1, None, 0)

        # default case 或 sink 不在 switch 中 → 搜索赋值并回溯
        result = _search_in_switch(stmt_node, var_name)
        if result:
            rhs_node, lineno = result
            return trace_go_expr(
                var_name, rhs_node, file_path, lineno, to_line,
                repair_functions, controlled_params, depth, max_depth,
                trace_variable_fn
            )
    
    # expression_statement (可能包含赋值)
    elif stmt_node.type == 'expression_statement':
        for child in stmt_node.children:
            if child.type == 'assignment_statement':
                return trace_go_stmt(
                    var_name, child, file_path, vul_lineno, to_line,
                    repair_functions, controlled_params, depth, max_depth,
                    trace_variable_fn
                )
    
    return None  # 未找到赋值
