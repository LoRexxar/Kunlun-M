# Python 引擎回溯分析设计文档

> **模块路径**: `core/core_engine/python/`
> **核心文件**: `parser.py` (2050行)
> **辅助文件**: `builtin_knowledge.py`, `summary_generator.py`
> **解析器**: Python 标准库 `ast` 模块（无第三方依赖）

---

## 1. 解析器选型与技术架构

### 1.1 为什么选择标准库 ast

Python 引擎是所有引擎中**唯一不依赖第三方解析器**的模块。选型依据：

| 因素 | Python `ast` | 第三方方案 |
|------|-------------|-----------|
| 语法覆盖率 | 完整覆盖 Python 3.6-3.13 所有语法 | 无需额外维护 |
| 依赖管理 | 零外部依赖 | ljavalang/lesprima 均需独立版本维护 |
| 行号精度 | 逐节点 `lineno` + `end_lineno` | 一致 |
| AST 稳定性 | CPython 官方维护，向后兼容 | 需跟随上游更新 |

**权衡**: 对于 PHP/JS/Java 等语言，标准库不提供 AST 解析能力（或能力不足），必须依赖第三方。Python 的 `ast` 模块是 CPython 官方实现，可靠性极高。

### 1.2 递归深度限制

```python
import sys
sys.setrecursionlimit(3000)  # Line 13
```

由于核心追踪逻辑（`parameters_back` → `_trace_in_function` → `_trace_in_stmts` → `_trace_stmt` → `_trace_expr` → `parameters_back`）形成**深度递归链路**，默认的 1000 递归深度不够用。设置 3000 是对深度嵌套代码（如多层装饰器、深层嵌套的 if/for）的保护。

### 1.3 全局状态设计

Python 引擎采用与 PHP/Java 引擎一致的**模块级全局变量**模式：

```python
# Line 27-31
scan_results = []          # 当前扫描的最终结果列表
is_repair_functions = []   # 当前规则配置的修复函数列表
is_controlled_params = []  # 当前规则配置的可控参数列表
scan_chain = []            # 调用链记录

# Line 55-58
_trace_visited = set()     # 模块级追踪去重集合
_trace_cache = TraceCache("python")  # 双层缓存（运行时 + 内置知识库延迟加载）
```

**设计意图**: 每次调用 `scan_parser()` 时重置所有全局状态，确保不同规则/不同文件的扫描结果互不污染。

---

## 2. 核心回溯函数链路

### 2.1 返回码体系

Python 引擎定义了比其他引擎更丰富的返回码：

| Code | 含义 | 处理策略 |
|------|------|---------|
| `1` | **可控** — 污点到达用户输入源 | 漏洞确认，立即返回 |
| `2` | **已修复** — 经过修复函数处理 | 漏洞已修复，记录 |
| `3` | **未确认** — 无法判定 | 继续追踪其他路径 |
| `4` | **新漏洞函数** — 追踪到函数参数 | 进入 `_resolve_code4` 递归解析调用者 |
| `5` | **global 变量** | 退出当前函数，在模块级别继续追踪 |
| `-1` | **不可控** — 污点断裂 | 当前追踪路径终结 |
| `'deps'` | **依赖变量** — 返回值依赖调用者变量 | 上层继续向上追踪 |

**特别设计 — `'deps'` 机制**:

`'deps'` 是 Python 引擎独有的返回类型。当追踪函数调用时，函数的返回值可能依赖调用者作用域中的变量（如 `x = sanitize(user_input); os.system(x)`），此时 `_trace_function_return` 返回 `('deps', ['x'], lineno)`，由 `_trace_in_stmts` 继续向上追踪 `x` 的来源。这避免了在函数体内调用 `parameters_back` 时与调用者赋值行冲突导致的**循环追踪问题**。

### 2.2 入口函数: `scan_parser`

**位置**: Line 1542-1761

`scan_parser` 是 CAST 调用的主入口，完整流程如下：

```
scan_parser(sensitive_func, vul_lineno, file_path, ...)
  │
  ├─ 1. 重置全局状态 (_trace_visited, _trace_cache, _summaries_initialized)
  ├─ 2. 初始化函数摘要 (_init_function_summaries)
  ├─ 3. 解析 import 语句 (_parse_imports)
  ├─ 4. AST 中查找目标行的敏感函数调用节点 (ast.walk + ast.Call)
  ├─ 5. 赋值链迭代传播（scan_parser 特有的优化）
  ├─ 6. 逐参数分析
  │     ├─ 直接可控性检查 (is_controllable)
  │     ├─ 收集变量名 → parameters_back 反向追踪
  │     └─ 对 code=4 结果调用 _resolve_code4
  ├─ 7. 若未找到结果 → 跨文件追踪 (_try_cross_file_trace)
  └─ 8. 返回 scan_results
```

**关键优化 — 赋值链迭代传播** (Line 1615-1651):

```python
# 在函数内做变量传播：如果 x = tainted_var，则 x 也标记为可控
assign_map = {}  # {lhs: set_of_rhs_names}
for s in ast.walk(func_node):
    if isinstance(s, ast.Assign) and s.value:
        for t in s.targets:
            tname = _get_name(t)
            if tname:
                assign_map[tname] = _collect_names(s.value)

# 第一轮：用 parameters_back 标记 rhs 中可控的变量
# 后续迭代：传播（最多 5 轮，防止无限循环）
```

这是 `scan_parser` 在进入逐参数追踪之前做的**预处理**：提前标记所有通过赋值链间接可控的变量，扩展 `controlled_params` 列表。这使得后续 `parameters_back` 在遇到 `x` 时能直接判定为可控，避免了深度递归。

### 2.3 核心追踪: `parameters_back`

**位置**: Line 375-434

```python
def parameters_back(param_name, nodes, vul_lineno, file_path,
                     repair_functions=None, controlled_params=None,
                     visited_funcs=None, depth=0):
```

**函数签名特点**: `nodes` 参数在 Python 引擎中始终为空列表 `[]`（这是接口兼容保留，实际不使用）。这是 Python 引擎与其他引擎（PHP/JS）的差异点 — PHP/JS 引擎的 `nodes` 是从 pretreatment 获取的语法节点列表，Python 引擎直接从 `ast_object_singleton` 获取完整 AST 树。

**执行流程**:

```
parameters_back(param_name, ..., vul_lineno, file_path, depth)
  │
  ├─ 深度检查: depth > 5 → return (-1, None, 0)
  ├─ 缓存查询: _trace_cache.get(file_path, param_name, vul_lineno)
  ├─ 获取 AST 树: _ast_object_singleton.get_nodes(file_path)
  ├─ 收集目标行之前的顶层语句
  ├─ 查找包含目标行的函数: _find_function_at_line(tree, vul_lineno)
  │
  ├─ if func_node:
  │     └─ _trace_in_function(param_name, func_node, vul_lineno, ...)
  │
  ├─ else:
  │     └─ _trace_in_stmts(param_name, relevant_stmts, vul_lineno, ...)
  │
  └─ 缓存写入（仅确定性结果: code ∈ {-1, 1, 2}）
```

### 2.4 函数内追踪: `_trace_in_function` + `_trace_in_stmts`

**位置**: Line 606-685

```
_trace_in_function(param_name, func_node, vul_lineno, ...)
  │
  └─ _trace_in_stmts(param_name, func_node.body, ..., func_node=func_node)

_trace_in_stmts(param_name, stmts, vul_lineno, ..., func_node=None)
  │
  ├─ 过滤 vul_lineno 之前的语句
  ├─ 倒序遍历 prior_stmts（从 sink 行向上回溯）
  │     │
  │     └─ _trace_stmt(param_name, stmt, vul_lineno, ...)
  │           │
  │           ├─ 返回 None → 继续处理下一条语句
  │           ├─ 返回 'deps' → 对每个依赖变量继续向上追踪
  │           └─ 返回 (code, ...) → 直接返回
  │
  ├─ 未找到赋值 → 检查是否是函数参数 → return (4, func_node, vul_lineno)
  ├─ self.xxx 属性 → _trace_self_attribute
  ├─ global 声明 → return (5, None, vul_lineno)
  └─ 全部未匹配 → return (-1, None, 0)
```

**`'deps'` 依赖追踪** (Line 640-656):

当 `_trace_stmt` 返回 `('deps', ['var1', 'var2'], lineno)` 时，表示当前赋值 `x = some_func(var1, var2)` 的右部是函数调用，而 `some_func` 的返回值依赖调用者变量 `var1` 和 `var2`。此时需要在更早的语句中找到这些变量的赋值来源：

```python
if result[0] == 'deps':
    dep_vars = result[1]
    for dep_var in dep_vars:
        for earlier_stmt in reversed(prior_stmts):
            if earlier_stmt.lineno < stmt.lineno:
                r = _trace_stmt(dep_var, earlier_stmt, ...)
                if r and r[0] != 'deps':
                    return r
    return 3, None, vul_lineno  # 所有依赖变量都不可控
```

### 2.5 语句级分发: `_trace_stmt`

**位置**: Line 788-996

`_trace_stmt` 是 Python 引擎中最复杂的分发函数之一，处理 Python 语言的全部语句类型：

| 语句类型 | AST 节点 | 处理逻辑 |
|---------|---------|---------|
| `x = expr` | `ast.Assign` | 匹配目标名 → `_trace_expr` |
| `x += expr` | `ast.AugAssign` | 同上 |
| `x: int = expr` | `ast.AnnAssign` | 同上 |
| `with open() as f` | `ast.With` | 匹配 as 变量 → `_trace_expr`; 递归 with 体 |
| `if/elif/else` | `ast.If` | **分支约束分析**（详见第3节） |
| `for x in iter` | `ast.For` | 匹配循环变量; 递归 for 体 |
| `match/case` | `ast.Match` | **结构匹配约束**（Python 3.10+） |
| `while cond` | `ast.While` | 条件约束检查; 递归 while 体 |
| `try/except` | `ast.Try` | 遍历 body/handlers/orelse/finalbody |
| `return expr` | `ast.Return` | **不阻断追踪** — return 不影响赋值来源 |

**`return` 语句的处理** (Line 992-994):

```python
# return 语句不阻断追踪：变量出现在 return 中只是说明它被使用了，
# 不影响在之前的赋值语句中找到它的来源
```

这是刻意的设计：`return x` 不代表 `x` 的来源就是当前位置，应该继续向上查找 `x` 的赋值。

### 2.6 表达式级追踪: `_trace_expr`

**位置**: Line 999-1153

`_trace_expr` 处理表达式的数据流来源判定，按优先级执行以下检查：

```
_trace_expr(param_name, expr, lineno, ...)
  │
  ├─ 1. is_controllable(expr_str) → return (1, ...)
  ├─ 2. is_repair(expr_str) → return (2, ...)
  │
  ├─ 3. ast.Call — 函数调用
  │     ├─ 检查参数中是否有可控变量
  │     ├─ 递归追踪每个参数: parameters_back(arg_name, ...)
  │     ├─ .format() 特殊处理: "str".format(x) → 追踪 x
  │     ├─ 检查是否是修复函数调用
  │     ├─ 查找函数定义 → _trace_function_return
  │     └─ 查 builtin_knowledge / function_summary
  │
  ├─ 4. ast.BinOp — 二元运算 (x + y, x * y)
  │     ├─ 收集两边变量名 → parameters_back 逐个追踪
  │     └─ fallback: 递归 _trace_expr(left/right)
  │
  ├─ 5. ast.JoinedStr — f-string
  │     └─ 遍历 FormattedValue → _trace_expr
  │
  ├─ 6. ast.Subscript — 下标访问 (x[0], x[key])
  │     └─ _trace_expr(x) → 追踪基础对象
  │
  ├─ 6.5. ast.IfExp — 三元表达式 (x if cond else y)
  │     └─ **三元约束分析**（详见第3节）
  │
  ├─ 7. 收集所有变量名 → parameters_back 逐个追踪
  │     ├─ code=1/2 → 立即返回
  │     └─ code=4 → 收集候选，排序后尝试 _resolve_code4
  │
  └─ 全部失败 → return (3, None, 0)
```

**code=4 候选排序策略** (Line 1135-1151):

```python
code4_candidates.sort(key=lambda r: 1 if hasattr(r[1], 'name') and r[1].name == '__init__' else 0)
```

**设计意图**: `__init__` 的优先级最低，因为构造函数调用需要类名匹配，解析成功率低于普通函数调用。普通函数（有明确的调用者匹配）优先解析。

---

## 3. 分支约束分析

Python 引擎实现了 Kunlun-M 中最完整的分支约束提取系统，支持 6 种分支语法结构。

### 3.1 if/elif/else — `_find_sink_branch_py` + `_trace_stmt`

**位置**: Line 687-705, 836-877

**判断逻辑**:

```
_find_sink_branch_py(if_stmt, vul_lineno)
  │
  ├─ vul_lineno 在 if.body 范围内 → return 'if'
  ├─ orelse 是 [If] 节点（elif）→ 递归调用
  ├─ vul_lineno 在 orelse 范围内 → return 'else'
  └─ 都不在 → return 'outside'
```

**约束提取策略** (在 `_trace_stmt` 中，Line 836-877):

```python
if sink_branch == 'if':
    constraints = extract_constraints_from_py_expr(stmt.test)       # if 体：直接使用条件
    body_stmts = stmt.body
elif sink_branch == 'else':
    constraints = [c.negate() for c in extract_constraints_from_py_expr(stmt.test)]  # else 体：取反
    body_stmts = stmt.orelse
```

**阻断检查**:

```python
for c in constraints:
    if c.var_name == param_name and c.op in ('==', '===', 'in'):
        return -1, None, 0  # 等值/成员约束阻断 → 不可控
```

**关键设计**: `!=` 约束不阻断（`x != "admin"` 不排除 `x` 是其他可控值）。

### 3.2 条件表达式解析 — `extract_constraints_from_py_expr`

**位置**: Line 708-778

该函数将 Python 条件表达式转换为 `BranchConstraint` 列表：

| Python 语法 | AST 节点 | 提取结果 |
|------------|---------|---------|
| `x == value` | `ast.Compare(ast.Eq)` | `BranchConstraint(var=x, op='==', value=value)` |
| `x != value` | `ast.Compare(ast.NotEq)` | `BranchConstraint(var=x, op='!=', value=value)` |
| `x is None` | `ast.Compare(ast.Is)` | `BranchConstraint(var=x, op='==', value=None)` |
| `x is not None` | `ast.Compare(ast.IsNot)` | `BranchConstraint(var=x, op='!=', value=None)` |
| `x and y` | `ast.BoolOp(ast.And)` | 递归提取两个子约束（AND 关系） |
| `x == "a" or x == "b"` | `ast.BoolOp(ast.Or)` | 等价转换为 `BranchConstraint(var=x, op='in', value=['a','b'])` |
| `not (x == 1)` | `ast.UnaryOp(ast.Not)` | `negate()` 取反 |

**OR 优化** (Line 732-747):

```python
# x == "a" or x == "b" 等价于 x in ["a", "b"]
eq_values = defaultdict(list)
for c in or_constraints:
    if c.op == '==' and c.var_name:
        eq_values[c.var_name].append(c.value)
for var_name, values in eq_values.items():
    constraints.append(BranchConstraint(var_name=var_name, op='in', value=values))
```

这个优化将 `or` 分离的等值判断合并为 `in` 约束，避免了"忽略 OR"的精度损失。

### 3.3 match/case — 结构匹配约束

**位置**: Line 895-946 (在 `_trace_stmt` 中)

Python 3.10 引入的 `match/case` 语句被完整支持：

```python
if hasattr(ast, 'Match') and isinstance(stmt, ast.Match):
    # 找到 sink 所在的 case
    target_case = ...
    pattern = target_case.pattern

    # MatchValue(value=Constant(value=...)) — 固定值匹配 → 阻断
    if isinstance(pattern, ast.MatchValue):
        if isinstance(pattern.value, ast.Constant) and subject_name == param_name:
            return -1, None, 0  # BLOCKS

    # MatchSingleton(value=True/False/None) — 类似 MatchValue
    elif isinstance(pattern, ast.MatchSingleton):
        return -1, None, 0  # BLOCKS

    # MatchAs(pattern=None) — 通配符 _ → 不阻断
    elif isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        pass  # 不阻断
```

### 3.4 while 循环约束

**位置**: Line 949-968

```python
if sink_in_body:
    constraints = extract_constraints_from_py_expr(stmt.test)
    for c in constraints:
        if c.var_name == param_name and c.op in ('==', '===', 'in'):
            return -1, None, 0  # while True → 循环体内的 sink 不可达（无限循环）
```

**语义**: `while x == "fixed"` 内的 sink 不可达 — 因为条件为真时会无限循环，不会执行后续代码。这实际上处理了"条件恒真导致死循环"的场景。

### 3.5 三元表达式约束

**位置**: Line 1102-1118

```python
if isinstance(expr, ast.IfExp):
    true_names = set()
    false_names = set()
    _collect_names(expr.body, true_names, 0)
    _collect_names(expr.orelse, false_names, 0)
    constraints = extract_constraints_from_py_expr(expr.test)
    for c in constraints:
        if c.op in ('==', '===', 'in'):
            if c.var_name in true_names and c.var_name not in false_names:
                # 约束变量只在 true 分支 → true 路径中 var == fixed → 阻断
                return -1, None, 0
            elif c.var_name in false_names and c.var_name not in true_names:
                # 约束变量只在 false 分支 → false 路径中 var != fixed → 不阻断
                return _trace_expr(param_name, expr.orelse, ...)
```

---

## 4. 跨文件追踪

### 4.1 import 解析 — `_parse_imports`

**位置**: Line 60-88

```python
def _parse_imports(tree, file_path):
    """返回 {imported_name: module_file_path} 映射

    支持:
      from helpers import run_command  →  {'run_command': '/path/helpers.py'}
      import helpers                   →  {'helpers': '/path/helpers.py'}
      from pkg.helpers import func     →  {'func': '/path/pkg/helpers.py'}
    """
```

**路径解析策略** (`_resolve_module_path`, Line 91-102):

1. 先尝试文件形式: `base_dir/part1/part2/module.py`
2. 再尝试包形式: `base_dir/part1/part2/__init__.py`

### 4.2 跨文件间接 sink 检测 — `_try_cross_file_trace`

**位置**: Line 1764-1894

这是 Python 引擎的跨文件追踪主逻辑：

```
_try_cross_file_trace(tree, target_line, sensitive_func, file_path, ...)
  │
  ├─ 1. 找到目标行的所有 Call 节点
  ├─ 2. 对每个调用:
  │     ├─ 提取函数名（去掉对象前缀）
  │     ├─ 匹配 import_map:
  │     │     ├─ 直接匹配: func_name in import_map
  │     │     ├─ 对象类型匹配: ex.run() → 解析 ex 的类型 → 类型名 in import_map
  │     │     └─ 完整名匹配: call_name in import_map
  │     │
  │     ├─ 加载被 import 文件的 AST
  │     ├─ 在被 import 文件中找到函数定义
  │     ├─ 检查函数内部是否调用了 BUILTIN_SENSITIVE_SINKS 中的函数
  │     │     ├─ 是 → 检查实参可控性 → return code=1
  │     │     └─ 否 → 继续下一个
  │     │
  │     └─ 类方法: _trace_cross_file_self_attribute
  │
  └─ return None（未找到跨文件 sink）
```

### 4.3 跨文件 self.xxx 追踪 — `_trace_cross_file_self_attribute`

**位置**: Line 1897-2013

这是 Python 引擎中最复杂的跨文件分析，追踪完整链路：

```
ex = Executor(user_input)          ← caller_tree 中
     ↓ __init__(self, base)        ← imported_tree 中
     ↓ self.base = base
ex.run('ls')                       ← call_node
     ↓ os.popen(self.base + arg)   ← method_def 中
     ↑ self.base 可控因为 __init__ 参数 base 来自 user_input
```

**执行步骤**:

1. 找到方法所属的 ClassDef
2. 收集方法体内使用的 `self.xxx` 属性名
3. 在 `__init__` 中建立 `self.attr → __init__参数名` 映射
4. 在 caller_tree 中找到 `ClassName(...)` 构造调用
5. 检查构造参数是否可控（`is_controllable` 或 `parameters_back`）

### 4.4 内置敏感 Sink 列表

**位置**: Line 38-48

```python
BUILTIN_SENSITIVE_SINKS = [
    'os.system', 'os.popen', 'os.spawnl', ...,
    'subprocess.call', 'subprocess.run', 'subprocess.Popen', ...,
    'eval', 'exec', 'compile',
    'pickle.loads', 'pickle.load', 'yaml.load', ...,
    'requests.get', 'requests.post', ...,
    'urllib.request.urlopen', ...,
    'open', 'file',
    'socket.connect', 'socket.send',
]
```

这是**硬编码**的 Python 危险函数列表，用于跨文件追踪时判断被 import 函数内部是否包含间接 sink。这些函数不在规则配置中（因为规则只匹配目标文件中的调用），但它们是已知的危险 sink，需要被识别。

---

## 5. 函数摘要系统

### 5.1 摘要生成器 — `summary_generator.py`

Python 引擎是第一个实现**语言特有**函数摘要生成器的模块。架构：

```
summary_generator.py
  ├─ generate_summaries_for_target(target_path, files_dict)
  │     ├─ 第一遍: generate_file_summaries → 注册到 _summary_registry
  │     └─ 第二遍: 对有自定义方法调用的函数做二次分析
  │
  ├─ _analyze_function(func_node, file_content)
  │     ├─ 收集参数列表（跳过 self/cls）
  │     ├─ 收集函数体内赋值: _find_assignments
  │     ├─ 遍历所有 Return 节点
  │     └─ 对每个 return 值: _trace_dataflow → ReturnFlowItem
  │
  ├─ _trace_dataflow(expr_node, param_names, func_body, assignments)
  │     ├─ 检查是否是字面量 → origin_type='literal'
  │     ├─ 检查是否直接引用参数 → origin_type='param'
  │     ├─ 检查是否是函数调用 → origin_type='call'（递归展开）
  │     └─ 检查是否引用全局变量 → origin_type='global'
  │
  └─ lookup_summary(func_name) → FunctionSummary or None
```

**两遍处理的设计意图** (Line 443-465):

第一遍生成所有函数的初始摘要（只分析直接数据流），注册到全局注册表后，第二遍重新生成摘要——此时 `_trace_dataflow` 可以查到其他函数的摘要，从而展开间接数据流（如函数 A 调用函数 B 的返回值）。

### 5.2 摘要应用 — `_judge_from_summary_py`

**位置**: Line 1165-1209

```python
def _judge_from_summary_py(summary, call_node, controlled_params):
    for rf in summary.return_flow:
        if rf.origin_type == "param":
            # 返回值来自参数 → 检查对应实参是否可控
            for param_idx in rf.dep_params:
                if is_controllable(call_args[param_idx], controlled_params):
                    return (1, ...)
        elif rf.origin_type == "call":
            # 返回值来自内部函数调用 → 检查是否是已知内置函数
            knowledge = lookup_builtin(rf.origin)
            if knowledge and knowledge.get("passthrough"):
                # 内置函数透传 → 检查对应的 dep_params
                ...
        elif rf.origin_type == "global":
            if is_controllable(rf.origin, controlled_params):
                return (1, ...)
```

---

## 6. OOP 支持：类与 self 属性追踪

### 6.1 self.xxx 属性追踪 — `_trace_self_attribute`

**位置**: Line 470-570

Python 引擎的 OOP 支持远超其他引擎，因为 Python 的 `self.xxx` 是最常见的属性访问模式：

```
_trace_self_attribute(attr_name='self.base', class_node, ...)
  │
  ├─ 1. 在类中查找 __init__ 方法
  │     ├─ 找到 → 在 __init__ 体内查找 self.base = expr
  │     │     ├─ 追踪 expr → _trace_expr
  │     │     └─ expr 是 __init__ 参数 → return (4, init_method, vul_lineno)
  │     └─ 未找到 → 检查父类的 __init__
  │
  ├─ 2. 检查类级别属性 (class-level assignment)
  │
  └─ 3. 检查 @property getter
        └─ 支持 @property 装饰器 → _trace_property_getter
```

**继承支持**:

```python
# 当前类没有 __init__，检查父类
for base in class_node.bases:
    base_name = _get_name(base)
    if base_name:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == base_name:
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == '__init__':
                        init_method = item
```

### 6.2 @property 追踪 — `_trace_property_getter`

**位置**: Line 573-603

```python
def _trace_property_getter(prop_func, vul_lineno, ...):
    for node in ast.walk(prop_func):
        if isinstance(node, ast.Return) and node.value:
            # 追踪 getter 的返回值
            result = _trace_expr('return_value', node.value, ...)
            if result and result[0] in (1, 2, 4):
                return result
            # fallback: 收集 names → parameters_back
```

### 6.3 code=4 解析 — `_resolve_code4`

**位置**: Line 1355-1510

`_resolve_code4` 处理"追踪到函数参数"的递归解析，支持多种函数类型：

```python
def _resolve_code4(func_def, tree, file_path, sensitive_func, ...)
    │
    ├─ 深度限制: depth > 3 → return None
    │
    ├─ 确定匹配的调用名:
    │     ├─ __init__ → 匹配 ClassName(...) 构造调用
    │     │     └─ 也匹配所有继承该类的子类
    │     ├─ __call__ → 匹配 instance(...) 实例调用
    │     └─ 普通方法 → 匹配 obj.method(...) / func(...)
    │
    ├─ 遍历所有候选调用点
    │     ├─ 检查函数体内是否有 sink (_func_has_sink)
    │     ├─ 建立实参 → 形参映射
    │     ├─ 检查对应实参是否可控
    │     └─ 不可控 → 递归 _resolve_code4
    │
    └─ return {'code': 1, 'chain': [...], 'source': ...}
```

---

## 7. 内置知识库 — `builtin_knowledge.py`

### 7.1 知识库结构

```python
KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {
    "str.upper":   {"passthrough": [0], "safe": False},
    "int":         {"passthrough": [],  "safe": True},
    "len":         {"passthrough": [],  "safe": True},
    ...
}
```

### 7.2 分类覆盖

| 类别 | 示例 | passthrough | safe | 说明 |
|------|------|------------|------|------|
| 字符串方法 | `str.upper`, `str.replace` | `[0]` | False | 透传 self |
| 类型转换 | `str`, `bytes`, `list` | `[0]` | False | 透传参数 |
| 数值转换 | `int`, `float`, `bool` | `[]` | True | 返回值安全 |
| 不透传 | `len`, `type`, `id` | `[]` | True | 与输入无关 |
| 特殊方法 | `str.join` | `[1]` | False | 透传第2参数 |
| 高阶函数 | `map`, `filter` | `[1]` | False | 透传函数参数 |

### 7.3 应用场景

在 `_trace_function_return` 中，**知识库优先级高于函数体分析**（Line 1229-1256）：

```python
if call_func_name:
    knowledge = lookup_builtin(call_func_name)
    if knowledge:
        if knowledge["safe"] and not knowledge["passthrough"]:
            return -1, None, 0  # 安全函数，不透传
        if knowledge["passthrough"]:
            # 返回依赖的参数变量名列表
            return ('deps', list(deps), ...)
```

**设计意图**: 对于 Python 标准库函数，不需要分析其函数体（大部分也分析不了——它们是 C 实现的），直接用预定义的知识条目判定。

---

## 8. 可控性判定 — `is_controllable`

**位置**: Line 337-354

```python
def is_controllable(expr_str, controlled_params=None):
    for cp in controlled_params:
        if cp in expr_str:
            return True
        # 特殊处理：可控源是 func() 形式
        if cp.endswith('()'):
            func_name = cp[:-2]
            if expr_str.startswith(func_name + '('):
                return True
    return False
```

**与其他引擎的差异**:

| 引擎 | 可控源定义 |
|------|-----------|
| PHP | 硬编码超全局变量 (`$_GET`, `$_POST`, ...) |
| JavaScript | 由规则配置传入 |
| **Python** | 由规则配置传入 + `func()` 形式匹配 |

Python 没有像 PHP 那样的超全局变量概念，可控源完全由规则配置决定。`func()` 形式支持是 Python 特有的——用于匹配 `request.get_data()` 这类框架提供的输入获取函数。

---

## 9. 完整追踪流程示例

以下展示从 sink 到最终判定的完整链路：

### 示例 1: 直接可控

```python
# app.py
@app.route('/cmd')
def run_cmd():
    cmd = request.args.get('cmd')  # Line 5
    os.system(cmd)                  # Line 6 — sink
```

```
scan_parser(sensitive_func=["os.system"], vul_lineno=6, ...)
  │
  ├─ 找到 os.system() 调用 at line 6
  ├─ 赋值链传播: cmd = request.args.get('cmd') → cmd 标记为可控
  ├─ is_controllable("cmd", extended_controlled) → True
  └─ return [{"code": 1, "source": "cmd"}]
```

### 示例 2: 跨函数追踪 + code=4 解析

```python
def build_cmd(user_input):
    return "ls " + user_input    # Line 2

os.system(build_cmd(req.args.get('x')))  # Line 5 — sink
```

```
scan_parser(..., vul_lineno=5)
  │
  ├─ 找到 os.system() at line 5
  ├─ arg = build_cmd(req.args.get('x'))
  ├─ arg_names = [] (无直接变量名)
  ├─ _trace_expr → ast.Call(build_cmd)
  │     ├─ _find_function_def(build_cmd) → 找到函数定义
  │     ├─ _trace_function_return(build_cmd, call_node, ...)
  │     │     ├─ 建立参数映射: user_input ← req.args.get('x')
  │     │     ├─ controllable_param_names = {'user_input'} (is_controllable)
  │     │     ├─ return "ls " + user_input → return_names = {'user_input'}
  │     │     ├─ matched = {'user_input'} & {'user_input'} → True
  │     │     └─ return ('deps', ['req', 'args', 'get', 'x'], ...)
  │     └─ 返回 deps
  │
  ├─ _trace_in_stmts 处理 deps: 追踪 'req' → 在更早语句中未找到
  └─ 但 scan_parser 的赋值链传播在预处理阶段已处理
      (注: 这里实际上 parameters_back 会直接处理)
```

### 示例 3: 分支约束阻断

```python
def check():
    mode = get_mode()
    if mode == "safe":
        os.system("echo safe")    # Line 4 — sink
    else:
        os.system("echo danger")  # Line 6
```

```
scan_parser(..., vul_lineno=4)
  │
  ├─ 找到 os.system() at line 4
  ├─ arg = "echo safe" → 字面量，追踪无变量
  └─ code=-1 (字面量不可控)

# 另一个 sink at line 6:
scan_parser(..., vul_lineno=6)
  │
  ├─ 找到 os.system() at line 6
  ├─ arg = "echo danger" → 字面量，追踪无变量
  └─ code=-1
```

### 示例 4: 跨文件 self.xxx 追踪

```python
# main.py
from executor import Executor

ex = Executor(request.args.get('cmd'))  # Line 3
ex.run('ls')                             # Line 4 — sink
```

```python
# executor.py
class Executor:
    def __init__(self, base):
        self.base = base           # self.base ← base ← 构造参数

    def run(self, arg):
        os.popen(self.base + arg)  # indirect sink
```

```
scan_parser(main.py, ..., vul_lineno=4)
  │
  ├─ 找到 ex.run('ls') at line 4
  ├─ 直接参数 'ls' 不可控
  ├─ _try_cross_file_trace:
  │     ├─ call_name = 'ex.run', func_name = 'run'
  │     ├─ import_map: {'Executor': '/path/executor.py'}
  │     ├─ _resolve_variable_type: ex → Executor
  │     ├─ 加载 executor.py AST
  │     ├─ 在 Executor.run 中找到 os.popen → BUILTIN_SENSITIVE_SINKS
  │     ├─ 实参 'ls' 不可控
  │     ├─ is_class_method=True → _trace_cross_file_self_attribute:
  │     │     ├─ used_self_attrs = {'self.base'}
  │     │     ├─ __init__ 映射: self.base → base
  │     │     ├─ caller_tree 中找到 Executor(request.args.get('cmd'))
  │     │     ├─ 构造参数: request.args.get('cmd')
  │     │     ├─ is_controllable("request.args.get('cmd')") → True
  │     │     └─ return [{"code": 1, "source": "request.args.get('cmd')"}]
  │     └─ return code=1
  └─ 漏洞确认
```

---

## 10. 防护机制

### 10.1 递归深度保护

| 层级 | 限制 | 位置 |
|------|------|------|
| `parameters_back` | `depth > 5` | Line 396 |
| `_trace_dataflow` (摘要) | `depth > 10` | summary_generator.py Line 92 |
| `_resolve_code4` | `depth > 3` | Line 1366 |
| Python 解释器 | `sys.setrecursionlimit(3000)` | Line 13 |

### 10.2 缓存策略

```python
# 只缓存确定性结果（跳过中间状态）
if code in (-1, 1, 2):
    _trace_cache.put(file_path, param_name, int(vul_lineno), result)
```

`code=3`（未确认）、`code=4`（新漏洞函数）、`code=5`（global）不缓存，因为它们的判定依赖于调用上下文。

### 10.3 追踪去重

```python
_trace_visited = set()  # 模块级
```

每次 `scan_parser` 调用时清空。注意这个集合是粗粒度的——实际上 Python 引擎的循环保护主要靠 `depth` 参数和 `visited_funcs`，`_trace_visited` 在当前代码中未被 actively 使用（可能为将来扩展预留）。

---

## 11. 与其他引擎的设计对比

| 特性 | Python | PHP | JavaScript | Java |
|------|--------|-----|-----------|------|
| 解析器 | 标准库 ast | lphply | lesprima | ljavalang |
| 返回码数量 | 6 + deps | 5 | 5 | 5 |
| OOP 支持 | self.xxx + @property + 继承 | $this->xxx | this.xxx + 原型链 | 对象污点传播 |
| 跨文件追踪 | import + self.xxx | include/require | require/import | import |
| 分支约束 | if/elif/else + match + while + 三元 + for | if/elseif/else + 三元 + switch | if/else + switch + 三元 | if/else + switch |
| 函数摘要 | 语言特有 (summary_generator.py) | 共享 (function_summary.py) | 共享 | 共享 |
| code=4 解析 | _resolve_code4 | scan_parser 内联 | scan_parser 内联 | _propagate_object_taint |
| 赋值链传播 | scan_parser 预处理 + 迭代 | 无独立预处理 | 无独立预处理 | 无独立预处理 |

---

## 12. 已知限制

1. **闭包支持不足**: Python 的闭包（`nonlocal`）当前未被显式处理。嵌套函数中引用外层函数的变量时，追踪可能失败。

2. **装饰器未解析**: `@decorator` 装饰器会改变函数的行为，但当前引擎不解析装饰器的影响。`@property` 是唯一的例外。

3. **动态特性**: `setattr`, `__getattr__` 等动态属性访问无法追踪。`getattr(obj, 'method')` 作为间接调用模式已通过 AliasBuilder 支持（alias_type=`via_getattr`）。

4. **async/await**: 虽然 `AsyncFunctionDef` 在 AST 遍历时被包含，但 `async` 执行流（如 `await` 的数据流）未被特殊处理。

5. **跨文件单层**: `_try_cross_file_trace` 只做一层跨文件追踪（import 的函数 → 该函数内的 sink）。更深层的跨文件调用链无法追踪。

6. **import_map 路径解析**: 仅支持文件系统和包形式的相对路径解析，不支持 `sys.path` 修改、`pip install` 的第三方包。
