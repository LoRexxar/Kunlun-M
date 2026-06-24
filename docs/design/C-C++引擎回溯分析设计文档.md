# C/C++ 引擎回溯分析设计文档

## 一、引擎概览

### 1.1 技术选型

C/C++ 引擎是 Kunlun-M 中**第二个使用 tree-sitter** 的语言引擎（第一个是 Go），使用 `tree-sitter-c` 解析 C/C++ 源码 AST。与 Go 引擎不同的是，C/C++ 引擎**没有独立的 _ast_trace.py 模块**，所有 AST 追踪逻辑都在 `parser.py` 中实现，同时保留了文本回退（text fallback）路径。

**核心依赖：**
- `tree-sitter` + `tree-sitter-c`：C/C++ 源码 AST 解析
- 注意：`tree-sitter-c` 同时覆盖 C 和 C++（tree-sitter 官方 grammar 包含 C++ 扩展）

**文件结构：**

```
core/core_engine/c/
├── __init__.py              # 包初始化（空）
├── engine.py                # 引擎注册（37B）
├── parser.py                # 核心回溯分析引擎（2892行，111KB）
├── builtin_knowledge.py     # C/C++ 内置知识库（278行，13KB）
└── summary_generator.py     # 函数摘要生成器（751行，27KB）
```

### 1.2 可控源定义

C/C++ 的可控源围绕系统输入和标准 I/O 函数：

```python
C_CONTROLLED_SOURCES = [
    # 命令行参数
    "argv", "argc",
    # 环境变量
    "getenv", "secure_getenv",
    # 格式化输入
    "scanf", "fscanf", "sscanf",
    # 行输入
    "fgets", "gets", "getline", "getdelim",
    # 网络输入
    "read", "fread", "recv", "recvfrom", "recvmsg",
    # 标准流
    "stdin", "STDIN_FILENO", "FILE stdin", "std::cin", "cin",
]
```

**C 语言输入模型特点：**
- C 没有框架层面的可控源，所有输入来自系统调用（getenv/scanf/fgets/read）
- `argv` 直接作为可控源（含下标访问如 `argv[1]`）
- `scanf` 家族特殊处理：`SCANF_FAMILY = {"scanf", "fscanf", "sscanf"}`，格式串后的参数都是输出参数

### 1.3 Sink 定义

C/C++ 引擎的 sink 定义在规则文件中（非引擎内置），涵盖：
- **命令执行**：`system`, `execvp`, `execl`, `popen`
- **内存操作**：`strcpy`, `strcat`, `memcpy`（缓冲区溢出 sink）
- **SQL 操作**：通过数据库 C API（MySQL/PostgreSQL/SQLite）
- **格式化字符串**：`printf`, `fprintf`, `sprintf`（含 `%s` 的格式串注入）

### 1.4 无条件危险函数

```python
# scan_parser 中特殊处理
if matched_func in ("gets",):
    # gets() 无条件危险 — 无边界检查的行输入，不需要分析参数
    results.append({"code": 1, "param": "unbounded_input", ...})
```

---

## 二、AST 解析与缓存层

### 2.1 tree-sitter C AST 解析

```python
try:
    import tree_sitter_c as _tsc
    from tree_sitter import Language as _TS_Language, Parser as _TS_Parser
    _C_TS_LANGUAGE = _TS_Language(_tsc.language())
    _ts_parser = _TS_Parser(_C_TS_LANGUAGE)
    _HAS_TREE_SITTER = True
except Exception as e:
    _ts_parser = None
    _HAS_TREE_SITTER = False
```

**与 Go 引擎的差异：**
| 特性 | C/C++ | Go |
|------|-------|-----|
| Parser 初始化 | 模块级单例 `_ts_parser` | 每次解析创建新 Parser |
| Language 初始化 | 模块级 `_C_TS_LANGUAGE` | 每次解析 |
| 错误处理 | `_HAS_TREE_SITTER` 标志 | 异常捕获 |

### 2.2 缓存体系

```python
_ast_cache = {}              # AST 解析缓存: file_path → tree
_func_def_index = {}          # 函数定义索引: (file_path, func_name) → (param_names, body_node, def_lineno, end_lineno)
_func_def_indexed_files = set()  # 已索引文件集合
_trace_cache = TraceCache("c")  # 追踪结果缓存（共享模块）
```

**关键设计：**
- `_ast_cache` 与 Go 引擎相同的文件级 AST 缓存
- `_func_def_index` 存储的是完整的 AST 节点引用（body_node），不是行号列表，与 Go 引擎不同
- `_func_def_indexed_files` 用于避免重复索引同一文件
- `_trace_cache` 使用共享模块 `TraceCache`，按语言标识符 `"c"` 隔离

### 2.3 全局状态

```python
scan_results = []             # 当前扫描结果
is_repair_functions = []      # 当前修复函数列表
is_controlled_params = []     # 当前可控参数列表
scan_chain = []               # 调用链
_scan_function_stack = []     # 跨函数递归防护栈
_summaries_initialized = False # 摘要初始化标志
_file_summaries = {}          # 文件摘要缓存
```

---

## 三、tree-sitter C 关键 AST 节点类型

### 3.1 C/C++ 声明系统

C 语言的声明系统比 Go 复杂得多，tree-sitter-c 反映了这种复杂性：

| 节点类型 | C 代码示例 | 说明 |
|---------|-----------|------|
| `function_definition` | `int foo(int x) { ... }` | 函数定义 |
| `declaration` | `int x = 5;` | 变量声明 |
| `init_declarator` | `x = 5` | 带初始化的声明符 |
| `declarator` | `x` | 声明符（可能是 identifier） |
| `pointer_declarator` | `*x` | 指针声明符 |
| `parenthesized_declarator` | `(x)` | 括号声明符 |
| `function_declarator` | `foo(params)` | 函数声明符 |
| `parameter_declaration` | `int x` | 参数声明 |
| `parameter_list` | `(int x, char *y)` | 参数列表 |
| `array_declarator` | `x[10]` | 数组声明符 |

**C 声明的嵌套本质：**

```
function_definition
├── type: type_identifier("int")
├── declarator: function_declarator
│   ├── declarator: identifier("foo")
│   ├── parameters: parameter_list
│   │   └── parameter_declaration
│   │       ├── type: primitive_type("int")
│   │       └── declarator: identifier("x")
│   └── type: primitive_type("int")   ← 返回类型
└── body: compound_statement
```

**函数指针的情况更复杂：**
```
function_definition
├── type: primitive_type("void")
├── declarator: pointer_declarator
│   ├── "*"
│   └── function_declarator
│       └── declarator: parenthesized_declarator
│           └── identifier("callback")
```

**函数指针间接调用（已支持单层）：**

对于函数指针声明 `int (*func)(const char *) = system;`，normalizer 的处理：
- 从 `function_declarator > parenthesized_declarator > pointer_declarator > identifier` 路径提取 LHS 变量名 `func`
- 创建 `assign` operator 节点，LHS 为 `func` identifier，RHS 为 `system` identifier
- DFG builder 自动生成 `forward_slice` 边，alias builder 沿 DFG 回溯创建 `alias` 边（alias_type=`via_function_pointer`）
- `_resolve_callee_name` 通过 alias 边将 `func(cmd)` 解析为 `system`

**限制：**
- 多层间接调用（全局声明 + 函数内调用，跨作用域 DFG 不支持）仍 skip
- 函数指针作为函数参数传递不支持

### 3.2 C 赋值系统

| 节点类型 | C 代码示例 | 说明 |
|---------|-----------|------|
| `assignment_expression` | `x = expr` | 赋值表达式 |
| `assignment_expression` (复合) | `x += expr` | tree-sitter 用 `+=` 等类型 |
| `expression_statement` | `x = expr;` | 表达式语句 |
| `declaration` > `init_declarator` | `int x = expr;` | 带初始化声明 |
| `compound_assignment` | `x += 1` | 复合赋值 |

### 3.3 C 控制流

| 节点类型 | C 代码 | 说明 |
|---------|--------|------|
| `if_statement` | `if (cond) { ... } else { ... }` | 条件语句 |
| `while_statement` | `while (cond) { ... }` | while 循环 |
| `do_statement` | `do { ... } while (cond);` | do-while 循环 |
| `for_statement` | `for (init; cond; update) { ... }` | for 循环 |
| `switch_statement` | `switch (expr) { case ...: }` | switch 语句 |
| `case_statement` | `case 1: ...` 或 `default: ...` | case 分支 |
| `conditional_expression` | `cond ? a : b` | 三元运算符 |

---

## 四、AST 辅助函数体系

### 4.1 函数查找

**`_find_enclosing_function(tree, lineno)`** — 查找包含指定行号的函数定义。

这是所有回溯分析的起点，返回 `(func_name, param_names, body_node, start_line, end_line)`。

**C 函数名提取的难点：**
C 语言的函数声明符可以嵌套多层（pointer_declarator → function_declarator → identifier），需要递归提取：

```python
def _extract_declarator_name_simple(decl_node) -> str:
    """从声明符节点中提取名称（递归处理嵌套声明符）。"""
    for child in decl_node.children:
        if child.type == "identifier":
            return _node_text(child)
        if child.type in ("pointer_declarator", "array_declarator",
                          "parenthesized_declarator", "init_declarator",
                          "parameter_declarator"):
            name = _extract_declarator_name_simple(child)
            if name:
                return name
    return ""
```

**`_find_function_def_in_ast(tree, func_name)`** — 在 AST 中按函数名查找定义。支持 C++ 命名空间短名匹配（`std::strcpy` → `strcpy`）。

**`_find_call_at_line(tree, lineno, func_name)`** — 在指定行号查找 sink 调用节点。支持短名匹配，且先递归搜索子节点（找内层调用）。

### 4.2 标识符收集

**`_collect_identifiers_from_ast(node)`** — 从 AST 节点递归收集所有变量标识符，排除 C 关键字。

**过滤的关键字集合（~40个）：**
```python
_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while",
    "bool", "true", "false", "restrict",  # C99
    "alignas", "alignof", "atomic", "generic", "noreturn", "static_assert", "thread_local",  # C11
    "NULL", "nullptr",
    "size_t", "ssize_t", "ptrdiff_t", "int8_t", ... # 常见类型名
    "FILE", "stdin", "stdout", "stderr", "errno",
})
```

**特殊处理：**
- `field_expression`（`a.b` / `ptr->field`）：收集基础变量 `a` / `ptr`
- `subscript_expression`（`arr[i]`）：收集数组名 `arr`
- `call_expression`：只递归收集参数中的标识符，不收集函数名

### 4.3 字面量判断

```python
_LITERAL_NODE_TYPES = frozenset({
    "number_literal", "string_literal", "char_literal",
    "true", "false", "null",
})

def _is_literal_node(node) -> bool:
    if node.type in _LITERAL_NODE_TYPES:
        return True
    if node.type == "identifier" and _node_text(node) in ("NULL", "nullptr", "true", "false"):
        return True
    # 带符号数字: -42, +3.14
    if node.type == "unary_expression" and node.children:
        op = _node_text(node.children[0])
        if op in ("-", "+") and len(node.children) >= 2:
            return _is_literal_node(node.children[-1])
    return False
```

### 4.4 赋值查找

**`_find_assignment_at_line(tree, lineno, var_name, to_line)`** — 在 AST 中查找 `<= lineno` 的变量赋值节点。

支持多种 C 赋值形式：
1. **声明初始化**：`declaration > init_declarator > identifier("x") = expr`
2. **表达式赋值**：`expression_statement > assignment_expression`
3. **复合赋值**：`x += expr`（类型为 `+=_assignment`）
4. **数组下标赋值**：`arr[i] = expr`（`subscript_expression` 作为 LHS）
5. **for 循环中的赋值**：`assignment_expression` 直接作为 for 子节点

**返回值**：`(lhs_name, rhs_node, assign_lineno)` 或 `None`

---

## 五、分支约束追踪

### 5.1 约束提取

**`_extract_constraints_from_c_expr(cond_node)`** — 从 C 条件表达式提取 `BranchConstraint` 列表。

支持的模式：
```
x == value              → BranchConstraint(x, '==', value)
x != value              → BranchConstraint(x, '!=', value)
strcmp(x, "str") == 0   → BranchConstraint(x, '==', "str")
strcmp(x, "str") != 0   → BranchConstraint(x, '!=', "str")
!strcmp(x, "str")         → BranchConstraint(x, '==', "str")  (取反)
x && y                   → 分别提取左右
x || y                   → 同一变量多值合并为 in 约束
```

**C/C++ 特有的 `strcmp` 约束提取：**

```python
def _extract_strcmp_constraint(call_node, literal_node, op_text):
    """检查 strcmp/strncmp/strcasecmp/strncasecmp/memcmp/bcmp(x, "str") == 0 模式。"""
    # strcmp 返回 0 表示相等
    if literal_val == 0:
        return BranchConstraint(var_name=var_name, op=op_text, value=value)
    if literal_val != 0:
        neg_op = '!=' if op_text == '==' else '=='
        return BranchConstraint(var_name=var_name, op=neg_op, value=value)
```

### 5.2 if/else 分支约束

```python
def _check_if_branch_constraint(if_node, vul_lineno, var_name):
    """tree-sitter C if_statement 结构:
      if_statement
        ├── "if"
        ├── parenthesized_expression   ← 条件
        ├── compound_statement         ← if body
        └── else_clause                ← 可选
             ├── "else"
             ├── compound_statement    ← else body
             └── if_statement          ← else if (递归处理)
    """
```

**约束阻断逻辑：**
- `in_if` 且约束 `op in ('==', 'in')` → **阻断**（等值约束使变量值固定）
- `in_else` 且约束 `op in ('!=', 'not in')` → **阻断**（不等约束的 else 分支隐含等值）
- `else if` → 递归调用 `_check_if_branch_constraint`

### 5.3 while 循环约束

```python
def _check_while_constraint(while_node, vul_lineno, var_name):
    """支持 while_statement 和 do_statement 两种形式。"""
```

- sink 在 while 体内，且条件中有 `var_name` 的等值约束 → **阻断**

### 5.4 switch/case 分支约束

```python
def _check_switch_branch_constraint(switch_node, vul_lineno, var_name):
    """tree-sitter C switch_statement 结构:
      switch_statement
        ├── "switch"
        ├── parenthesized_expression    ← switch 表达式
        └── compound_statement
             ├── case_statement         ← case 值
             └── case_statement         ← default
    """
```

- sink 在**非 default case** 中 → **阻断**（变量值被限定为 case 值）
- sink 在 **default case** 中 → **不阻断**
- sink 不在 switch 中 → **不阻断**（返回 None）

### 5.5 顶层分支约束检查

```python
def _check_sink_branch_constraints(tree, vul_lineno, var_name, func_body_node):
    """遍历函数体内的 if/switch/while，检查 sink 是否被分支约束阻断。"""
```

**调用时机：**
1. `_trace_variable_in_lines_impl` 中，当 RHS 分析返回 `code=1`（可控）时
2. `scan_parser` 中，当变量直接可控或追踪结果为可控时

---

## 六、三元运算符分支约束

### 6.1 conditional_expression 处理

C 的三元运算符 `cond ? a : b` 在 AST 中表现为 `conditional_expression` 节点，C/C++ 引擎对其有专门的约束追踪：

```python
def _analyze_rhs_node(rhs_node, var_name, ...):
    ...
    if node_type == "conditional_expression":
        condition = rhs_node.child_by_field_name("condition")
        consequence = rhs_node.child_by_field_name("consequence")
        alternative = rhs_node.child_by_field_name("alternative")

        # 提取三元条件约束
        constraints = _extract_constraints_from_c_expr(condition)

        # 收集 true/false 分支中的变量名
        true_names = set()
        false_names = set()
        _collect_var_names_recursive(consequence, true_names)
        _collect_var_names_recursive(alternative, false_names)

        # 约束变量在 true 分支 + op== → 阻断 true 分支
        for c in constraints:
            if c.op in ('==', 'in') and c_name in true_names and c_name not in false_names:
                return (-1, 0)  # 阻断
            if c.op == '!=' and c_name in false_names and c_name not in true_names:
                return (-1, 0)  # 阻断

        # 不受约束，继续追踪两个分支
        for part in (consequence, alternative):
            result = _analyze_rhs_node(part, ...)
            if result and result[0] in (1, 2):
                return result
```

**设计思路：**
- 三元运算符的两路分支各自收集变量名集合
- 如果条件约束的变量**只出现在其中一个分支**，说明该分支有等值约束
- 与 if/else 分支约束逻辑一致，但作用域更精细（表达式级别）

---

## 七、扫描入口：scan_parser

### 7.1 完整扫描流程

```
scan_parser(rule_match, vul_lineno, file_path)
│
├─ 1. 预建函数定义索引
│   ├─ _build_func_def_index(file_path)          # 当前文件 AST walk
│   └─ _build_func_def_index_cross_file()        # 遍历 pre_result 中所有 C/C++ 文件
│
├─ 2. 初始化函数摘要
│   └─ _init_function_summaries(file_path)
│       ├─ SummaryCacheManager.load_or_generate()
│       └─ generate_summaries_for_target()
│
├─ 3. 精确匹配规则函数名（与 Go 引擎相同逻辑）
│
├─ 4. tree-sitter 解析 AST + 节点提取
│   ├─ _parse_c_ast(file_path)
│   ├─ _find_call_at_line(ast_tree, vul_lineno, matched_func)
│   └─ _get_call_args_from_ast(call_node)
│
├─ 5. 无条件危险函数检查
│   └─ matched_func == "gets" → code=1 直接返回
│
├─ 6. 遍历 AST 参数节点
│   ├─ 6a. 字面量 → 跳过
│   ├─ 6b. call_expression 作为参数
│   │   └─ function_back_c → code=1 或 deps=controllable → 返回
│   ├─ 6c. 提取标识符列表
│   │   ├─ 直接可控 → 分支约束检查 → code=1
│   │   └─ 反向追踪 → _trace_variable_in_lines()
│   │       ├─ code=1 → 分支约束检查 → 返回
│   │       ├─ code=2 → 已修复
│   │       └─ code=3 → 未确认
│   └─ 6d. 所有参数都不可控 → code=-1
│
├─ 7. AST 未提取到参数 → 文本回退
│   ├─ _extract_args_from_line(line_text, matched_func)
│   └─ 正则匹配变量名 → 重复追踪逻辑
│
└─ 8. 配置型漏洞 / 不可控
    └─ is_config_vuln → code=4 / code=-1
```

### 7.2 分支约束在入口的检查

C/C++ 引擎在 `scan_parser` 中有两处分支约束检查：

```python
# 检查点 1: 变量直接可控时
if _is_controllable_source(var_name, controlled_params):
    func_info = _find_enclosing_function(ast_tree, vul_lineno)
    if func_info:
        _, _, body_node, _, _ = func_info
        if _check_sink_branch_constraints(ast_tree, vul_lineno, var_name, body_node):
            continue  # 被约束阻断，跳过此变量

# 检查点 2: 追踪结果为可控时
trace_code, src_lineno = _trace_variable_in_lines(...)
if trace_code == 1:
    if _check_sink_branch_constraints(ast_tree, vul_lineno, var_name, body_node):
        continue  # 被约束阻断
```

---

## 八、核心回溯分析：_trace_variable_in_lines

### 8.1 双层架构

与 Go 引擎相同，分为缓存包装层和实现层：

```python
# 缓存包装层 (1282行)
def _trace_variable_in_lines(file_path, var_name, from_line, to_line, ...):
    if depth == 0:
        cached = _trace_cache.get(file_path, var_name, int(to_line))
        if cached is not None: return cached
    code, source_lineno = _trace_variable_in_lines_impl(...)
    if depth == 0 and code in (1, 2, -1):
        _trace_cache.put(file_path, var_name, int(to_line), (code, [], source_lineno))
    return (code, source_lineno)
```

**与 Go 引擎的差异：**
- C 引擎使用 `TraceCache("c")` 共享模块实例化
- C 引擎额外传入 `visited` 参数用于环检测（Go 引擎用 `_scan_function_stack` 检测递归函数）

### 8.2 实现层流程

```
_trace_variable_in_lines_impl(file_path, var_name, to_line)
│
├─ 1. 深度检查 + 环检测
│   ├─ depth > max_depth → (-1, 0)
│   └─ (file_path, var_name, to_line) in visited → (-1, 0)  ← C 独有
│
├─ 2. AST 解析：_parse_c_ast(file_path)
│
├─ 3. 定位函数体：_find_enclosing_function(tree, to_line)
│
├─ 4. 直接可控源检查
│   ├─ var_name in C_CONTROLLED_SOURCES → (1, to_line)
│   └─ var_name == "argv" → (1, to_line)
│
├─ 5. 形参检查
│   └─ var_name in param_names → _trace_param_at_call_sites()
│       ├─ 当前文件搜索
│       └─ 跨文件暴力搜索 pre_result
│
├─ 6. 赋值查找 + RHS 分析
│   └─ _find_assignment_at_line(tree, to_line, var_name, to_line)
│       └─ _analyze_rhs_node(rhs_node, var_name, ...)
│           ├─ code=1/2 → 分支约束检查 → 返回
│           ├─ code=-1 且来自 safe 函数 → 不返回，继续后续检查
│           └─ code=-1 且非 safe 函数 → 返回
│
├─ 7. 后续写入检查（C 独有）
│   └─ _find_call_with_var_as_arg(tree, to_line, var_name, to_line - 1)
│       └─ snprintf(cmd, ...) 等通过参数修改变量的模式
│           ├─ passthrough/param_flow 检查
│           └─ 隐式数据源 ("stdin", "network") 直接可控
│
└─ 8. 文本回退
    └─ _text_trace_variable(file_path, var_name, to_line)
```

### 8.3 C 独有：后续写入检查

C/C++ 引擎有一个其他引擎没有的特殊检查——`_find_call_with_var_as_arg`：

```python
def _find_call_with_var_as_arg(tree, to_line, var_name, to_line_limit):
    """查找 <= to_line 的、以 var_name 作为参数的 call_expression。
    用于处理 snprintf(cmd, ...) 等通过参数修改变量的模式。
    """
```

**使用场景：**
```c
char cmd[256];
snprintf(cmd, sizeof(cmd), "ls %s", user_input);  // cmd 通过 snprintf 写入
system(cmd);  // sink — cmd 的来源是 snprintf 的输出
```

**检查逻辑：**
1. 找到 `snprintf(cmd, ...)` 调用，`cmd` 是参数 0
2. 查知识库：`snprintf` 的 `param_flow: {0: 1}` → 参数 0 的数据来自参数 1
3. 参数 1 = `"ls %s", user_input` → 检查是否包含可控源
4. 如果参数 1 包含可控变量 → `cmd` 可控

**param_flow 隐式数据源：**
```python
# scanf 的 param_flow: {1: "stdin", 2: "stdin", 3: "stdin"}
# 含义：参数 1/2/3 从 stdin 获取数据（隐式可控源）
if isinstance(source_info, str):
    # 隐式数据源（如 "stdin", "network"）— 直接标记为可控
    return (1, call_lineno)
```

### 8.4 赋值链续传（safe 函数后的后续写入）

```python
# 在 _trace_variable_in_lines_impl 中：
if code == -1:
    rhs_text = _node_text(rhs_node)
    callee = _get_call_func_name(rhs_node)
    if callee and lookup_builtin(callee).get("safe"):
        # 变量被 malloc 等安全函数初始化，但内容可能被后续 snprintf/fgets 覆盖
        # 不返回，继续到 _find_call_with_var_as_arg 检查
        pass
    else:
        return result
```

**设计意图：** C 语言中，变量经常先被 `malloc` 分配内存（safe），然后通过 `snprintf`/`fgets`/`scanf` 等写入数据。如果遇到 safe 函数初始化就返回 `(-1, 0)`，会遗漏后续的数据写入。

---

## 九、RHS 分析分派器：_analyze_rhs_node

### 9.1 节点类型处理矩阵

| 节点类型 | 处理方式 |
|---------|---------|
| 字面量 | `(-1, 0)` 安全 |
| `call_expression` | → `_handle_call_expression_rhs` |
| `binary_expression` | → `_handle_binary_expression_rhs` |
| `identifier` | 自赋值跳过 / 可控检查 / 递归追踪 |
| `subscript_expression` (`arr[i]`) | `argv[i]` 可控 / 递归追踪基础变量 |
| `field_expression` (`obj.field`) | 递归追踪 operand |
| `parenthesized_expression` | 解包递归 |
| `cast_expression` / `type_conversion` | 递归追踪被转换的值 |
| `unary_expression` (`!x`, `-x`, `*ptr`, `&x`) | 递归追踪 operand |
| `pointer_expression` / `dereference_expression` | 递归追踪被解引用变量 |
| `conditional_expression` (`? :`) | 三元约束检查 + 递归两路 |
| 其他 | 收集标识符逐一追踪 |

### 9.2 _handle_call_expression_rhs

```python
def _handle_call_expression_rhs(call_node, var_name, ...):
    func_text = _get_call_func_text(call_node)
    args = _get_call_args_from_ast(call_node)

    # 1. 内置知识库 → safe 且无 passthrough → (-1, 0)
    # 2. passthrough/param_flow → 追踪所有非字面量参数
    #    （注意：不只追踪 passthrough 索引，追踪所有参数）
    # 3. 可控源函数（getenv/scanf/fgets 等）→ (1, lineno)
    # 4. 未知函数 → function_back_c deps 追踪
```

**与 Go/Java 引擎的差异：**
- C 引擎额外检查 `C_CONTROLLED_SOURCES`（第 3 步），因为 C 的可控源是函数调用而非变量属性
- 其他引擎（PHP/JS/Python/Go）的可控源通常是变量访问（`$_GET['x']`, `request.args`）

### 9.3 _handle_binary_expression_rhs

```python
def _handle_binary_expression_rhs(bin_node, var_name, ...):
    for child in bin_node.children:
        # 跳过操作符（+, -, *, /, %, ||, &&, |, &, ^, <<, >>, <, >, <=, >=, ==, !=）
        if child.type in ("+", "-", "*", "/", "%", "||", "&&", "|", "&", "^",
                          "<<", ">>", "<", ">", "<=", ">=", "==", "!="):
            continue
        if _is_literal_node(child):
            continue
        # 追踪非字面量子表达式中的变量
        var_names = _collect_identifiers_from_ast(child)
        for vn in var_names:
            if _is_controllable_source(vn, controlled_params):
                return (1, lineno)
            r = _trace_variable_in_lines(file_path, vn, ...)
            if r[0] in (1, 2):
                return r
```

---

## 十、跨函数追踪：function_back_c

### 10.1 执行流程

```
function_back_c(func_name, call_args, vul_lineno, file_path)
│
├─ 1. 递归防护：_scan_function_stack
│
├─ 2. 内置知识库检查
│   └─ safe=True 且无 passthrough/param_flow → (-1, [])
│
├─ 3. 函数摘要快速判定
│   └─ lookup_summary(func_name) → _judge_from_summary()
│
├─ 4. 函数定义查找（三级策略）
│   ├─ _func_def_index 索引（当前文件）
│   ├─ _find_function_def_in_ast（实时 AST 搜索）
│   └─ 跨文件搜索 pre_result
│
├─ 5. callee 函数体 sink 检查
│   └─ _trace_callee_body_for_sinks(...)
│
└─ 6. 返回值依赖分析
    └─ _analyze_return_deps_c(...)
```

### 10.2 _trace_callee_body_for_sinks

```python
def _trace_callee_body_for_sinks(callee_file_path, callee_func_name, formal_params,
                                  call_args_str, caller_file_path, ...):
```

**流程：**
1. AST 解析 callee 文件，查找函数定义
2. Walk 函数体，找所有 `lookup_builtin()` 返回 `safe=False` 的调用（即 sink）
3. 建立形参→实参映射
4. 对每个 sink 参数：
   - 参数标识符 ∈ arg_map → 检查实参可控性
   - 实参直接可控 → `(1, [])`
   - 实参含变量 → `("deps", caller_var_names)`

### 10.3 _analyze_return_deps_c

```python
def _analyze_return_deps_c(formal_params, body_node, call_args_str, ...):
```

**关键设计点——赋值链传播（AST 版本）：**

```python
controllable_local = set(controllable_formal)
for _ in range(3):
    changed = _propagate_controllable_in_body(body_node, controllable_local)
    if not changed:
        break
```

`_propagate_controllable_in_body` 是 C/C++ 引擎独有的 AST 传播函数，在函数体内传播可控变量标记。它处理三种节点：

1. **init_declarator**（`int x = controllable_var`）：
   - RHS 标识符 ∩ controllable_local ≠ ∅ → LHS 标记为可控

2. **assignment_expression**（`x = controllable_var`）：
   - 同上，支持 `subscript_expression` 作为 LHS（`arr[i] = ...`）

3. **call_expression**（`strcpy(buf, controllable_var)`）：
   - **passthrough**：返回值透传，如果透传参数可控 → 标记调用结果为可控
   - **param_flow**（int → int）：输出参数继承输入参数的可控性
   - **param_flow**（int → str）：隐式数据源（如 `"stdin"`）→ 输出参数直接可控

### 10.4 _judge_from_summary

```python
def _judge_from_summary(summary, call_args_str, controlled_params):
    for rf in summary.return_flow:
        if rf.origin_type == "param":
            # 检查对应实参是否可控
        elif rf.origin_type == "call":
            # 检查知识库中该函数的安全/透传属性
        elif rf.origin_type == "global":
            if _is_controllable_source(rf.origin): return (1, [])
        elif rf.origin_type == "literal":
            continue
    return (-1, [])
```

---

## 十一、形参追踪与跨文件搜索

### 11.1 _trace_param_at_call_sites

```python
def _trace_param_at_call_sites(func_name, param_name, file_path, tree, ...):
    # 1. AST walk 搜索所有 call_expression，匹配 func_name
    # 2. 获取函数定义的形参列表（AST 搜索或索引 fallback）
    # 3. 找到 param_name 在形参中的位置
    # 4. 获取对应实参
    # 5. 追踪实参
    #    ├─ identifier → _trace_variable_in_lines
    #    └─ 复杂表达式 → _analyze_rhs_node
```

### 11.2 跨文件搜索

```python
# 在 _trace_variable_in_lines_impl 中：
# 当前文件搜索
call_result = _trace_param_at_call_sites(func_name, param_name, file_path, tree, ...)

# 跨文件暴力搜索
if not call_result:
    for other_fp, other_data in pt.pre_result.items():
        if other_data.get("language") in ("c", "cpp", "c++"):
            other_tree = _parse_c_ast(other_fp)
            call_result = _trace_param_at_call_sites(func_name, param_name, other_fp, other_tree, ...)
```

**与 Go 引擎的差异：**
- Go 引擎有 `import_map` 精确搜索（通过 import 别名映射文件）
- C/C++ 引擎**没有 include/import 路径解析**，只有暴力搜索 fallback
- 这是合理的——C/C++ 的 `#include` 系统比 Go import 复杂得多（宏、条件编译、系统头文件）

---

## 十二、文本回退：_text_trace_variable

当 AST 分析未找到赋值或 AST 解析失败时，回退到纯文本逐行扫描：

```python
def _text_trace_variable(file_path, var_name, vul_lineno, ...):
    lines = _get_source_lines(file_path)
    # 向上查找赋值（最多 50 行）
    start = max(0, vul_lineno - 52)
    for i in range(vul_lineno - 2, start, -1):
        line = lines[i].strip()
        if not line or line.startswith('//'): continue

        # 匹配带类型声明: int/char/... var = expr
        m_decl = re.match(r'(?:\w+(?:\s*\*)*)\s+' + re.escape(var_name) + r'\s*=\s*(.+)', line)
        # 匹配纯赋值: var = expr
        m_assign = re.match(r'(?:' + re.escape(var_name) + r')\s*=\s*(.+)', line)

        # 检查 RHS 是否可控 / 修复 / 递归追踪子变量
```

**限制：** 最多向上搜索 50 行，避免跨函数误匹配。

---

## 十三、内置知识库设计

### 13.1 知识库分类

C/C++ 知识库覆盖 ~100 个函数，按头文件/功能分类：

| 类别 | 典型函数 | passthrough | param_flow | safe |
|------|---------|-------------|------------|------|
| 字符串处理 | `strlen` | [] | - | True |
| 字符串处理 | `strcpy` | [0] | {0:1} | False |
| 字符串处理 | `strdup` | [0] | - | False |
| 格式化 I/O | `sprintf` | [] | {0:1} | False |
| 格式化 I/O | `scanf` | [] | {1:"stdin",...} | False |
| 类型转换 | `atoi` | [0] | - | False |
| 内存分配 | `malloc` | [] | - | True |
| 安全函数 | `mysql_real_escape_string` | [] | {0:1} | True |
| 网络 I/O | `recv` | [] | {1:0} | False |
| POSIX 执行 | `execvp` | [] | - | False |

### 13.2 知识库字段语义

```python
{
    "passthrough": [0],           # 返回值依赖哪些参数（0-indexed）
    "safe": True,                 # 函数是否做了安全过滤
    "param_flow": {0: 1}          # 参数间数据流：{输出索引: 输入索引或隐式源}
}
```

**param_flow 的两种值类型：**
- `int`：参数位置索引，表示输出参数继承输入参数的数据
  - `"strcpy": {0: 1}` → 参数 0（dest）的数据来自参数 1（src）
- `str`：隐式数据源标识
  - `"scanf": {1: "stdin"}` → 参数 1（&var）的数据来自 stdin
  - 这对应 C 语言的指针参数输出模式

### 13.3 lookup 函数

```python
def lookup(func_name: str):
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]
    # C++ 命名空间短名匹配
    if "::" in func_name:
        short_name = func_name.split("::")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]
    return None
```

---

## 十四、完整数据流图

### 14.1 从 Sink 到 Source 的完整追踪链路

以一个 C 命令注入为例：

```c
// main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void run_command(const char *input) {    // Line 8
    char cmd[256];                       // Line 9
    snprintf(cmd, sizeof(cmd), "ls %s", input);  // Line 10
    system(cmd);                         // Line 11: sink
}

int main(int argc, char *argv[]) {       // Line 14
    if (argc < 2) return 1;              // Line 15
    char *user_input = argv[1];          // Line 16: source
    run_command(user_input);             // Line 17
    return 0;
}
```

**追踪链路：**

```
scan_parser(["system"], 11, "main.c")
│
├─ _find_call_at_line → call_node = system(cmd)
├─ _get_call_args_from_ast → [arg0=identifier("cmd")]
│
├─ 对 arg0 (cmd):
│   ├─ _collect_identifiers → ["cmd"]
│   └─ _trace_variable_in_lines("main.c", "cmd", 11)
│       │
│       └─ _trace_variable_in_lines_impl:
│           ├─ _parse_c_ast("main.c")
│           ├─ _find_enclosing_function → "run_command"
│           ├─ cmd ∉ C_CONTROLLED_SOURCES
│           ├─ cmd ∉ param_names (只有 "input")
│           │
│           ├─ _find_assignment_at_line:
│           │   ├─ Line 9: declaration > init_declarator
│           │   │   └─ cmd ← skip（无 RHS，char cmd[256] 是数组声明）
│           │   └─ Line 10: expression_statement > call_expression(snprintf)
│           │       └─ cmd 不是 LHS → skip
│           │   返回 None
│           │
│           ├─ code=-1 且来自 safe 函数？不，无赋值
│           │
│           ├─ _find_call_with_var_as_arg(tree, 11, "cmd", 10)
│           │   ├─ 找到: snprintf(cmd, sizeof(cmd), "ls %s", input) @ Line 10
│           │   ├─ arg_index=0 (cmd 是参数 0)
│           │   ├─ lookup_builtin("snprintf")
│           │   │   └─ {"passthrough": [], "safe": False, "param_flow": {0: 1}}
│           │   ├─ param_flow[0] = 1 → 检查参数 1
│           │   ├─ args[1] = sizeof(cmd) → _is_literal_node → skip
│           │   │
│           │   │   ⚠️ 注意：snprintf 的格式串 "ls %s" 是参数 1，
│           │   │   但 param_flow {0:1} 指向参数 1（格式串），不是参数 2（input）
│           │   │   这可能是一个知识库设计问题...
│           │   │
│           │   └─ 对于这个例子，假设 param_flow 修改为 {0: 2}：
│           │       ├─ args[2] = "ls %s", input
│           │       ├─ _collect_identifiers → ["input"]
│           │       ├─ _is_controllable_source("input") → False
│           │       └─ _trace_variable_in_lines("main.c", "input", 10)
│           │           │
│           │           └─ _trace_variable_in_lines_impl:
│           │               ├─ _find_enclosing_function → "run_command"
│           │               ├─ input ∈ param_names! (第 0 个形参)
│           │               ├─ _trace_param_at_call_sites("run_command", "input")
│           │               │   ├─ Walk AST → 找到 run_command(user_input) @ Line 17
│           │               │   ├─ formal_params = ["input"], param_idx = 0
│           │               │   ├─ actual_arg = identifier("user_input")
│           │               │   └─ _trace_variable_in_lines("main.c", "user_input", 17)
│           │               │       │
│           │               │       └─ _trace_variable_in_lines_impl:
│           │               │           ├─ _find_enclosing_function → "main"
│           │               │           ├─ user_input ∉ param_names (argc, argv)
│           │               │           ├─ _find_assignment_at_line:
│           │               │           │   └─ Line 16: declaration > init_declarator
│           │               │           │       └─ LHS="user_input", RHS=argv[1]
│           │               │           └─ _analyze_rhs_node(argv[1])
│           │               │               ├─ subscript_expression
│           │               │               ├─ array = argv → "argv" == "argv"
│           │               │               └─ return (1, 16) ✅
│           │               │
│           │               └─ return (1, 16)
│           │
│           └─ return (1, 16)
│
├─ 分支约束检查
│   └─ _check_sink_branch_constraints(tree, 11, "cmd", body_node)
│       └─ main 函数中有 if (argc < 2) 但 sink 不在其中 → False
│
└─ return (1, 16) → code=1, 漏洞成立
    结果: {"code": 1, "vul_func": "system", "param": "cmd",
           "source_file": "main.c", "source_lineno": 16}
```

### 14.2 gets() 无条件危险函数

```c
char buf[64];
gets(buf);  // Line 5: sink — 无边界检查，任何输入都危险
```

```
scan_parser(["gets"], 5, "file.c")
├─ matched_func = "gets"
├─ matched_func in ("gets",) → True
└─ 直接返回 {"code": 1, "param": "unbounded_input"}
```

---

## 十五、C/C++ 引擎设计特点总结

### 15.1 与其他引擎的对比

| 特性 | C/C++ | Go | PHP | JS | Python | Java |
|------|-------|-----|-----|-----|---------|------|
| 解析器 | tree-sitter-c | tree-sitter-go | lphply | lesprima | builtins ast | ljavalang |
| AST 缓存 | ✅ 模块级 | ✅ 模块级 | ❌ | ❌ | ❌ | ❌ |
| 函数定义索引 | ✅ AST 节点 | ✅ AST 节点 | ❌ | ❌ | ❌ | ❌ |
| 独立 AST 追踪模块 | ❌ 内聚 | ✅ _ast_trace.py | ❌ | ❌ | ✅ ast 模块 | ❌ |
| param_flow 支持 | ✅ int+str | ✅ | ❌ | ❌ | ❌ | ❌ |
| 后续写入检查 | ✅ 独有 | ❌ | ❌ | ❌ | ❌ | ❌ |
| strcmp 约束提取 | ✅ 独有 | ❌ | ❌ | ❌ | ❌ | ❌ |
| 赋值链 AST 传播 | ✅ _propagate | ❌ | ❌ | ❌ | ❌ | ❌ |
| 无条件危险函数 | ✅ gets() | ❌ | ❌ | ❌ | ❌ | ❌ |
| 文本回退路径 | ✅ _text_trace | ✅ | ✅ | ✅ | ❌ | ✅ |

### 15.2 C/C++ 引擎独有设计

1. **param_flow 隐式数据源**：`{output_idx: "stdin"}` 直接标记输出参数为可控，解决 C 语言指针参数输出模式
2. **后续写入检查**（`_find_call_with_var_as_arg`）：处理 `malloc` + `snprintf` 的两阶段写入模式
3. **safe 函数续传**：遇到 `malloc` 等 safe 初始化不立即返回，继续检查后续数据写入
4. **strcmp 约束提取**：专门处理 `strcmp(x, "str") == 0` 的 C 语言惯用模式
5. **AST 赋值链传播**（`_propagate_controllable_in_body`）：在函数体内迭代传播可控变量标记
6. **无条件危险函数**（`gets()`）：不需要分析参数，直接标记为漏洞
7. **环检测**：使用 `visited` 集合（比 Go 的 `_scan_function_stack` 更精细，可检测变量级别的循环追踪）

### 15.3 潜在改进方向

1. **`#include` 路径解析**：当前无 include 系统分析，跨文件搜索完全依赖暴力遍历
2. **宏展开**：C 预处理宏会改变代码结构，tree-sitter 不处理宏展开
3. **指针分析**：当前追踪 `*ptr` 只追踪 `ptr` 本身，不做指针别名分析
4. **结构体字段追踪**：`obj.field` 只追踪 `obj`，不区分不同字段的污点
5. **函数指针（多层/跨作用域）**：单层函数指针间接调用已通过 alias 边支持，但多层间接（全局声明+函数内调用）和函数指针作为参数传递仍不支持
6. **snprintf param_flow**：格式串函数的 param_flow 设计需要更精细（区分格式串和数据参数）
