# Lua AST → Unified Graph Mapping

## Parser: tree-sitter-lua

Lua 使用 `tree-sitter-lua` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"function_declaration"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"then"`、`"end"` |

---

## Node Type Mapping

### Class (0 types)

| Lua AST Node | Unified Label | ClassType | 备注 |
|--------------|---------------|-----------|------|
| — | — | — | Lua 无原生 class 语法 |

Lua 的面向对象通过 table + metatable 模拟，但 normalizer 不将其映射为 CLASS 节点。

### Import (1 type)

| Lua AST Node | Unified Label | ImportType | 备注 |
|--------------|---------------|------------|------|
| `require_call` | IMPORT | require | `require("module")` 专用语法 |
| `function_call` (callee=identifier "require") | IMPORT | require | `require("module")` 在 tree-sitter 中可能解析为普通函数调用 |

require 调用通过 FRG IMPORT 边链接到 DEPENDENCY 节点。

### Function (2 types)

| Lua AST Node | Unified Label | FunctionType | 备注 |
|------------------|---------------|-------------|------|
| `function_declaration` | FUNCTION | function | 命名函数 `function foo() end` |
| `function_definition` | FUNCTION | lambda | 匿名函数 `function(x, y) end` |
| `local_declaration` (含 function_definition) | FUNCTION | lambda | `local f = function(x) end` |
| `local_declaration` (含 function_call) | — | — | `local x = foo()` — 生成变量 + 调用节点 |

**函数参数：** 从 `parameters` 中提取 `identifier` 子节点，生成 PARAMETER 节点。

### Branch (6 types)

| Lua AST Node | Unified Label | BranchType | 备注 |
|--------------|---------------|------------|------|
| `if_statement` | BRANCH | if | if 条件语句（含 elseif/else） |
| `while_statement` | BRANCH | while | while 循环 |
| `for_statement` | BRANCH | for | 数值型 for `for i=1,10 do end` |
| `for_in_statement` | BRANCH | foreach | 泛型 for `for k,v in pairs(t) do end` |
| `repeat_statement` | BRANCH | while | repeat-until 循环（映射为 while） |
| `return_statement` | RETURN | — | 返回语句（非 BRANCH） |

**if_statement 结构：** Lua 的 if 语句包含 `elseif` 和 `else` 关键字子节点作为分支分隔符，normalizer 遍历所有条件表达式和块。

### Operator (9 types)

| Lua AST Node | Unified Label | OperatorType | 备注 |
|--------------|---------------|-------------|------|
| `function_call` | OPERATOR | call | 函数调用 `foo(args)` |
| `method_call` | OPERATOR | method_call | 方法调用 `obj:method(args)` |
| `assignment` | OPERATOR | assign | 赋值 `x = value` |
| `binary_operation` | OPERATOR | binary_op | 二元运算 |
| `unary_operation` | OPERATOR | unary_op | 一元运算（-, not, #） |
| `bracket_index_expression` | OPERATOR | binary_op | 索引访问 `a[b]` |
| `break_statement` | OPERATOR | break | break 语句 |
| `goto_statement` | OPERATOR | goto | goto 语句，提取目标 label |

### Identifier (3 types)

| Lua AST Node | Unified Label | IdentifierType | 备注 |
|--------------|---------------|---------------|------|
| `identifier` | IDENTIFIER | variable | 普通标识符 |
| `name` (table field) | IDENTIFIER | field | 表字段名 `{ key = value }` |
| `dot_index_expression` | IDENTIFIER | field | 点访问 `a.b` — 提取 . 后的名称 |
| `label_statement` | IDENTIFIER | variable | 标签 `::name::` — 用于 goto 跳转目标 |

### Const (5 types)

| Lua AST Node | Unified Label | ConstType | 备注 |
|--------------|---------------|-----------|------|
| `number` | CONST | number | 数字（整数/浮点/十六进制/科学计数） |
| `string` | CONST | string | 字符串（单引号/双引号/长字符串 [[]]） |
| `true` / `false` | CONST | boolean | 布尔值（在 _SKIP_TYPES 中特殊处理） |
| `nil` | CONST | null | nil 空值（在 _SKIP_TYPES 中特殊处理） |

### Parameter

| Lua AST Node | Unified Label | 备注 |
|--------------|---------------|------|
| `identifier` (in `parameters`) | PARAMETER | 函数参数 |

---

## Edge Type Mapping

| 边类型 | Lua 中的使用场景 |
|--------|-----------------|
| OWN | file→import, file→function, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, binary→left/right, return→value, assign→lhs/rhs, goto→label |
| FRG | import→dependency (IMPORT) |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand |
| VALUE | return→expression, local_var→initializer |
| LHS | assignment→left side |
| RHS | assignment→right side |
| OPERAND | unary→operand, method_call→object |

---

## 语言特性限制

| 统一类型 | Lua 支持情况 | 说明 |
|----------|-------------|------|
| ClassType.CLASS | ❌ | Lua 无原生 class，使用 table + metatable 模拟 |
| ClassType.INTERFACE | ❌ | 无接口 |
| ClassType.STRUCT | ❌ | 无结构体 |
| ClassType.ENUM | ❌ | 无枚举 |
| FunctionType.METHOD | ❌ | Lua 无原生方法，通过 `obj:method()` 调用（映射为 OPERATOR/METHOD_CALL） |
| FunctionType.CONSTRUCTOR | ❌ | 无构造函数 |
| FunctionType.DESTRUCTOR | ❌ | 无析构函数 |
| FunctionType.LAMBDA | ✅ | function_definition（匿名函数） |
| OperatorType.STATIC_CALL | ❌ | 无静态调用 |
| OperatorType.NEW | ❌ | 无 new 关键字 |
| OperatorType.ASSIGN | ✅ | assignment |
| OperatorType.AUG_ASSIGN | ❌ | Lua 无 +=/-=，需要 `x = x + 1` |
| OperatorType.THROW | ❌ | Lua 使用 `error()` 函数 |
| OperatorType.AWAIT | ❌ | Lua 无 async/await（LuaJ 可用协程但语法不同） |
| OperatorType.YIELD | ❌ | Lua 使用 `coroutine.yield()` 函数调用 |
| OperatorType.CONTINUE | ❌ | Lua 5.1/5.2 无 continue（5.3+ 不适用 tree-sitter） |
| OperatorType.GOTO | ✅ | goto 语句 + label |
| BranchType.ELIF | ❌ | Lua 使用 elseif（在同一 if_statement 节点内） |
| BranchType.SWITCH | ❌ | Lua 无 switch/case |
| BranchType.TERNARY | ❌ | 无三元运算符 |
| BranchType.MATCH | ❌ | 无 match 表达式 |
| BranchType.TRY | ❌ | Lua 使用 pcall/xpcall 函数 |
| BranchType.CATCH | ❌ | 无 catch |
| BranchType.FINALLY | ❌ | 无 finally |
| ImportType.IMPORT | ❌ | Lua 使用 require 而非 import |
| IdentifierType.PROPERTY | ❌ | 无属性声明语法 |
| IdentifierType.STATIC | ❌ | 无 static |
| IdentifierType.GLOBAL | ❌ | 无全局声明关键字（所有变量默认全局） |

---

## tree-sitter Lua 关键陷阱

1. **关键字全是叶节点** — `if`、`then`、`else`、`elseif`、`end`、`for`、`in`、`while`、`do`、`repeat`、`until`、`local`、`function`、`return`、`break`、`goto`、`true`、`false`、`nil` 全部在 _SKIP_TYPES 中
2. **`::name::` 标签格式** — Lua 标签使用 `::` 包围标识符，`label_statement.text` 需要去除 `::` 前后缀
3. **method_call 使用 `:` 分隔** — `obj:method(args)` 中 `:` 是成员访问标记（非 `.`），method_call 的第一个非特殊子节点是对象
4. **require 的双重解析** — `require("module")` 可能被 tree-sitter 解析为 `require_call`（专用节点）或 `function_call`（callee 为 identifier "require"），normalizer 对两种情况都处理
5. **binary_operation vs binary_expression** — Lua 使用 `binary_operation` 作为节点类型名（其他语言通常使用 `binary_expression`）
6. **function_declaration vs function_definition** — Lua 区分命名函数（function_declaration）和匿名函数（function_definition）
7. **local_declaration 内嵌函数定义** — `local f = function(x) end` 中 function_definition 是 local_declaration 的子节点
8. **table_constructor 不生成节点** — 表构造器 `{ a=1, b=2 }` 通过 _walk_children 遍历子节点
9. **repeat_statement 没有 while 子节点** — repeat-until 语法中的 until 条件与 while 不同，normalizer 将其映射为 BranchType.WHILE
10. **Lua 没有 self 关键字** — `self` 在方法调用中是隐式的，不会作为独立节点出现
