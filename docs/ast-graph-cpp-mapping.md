# C++ AST → 统一图映射文档

## 解析器：tree-sitter-cpp

C++ 使用 `tree-sitter-cpp` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`），Normalizer 继承并扩展了 C Normalizer 的基础逻辑，新增了 C++ 特有的语言构造支持。

### tree-sitter C++ 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型名（如 `class_specifier`、`lambda_expression`） |
| `node.text` | **bytes**，UTF-8 源码文本（注意：非 str） |
| `node.children` | list[Node]，有序子节点列表 |
| `node.start_point` | (row, col)，row 为 **0-indexed** |
| `node.end_point` | (row, col)，row 为 **0-indexed** |

---

## NodeLabel 总览

| 统一标签 (NodeLabel) | 说明 | C++ 中对应的主要 tree-sitter 节点 |
|----------------------|------|-----------------------------------|
| `FILE` | 文件根节点 | 由 Normalizer 构造，非 tree-sitter 节点 |
| `CLASS` | 类型定义（类/结构体/枚举） | `class_specifier`、`struct_specifier`、`enum_specifier`、`type_definition` |
| `FUNCTION` | 函数/方法/构造/析构/lambda | `function_definition`、`declaration`+`function_declarator`、`lambda_expression` |
| `PARAMETER` | 函数参数 | `parameter_declaration`（嵌套在 `parameter_list` 中） |
| `RETURN` | 返回语句 | `return_statement` |
| `IDENTIFIER` | 变量/类型/字段名 | `identifier`、`type_identifier`、`field_identifier`、`destructor_name` |
| `CONST` | 字面量常量 | `number_literal`、`string_literal`、`char_literal`、`true`、`false`、`null` |
| `OPERATOR` | 运算/调用/赋值/控制转移 | `call_expression`、`binary_expression`、`assignment_expression` 等 |
| `BRANCH` | 分支/循环/异常 | `if_statement`、`for_statement`、`for_range_loop`、`try_statement` 等 |
| `IMPORT` | 导入/包含/using | `preproc_include`、`using_declaration` |
| `DEPENDENCY` | 文件依赖 | 由 `preproc_include` 的路径动态生成 |
| `ANNOTATION` | 注解/装饰器 | C++ 无此概念（见 [语言固有缺失](#语言固有缺失)） |

---

## ClassType 映射

| C++ AST 节点 | Unified Label | ClassType | C++ 特有 | 备注 |
|-------------|---------------|-----------|----------|------|
| `class_specifier` | CLASS | **class** | ✅ | C++ class 定义，支持继承（`base_class_clause`） |
| `struct_specifier`（独立） | CLASS | struct | ❌ | 独立 struct 定义（与 C 共享） |
| `union_specifier`（独立） | CLASS | struct | ❌ | union 定义（与 C 共享，ClassType 无 UNION 枚举值） |
| `enum_specifier`（独立） | CLASS | enum | ❌ | enum 定义（与 C 共享） |
| `type_definition` + `struct_specifier` | CLASS | struct | ❌ | `typedef struct { ... } Name;`（与 C 共享） |
| `type_definition` + `union_specifier` | CLASS | struct | ❌ | `typedef union { ... } Name;`（与 C 共享） |
| `type_definition` + `enum_specifier` | CLASS | enum | ❌ | `typedef enum { ... } Name;`（与 C 共享） |
| `type_definition`（其他） | CLASS | class | ❌ | 其他 typedef（与 C 共享） |

> **C++ 特有说明**：`class_specifier` 是 C++ 专属节点。在 C 中，`class_specifier` 不存在；C 的类定义只有 `struct_specifier`。C++ 的 `class_specifier` 内部会遍历子节点，将构造函数、析构函数、方法在 CLASS 上下文中注册（即 `ctx_stack` 中 parent 为 CLASS），从而正确识别 `FunctionType`。

---

## FunctionType 映射

| C++ AST 节点 | Unified Label | FunctionType | C++ 特有 | 备注 |
|-------------|---------------|-------------|----------|------|
| `function_definition`（顶层/非 class 内） | FUNCTION | function | ❌ | 普通函数（与 C 共享） |
| `function_definition`（class 内，无返回类型且名≠~名） | FUNCTION | **constructor** | ✅ | 构造函数：检测条件 — parent 为 CLASS 且 `ret_type == ""` |
| `function_definition`（含 `destructor_name`） | FUNCTION | **destructor** | ✅ | 析构函数：检测条件 — `function_declarator` 含 `destructor_name` 子节点 |
| `function_definition`（class 内，有返回类型） | FUNCTION | **method** | ✅ | 成员方法：检测条件 — parent 为 CLASS 且有返回类型 |
| `declaration` + `function_declarator` | FUNCTION | function | ❌ | 前向声明（与 C 共享） |
| `lambda_expression` | FUNCTION | **lambda** | ✅ | Lambda 表达式，名称格式 `<lambda[捕获列表]>` |

> **构造/析构/方法检测逻辑**：
> 1. 若 `function_declarator` 含 `destructor_name` 子节点 → `FunctionType.DESTRUCTOR`
> 2. 若 `ctx_stack` 顶节点为 CLASS：
>    - 若 `ret_type == ""` 或 `ret_type == name.lstrip("~")` → `FunctionType.CONSTRUCTOR`
>    - 否则 → `FunctionType.METHOD`
> 3. 否则 → `FunctionType.FUNCTION`

> **函数名提取**：从 `function_declarator` 的子节点中按优先级查找：`identifier` > `field_identifier` > `destructor_name` > `operator_name`

---

## OperatorType 映射

| C++ AST 节点 | Unified Label | OperatorType | C++ 特有 | 备注 |
|-------------|---------------|-------------|----------|------|
| `call_expression`（普通 callee） | OPERATOR | call | ❌ | 函数调用（与 C 共享） |
| `call_expression`（`field_expression`/`member_expression` callee） | OPERATOR | method_call | ❌ | 方法调用（与 C 共享） |
| `assignment_expression` | OPERATOR | assign | ❌ | `=`、`+=`、`-=` 等（与 C 共享） |
| `binary_expression` | OPERATOR | binary_op | ❌ | 二元运算（与 C 共享） |
| `unary_expression` | OPERATOR | unary_op | ❌ | `!`、`-`、`*`、`&`、`~`（与 C 共享） |
| `update_expression` | OPERATOR | unary_op | ❌ | `++`/`--`（与 C 共享） |
| `cast_expression` | OPERATOR | type_cast | ❌ | C 风格类型转换（与 C 共享） |
| `sizeof_expression` | OPERATOR | unary_op | ❌ | sizeof（与 C 共享） |
| `member_expression` / `field_expression` | OPERATOR | method_call | ❌ | `a.b` / `a->b`（与 C 共享） |
| `subscript_expression` | OPERATOR | binary_op | ❌ | `a[i]`（与 C 共享） |
| `break_statement` | OPERATOR | break | ❌ | break（与 C 共享） |
| `continue_statement` | OPERATOR | continue | ❌ | continue（与 C 共享） |
| `goto_statement` | OPERATOR | goto | ❌ | goto（与 C 共享） |
| `new_expression` | OPERATOR | **new** | ✅ | `new` 表达式，`attrs.callee` 保存完整表达式文本（截断至60字符） |
| `delete_expression` | OPERATOR | call（映射为 delete） | ✅ | `delete` 表达式，`attrs.callee = "delete"` |
| `throw_statement` | OPERATOR | **throw** | ✅ | `throw` 表达式 |

> **未使用的 OperatorType 枚举值**：`static_call`、`aug_assign`、`yield`、`await` — C++ 中不使用。

---

## BranchType 映射

| C++ AST 节点 | Unified Label | BranchType | C++ 特有 | 备注 |
|-------------|---------------|------------|----------|------|
| `if_statement` | BRANCH | if | ❌ | if 分支（与 C 共享） |
| `else_clause` + `compound_statement` | BRANCH | else | ❌ | else 分支（与 C 共享） |
| `else_clause` + `if_statement` | BRANCH | if（递归） | ❌ | else if 链（与 C 共享） |
| `for_statement` | BRANCH | for | ❌ | C 风格 for（与 C 共享） |
| `for_range_loop` | BRANCH | **foreach** | ✅ | C++11 range-based for，命名格式为 "foreach" |
| `while_statement` | BRANCH | while | ❌ | while 循环（与 C 共享） |
| `do_statement` | BRANCH | while | ❌ | do-while 循环（与 C 共享） |
| `switch_statement` | BRANCH | switch | ❌ | switch（与 C 共享） |
| `case_statement`（含 default） | BRANCH | case / default | ❌ | case/default 分支（与 C 共享） |
| `conditional_expression` | BRANCH | ternary | ❌ | 三元 `?:`（与 C 共享） |
| `try_statement` | BRANCH | **try** | ✅ | try 块 |
| `catch_clause` | BRANCH | **catch** | ✅ | catch 子句，作为 try 的 AST 边子节点 |

> **未使用的 BranchType 枚举值**：`elif`、`finally`、`match` — C++ 中不使用（C++ 无 elif 关键字，使用 else if 链；无 finally 关键字，使用 RAII）。

---

## ImportType 映射

| C++ AST 节点 | Unified Label | ImportType | C++ 特有 | 备注 |
|-------------|---------------|------------|----------|------|
| `preproc_include` + `system_lib_string` | IMPORT | include | ❌ | `#include <header>`（与 C 共享） |
| `preproc_include` + `string_literal` | IMPORT | include | ❌ | `#include "file"`（与 C 共享） |
| `using_declaration` | IMPORT | **import** | ✅ | `using namespace::item;`，从 `qualified_identifier` 或全文提取名称 |

> **未使用的 ImportType 枚举值**：`from_import`、`require`、`include_once`、`require_once`、`use` — C++ 中不使用。

> **缺失**：`namespace_definition` 节点当前走 fallback（`_walk_children`），不生成 IMPORT 节点。`template_declaration` 同理走 fallback。

---

## IdentifierType 映射

| C++ AST 节点 | Unified Label | IdentifierType | C++ 特有 | 备注 |
|-------------|---------------|---------------|----------|------|
| `identifier` | IDENTIFIER | variable | ❌ | 普通变量名（与 C 共享） |
| `type_identifier` | IDENTIFIER | static | ❌ | 类型名（struct/class/enum/typedef 名）（与 C 共享） |
| `field_identifier` | IDENTIFIER | field | ❌ | 结构体/类成员名，如 `user.name` 中的 `name`（与 C 共享） |
| `destructor_name`（通过 `_walk_function_def` 提取） | IDENTIFIER | variable | ✅ | 析构函数名（如 `~Foo`），⚠️ 其 `node.type` 为 `destructor_name` 而非 `identifier` |

> **未使用的 IdentifierType 枚举值**：`property`、`global`、`super`、`this` — C++ 中 `this` 和全局变量目前不区分标识。

---

## ConstType 映射

| C++ AST 节点 | Unified Label | ConstType | C++ 特有 | 备注 |
|-------------|---------------|-----------|----------|------|
| `number_literal` | CONST | number | ❌ | 数字字面量（与 C 共享） |
| `string_literal` | CONST | string | ❌ | 字符串字面量（与 C 共享） |
| `char_literal` | CONST | string | ❌ | 字符字面量（与 C 共享） |
| `true` | CONST | **boolean** | ✅ | C++ `true` 关键字（C 中无此节点） |
| `false` | CONST | **boolean** | ✅ | C++ `false` 关键字（C 中无此节点） |
| `null`（→ NULL leaf） | CONST | null | ❌ | C/C++ NULL 常量（与 C 共享） |

> **缺失**：C++ `nullptr` 关键字 — 在 tree-sitter-cpp 中可能映射为 `null` 节点或独立节点，当前 Normalizer 未单独处理，走 `null` → `ConstType.NULL` 路径或 fallback。

---

## EdgeType 映射

| 边类型 | C++ 中的使用场景 |
|--------|------------------|
| OWN | file→import/function/class, function→parameter, class→field, branch→statement, switch→case, try→catch |
| AST | branch→condition, call→callee/arg, binary→left/right, assign→lhs/rhs, return→value, try→catch |
| MEMBER | object→member_expression（`a.b` / `a->b` 的对象侧到成员访问节点） |
| FRG | import→dependency（`#include` 文件依赖关系） |

> **未使用的边类型**：`CG`（调用图）、`DFG`（数据流图）、`CRG`（类继承关系）、`USE`（引用关系） — 在 Normalizer 阶段不生成，可能在后续分析阶段补充。

---

## C 与 C++ 共享的基础节点

以下节点处理逻辑完全继承自 C Normalizer，行为一致：

| 类别 | 节点 |
|------|------|
| **函数** | `function_definition`、`declaration`+`function_declarator` |
| **分支** | `if_statement`、`for_statement`、`while_statement`、`do_statement`、`switch_statement`、`case_statement`、`conditional_expression` |
| **运算** | `call_expression`、`binary_expression`、`unary_expression`、`update_expression`、`assignment_expression`、`cast_expression`、`sizeof_expression`、`subscript_expression`、`member_expression`/`field_expression` |
| **控制** | `return_statement`、`break_statement`、`continue_statement`、`goto_statement` |
| **类型** | `type_definition`、`struct_specifier`、`union_specifier`、`enum_specifier` |
| **导入** | `preproc_include` |
| **字面量** | `number_literal`、`string_literal`、`char_literal`、`null` |
| **标识符** | `identifier`、`type_identifier`、`field_identifier` |
| **容器** | `compound_statement`、`parenthesized_expression`、`expression_statement`、`compound_literal` |

---

## 语言固有缺失

C++ 在 tree-sitter 层面缺少以下在其他语言中常见的结构，Normalizer 中对应的枚举值因此 **未被使用**：

| 缺失概念 | 说明 |
|---------|------|
| `interface`（ClassType.INTERFACE） | C++ 无 interface 关键字，纯虚类可模拟但 tree-sitter 无对应节点 |
| `enum class` 独立处理 | tree-sitter-cpp 将 `enum class` 解析为 `enum_specifier`，不区分类枚举 |
| `namespace_definition` | 存在此节点但 Normalizer 当前走 fallback，不生成独立图节点 |
| `template_declaration` / `template_parameter_list` | 存在此节点但 Normalizer 当前走 fallback，模板参数不提取 |
| `access_specifier`（public/protected/private） | 作为跳过类型（`_SKIP_TYPES`），不生成图节点 |
| `finally`（BranchType.FINALLY） | C++ 异常处理无 finally 关键字，使用 RAII 模式替代 |
| `match`（BranchType.MATCH） | C++ 无 match 表达式（C++17 无此特性） |
| `yield` / `await` | C++20 协程（co_yield/co_await）未在当前 Normalizer 中实现 |
| `this` 指针标识 | `this` 关键字作为普通 `identifier` 处理，无 IdentifierType.THIS 专用映射 |
| `nullptr` 专用处理 | C++ `nullptr` 未单独映射，走 `null` → `ConstType.NULL` 或 fallback |

---

## ⚠️ Pitfalls（常见陷阱）

### 1. `destructor_name` 不是 `identifier`

在 tree-sitter-cpp 中，析构函数名 `~ClassName` 的节点类型为 `destructor_name`，**不是** `identifier`。因此：

- `_IDENTIFIER_TYPES` frozenset 中 **不包含** `destructor_name`
- 在 `_walk_function_def` 中通过 `_find_child_by_type(func_decl, "destructor_name")` 单独检测
- 若代码仅检查 `identifier` 类型节点，会 **漏掉析构函数名**

```cpp
// tree-sitter 节点结构
// function_definition
//   type: void
//   function_declarator
//     destructor_name: ~Foo    ← node.type = "destructor_name"
//     parameter_list: (...)
//   compound_statement: { ... }
```

### 2. `field_identifier` 不是 `identifier`

`field_identifier` 有独立的 `node.type`，但在 `_IDENTIFIER_TYPES` 中被包含，映射为 `IdentifierType.FIELD`。**但**在泛用代码中搜索 `identifier` 类型节点时需注意不要遗漏 `field_identifier`。

```cpp
// tree-sitter 节点结构
// field_expression
//   identifier: user              ← node.type = "identifier"
//   .
//   field_identifier: name       ← node.type = "field_identifier"（非 identifier）
```

### 3. `for_range_loop` 命名

C++11 range-based for 在 tree-sitter-cpp 中的节点类型为 `for_range_loop`，**不是**更直觉的 `range_based_for`。代码中：

```python
if ntype == "for_range_loop":
    return self._walk_range_for(...)
```

映射为 `BranchType.FOREACH`（值为 `"foreach"`），在图中命名为 `"foreach"`。

### 4. `source_content` 的 bytes/str 兼容

tree-sitter 的 `node.text` 返回 **bytes** 类型，但 Normalizer 的 `source_content` 参数接受 `str | None`。在计算 content_hash 时：

```python
if isinstance(source_content, str) else source_content
```

内部 `_text()` 方法统一处理了 bytes → str 转换：

```python
if isinstance(raw, bytes):
    return raw.decode("utf-8", errors="ignore")
```

但某些 C++ 专有路径（如 `_walk_class`、`_walk_lambda`）直接调用 `node.text.decode(errors="replace")`，**使用的是 `errors="replace"` 而非 `errors="ignore"`**，行为不一致。

### 5. class 上下文必须遍历子节点

C++ 的 `class_specifier` 处理函数 `_walk_class` 中，方法/构造函数/析构函数的 FunctionType 判断 **依赖** `ctx_stack` 中是否存在 CLASS 上下文。因此：

```python
ctx_stack.append((pos, NodeLabel.CLASS.value))
for child in node.children:
    if child.type in ("field_declaration", "access_specifier", ...):
        continue  # 跳过非方法节点
    self._walk_node(child, ...)  # 遍历方法等
ctx_stack.pop()
```

若 `_walk_class` 仅提取字段而不遍历子节点，则所有方法会被错误识别为 `FunctionType.FUNCTION` 而非 `METHOD`/`CONSTRUCTOR`/`DESTRUCTOR`。

### 6. `namespace_definition` 和 `template_declaration` 未处理

这两个 C++ 特有节点当前走 `_walk_children` fallback，不生成专用的图节点：
- `namespace_definition`：命名空间信息丢失
- `template_declaration`：模板参数和类型信息丢失

### 7. `NULL` 和 `nullptr` 的区分

C 的 `NULL` 宏在 tree-sitter 中解析为 `null` 节点（子节点为 `NULL` 叶节点），映射为 `ConstType.NULL`。C++ 的 `nullptr` 关键字也可能被 tree-sitter-cpp 解析为 `null` 节点，导致无法在图层面区分 `NULL` 和 `nullptr`。

---

## 跳过节点类型（_SKIP_TYPES）

以下 token 类型被跳过，不生成图节点：

**标点/运算符**：`(` `)` `{` `}` `[` `]` `;` `,` `.` `->` `?` `:` `::` `...` `#`

**比较/逻辑运算符**：`==` `!=` `>=` `<=` `>` `<` `&&` `||`

**算术/位运算符**：`+` `-` `*` `/` `%` `=` `!` `~`

**关键字**：`if` `else` `for` `while` `do` `switch` `case` `default` `break` `continue` `return` `goto` `typedef` `struct` `union` `enum` `const` `volatile` `static` `extern` `inline` `void` `char` `short` `int` `long` `float` `double` `signed` `unsigned` `auto` `register`

**特殊**：`NULL`（C NULL 宏叶节点）、`"` `\n`

> **注意**：`class` 关键字不在 `_SKIP_TYPES` 中（因它是 `class_specifier` 的子节点名称），但在 `_walk_class` 中被显式跳过。`access_specifier`（public/protected/private）同样在 `_walk_class` 中被显式跳过。

---

## C++ 特有节点处理汇总

| C++ 特有节点 | 处理方法 | 生成的统一节点 |
|-------------|---------|---------------|
| `class_specifier` | `_walk_class` | CLASS (ClassType.CLASS)，含 base_class 信息 |
| `lambda_expression` | `_walk_lambda` | FUNCTION (FunctionType.LAMBDA)，名格式 `<lambda[capture]>` |
| `for_range_loop` | `_walk_range_for` | BRANCH (BranchType.FOREACH)，名 `"foreach"` |
| `try_statement` | `_walk_try` | BRANCH (BranchType.TRY) |
| `catch_clause` | `_walk_catch` | BRANCH (BranchType.CATCH)，作为 try 的 AST 子节点 |
| `new_expression` | `_walk_new` | OPERATOR (OperatorType.NEW) |
| `delete_expression` | `_walk_delete` | OPERATOR (OperatorType.CALL)，callee="delete" |
| `throw_statement` | `_walk_throw` | OPERATOR (OperatorType.THROW) |
| `using_declaration` | `_walk_using` | IMPORT (ImportType.IMPORT) |
| `destructor_name` | （在 `_walk_function_def` 中检测） | 影响函数的 FunctionType → DESTRUCTOR |
| `namespace_definition` | fallback (`_walk_children`) | 不生成专用节点 |
| `template_declaration` | fallback (`_walk_children`) | 不生成专用节点 |
| `access_specifier` | 在 `_walk_class` 中跳过 | 不生成节点 |
| `base_class_clause` | 在 `_walk_class` 中记录到 attrs | 不生成独立节点，信息存储在 CLASS.attrs.base_class |
| `lambda_capture` | 在 `_walk_lambda` 中提取到名称 | 不生成独立节点 |
| `true` / `false` | `_walk_literal` | CONST (ConstType.BOOLEAN) |

---

## 自动跳过的节点（_SKIP_TYPES 完整列表）

```python
_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "[", "]", ";", ":", ",", ".",
    "==", "!=", ">=", "<=", ">", "<", "&&", "||",
    "+", "-", "*", "/", "%", "=", "!", "~",
    "->", "?", ":", "::",
    "...", "#", "<", ">",
    "if", "else", "for", "while", "do", "switch", "case", "default",
    "break", "continue", "return", "goto",
    "typedef", "struct", "union", "enum",
    "const", "volatile", "static", "extern", "inline",
    "void", "char", "short", "int", "long", "float", "double",
    "signed", "unsigned", "auto", "register",
    "NULL",
    '"', "\n",
})
```
