# Rust AST → Unified Graph Mapping

## Parser: tree-sitter-rust

Rust 使用 `tree-sitter-rust` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"function_item"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"{"`、`"+"` |

---

## NodeLabel 映射

| Rust AST 节点 | Unified Label | 说明 |
|----------------|---------------|------|
| （根节点 source） | FILE | 每个文件生成一个 FILE 节点 |
| `attribute_item` | ANNOTATION | Rust 属性标注 `#[...]` |
| `use_declaration` | IMPORT | `use` 模块导入声明 |
| `struct_item` | CLASS | struct 定义 → ClassType.STRUCT |
| `enum_item` | CLASS | enum 定义 → ClassType.ENUM |
| `trait_item` | CLASS | trait 定义 → ClassType.INTERFACE |
| `impl_item` | —（容器） | impl 块本身不生成节点，仅遍历内部函数 |
| `function_item` | FUNCTION | 函数/方法定义 |
| `closure_expression` | FUNCTION | 闭包/lambda → FunctionType.LAMBDA |
| `if_expression` | BRANCH | if 表达式 → BranchType.IF |
| `else_clause` | BRANCH | else 分支 → BranchType.ELSE |
| `match_expression` | BRANCH | match 表达式 → BranchType.MATCH |
| `match_arm` | BRANCH | match arm → BranchType.CASE / DEFAULT |
| `for_expression` | BRANCH | for 循环 → BranchType.FOREACH |
| `while_expression` | BRANCH | while 循环 → BranchType.WHILE |
| `loop_expression` | BRANCH | 无限循环 → BranchType.WHILE |
| `return_expression` | RETURN | return 语句 |
| `break_expression` | OPERATOR | break → OperatorType.BREAK |
| `continue_expression` | OPERATOR | continue → OperatorType.CONTINUE |
| `let_declaration` | IDENTIFIER | 变量声明 → IdentifierType.VARIABLE |
| `call_expression` | OPERATOR | 函数调用 → OperatorType.CALL |
| `method_call_expression` | OPERATOR | 方法调用 → OperatorType.METHOD_CALL |
| `macro_invocation` | OPERATOR | 宏调用 → OperatorType.CALL |
| `assignment_expression` | OPERATOR | 赋值 → OperatorType.ASSIGN |
| `binary_expression` | OPERATOR | 二元运算 → OperatorType.BINARY_OP |
| `unary_expression` | OPERATOR | 一元运算 → OperatorType.UNARY_OP |
| `compound_assignment_expression` | OPERATOR | 复合赋值（+=/-= 等）→ OperatorType.AUG_ASSIGN |
| `field_expression` | IDENTIFIER | 字段访问 a.b → IdentifierType.FIELD |
| `index_expression` | OPERATOR | 索引 a[i] → OperatorType.BINARY_OP |
| `type_cast_expression` | OPERATOR | 类型转换 `as` → OperatorType.TYPE_CAST |
| `struct_expression` | OPERATOR | 结构体实例化 → OperatorType.NEW |
| `await_expression` | OPERATOR | await → OperatorType.AWAIT |
| `try_expression` | OPERATOR | `?` 错误传播 → OperatorType.YIELD |
| `scoped_identifier`（含 `::`） | OPERATOR | 作用域路径 → OperatorType.STATIC_CALL |
| `scoped_identifier`（无 `::`） | IDENTIFIER | 作用域标识符 → IdentifierType.STATIC |
| `self` | IDENTIFIER | self 引用 → IdentifierType.THIS |
| `identifier` | IDENTIFIER | 普通标识符 → IdentifierType.VARIABLE |
| `type_identifier` | IDENTIFIER | 类型名 → IdentifierType.VARIABLE |
| `field_identifier` | IDENTIFIER | 字段名 → IdentifierType.VARIABLE |
| `integer_literal` | CONST | 整数字面量 → ConstType.NUMBER |
| `float_literal` | CONST | 浮点字面量 → ConstType.NUMBER |
| `string_literal` | CONST | 字符串字面量 → ConstType.STRING |
| `char_literal` | CONST | 字符字面量 → ConstType.STRING |
| `true` / `false` | CONST | 布尔字面量 → ConstType.BOOLEAN |
| `parameter` | PARAMETER | 函数/闭包参数 |

---

## ClassType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `struct_item` | CLASS (type=struct) | struct 数据结构定义 |
| `enum_item` | CLASS (type=enum) | enum 枚举定义，枚举变体作为 FIELD 子节点 |
| `trait_item` | CLASS (type=interface) | trait 定义（类似接口），内部方法签名会被遍历 |
| `impl_item` | —（无节点） | impl 块作为容器，仅遍历其内部的 function_item |

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| ClassType.class | Rust 没有 `class` 关键字，使用 struct + impl 替代 |

---

## FunctionType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `function_item`（普通） | FUNCTION (type=function) | 顶层函数或关联函数（无 self） |
| `function_item`（有 self 或在 impl 内） | FUNCTION (type=method) | impl 块中的方法，或含 self 参数的函数 |
| `function_item`（名称为 `new` 或 `default`） | FUNCTION (type=constructor) | 构造器函数（按命名约定） |
| `closure_expression` | FUNCTION (type=lambda) | 闭包表达式 `|x| x + 1` |

**函数特殊处理：**
- 在 `impl` 中的函数 fullname 为 `ImplType::method_name` 格式
- 参数从 `parameters > parameter` 子节点提取，支持多种类型节点（reference_type, generic_type 等）
- 闭包参数从 `closure_parameters` 子节点提取

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| FunctionType.destructor | Rust 无析构器关键字，通过实现 `Drop` trait 实现（编译器自动调用 `drop()`） |

---

## OperatorType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `call_expression` | OPERATOR (type=call) | 普通函数调用 `foo(args)` |
| `method_call_expression` | OPERATOR (type=method_call) | 方法调用 `obj.method(args)`，AST 边 role=OPERAND 关联对象 |
| `macro_invocation` | OPERATOR (type=call) | 宏调用 `println!("...")`、`vec![...]` 等，名称带 `!` 后缀 |
| `assignment_expression` | OPERATOR (type=assign) | 赋值 `a = b`，AST 边 role=LHS/RHS |
| `compound_assignment_expression` | OPERATOR (type=aug_assign) | 复合赋值 `a += b`、`a -= b` 等 |
| `binary_expression` | OPERATOR (type=binary_op) | 二元运算，支持 `==`/`!=`/`>=`/`<=`/`>`/`<`/`&&`/`||`/`+`/`-`/`*`/`/`/`%`/`&`/`|`/`^`/`<<`/`>>` |
| `unary_expression` | OPERATOR (type=unary_op) | 一元运算，支持 `-`/`!`/`*`/`&`/`~` |
| `index_expression` | OPERATOR (type=binary_op) | 索引访问 `a[i]`，映射为二元操作 |
| `type_cast_expression` | OPERATOR (type=type_cast) | 类型转换 `expr as Type` |
| `struct_expression` | OPERATOR (type=new) | 结构体实例化 `Foo { field: value }` |
| `await_expression` | OPERATOR (type=await) | 异步等待 `.await` |
| `try_expression` | OPERATOR (type=yield) | 错误传播操作符 `?` |
| `scoped_identifier`（含 `::`） | OPERATOR (type=static_call) | 作用域路径调用如 `Type::method`、`std::io` |
| `break_expression` | OPERATOR (type=break) | break 语句（可带标签 `'label`） |
| `continue_expression` | OPERATOR (type=continue) | continue 语句（可带标签 `'label`） |

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| OperatorType.throw | Rust 无 throw 关键字，使用 `panic!` 宏或 `Result` 返回值 |
| OperatorType.goto | Rust 无 goto 语句 |

---

## BranchType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `if_expression` | BRANCH (type=if) | if 表达式，Rust 中 if 是表达式（有返回值），条件通过 AST 边 role=CONDITION 关联 |
| `else_clause`（含 block） | BRANCH (type=else) | else 分支，通过 AST 边 role=IFFALSE 关联到 if 节点 |
| `else_clause`（含 if_expression） | BRANCH (type=if, 递归) | else if 通过嵌套 `_walk_if` 递归实现 |
| `match_expression` | BRANCH (type=match) | match 表达式，匹配值通过 AST 边 role=CONDITION 关联 |
| `match_arm`（普通 pattern） | BRANCH (type=case) | match arm，通过 AST 边 role=IFTRUE 关联到 match 节点 |
| `match_arm`（`_` wildcard） | BRANCH (type=default) | match 的默认分支（wildcard pattern） |
| `for_expression` | BRANCH (type=foreach) | for 循环 `for x in iter { ... }`，Rust 只有 foreach 风格 |
| `while_expression` | BRANCH (type=while) | while 循环，条件通过 AST 边 role=CONDITION 关联 |
| `loop_expression` | BRANCH (type=while) | 无限循环 `loop { ... }`，condition 设为 `"true"` |

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| BranchType.ternary | Rust 无三元运算符，使用 `if expression` 替代 |
| BranchType.for | Rust 无 C 风格 for 循环，只有 `for...in`（foreach） |
| BranchType.switch | Rust 无 switch 语句，使用 `match expression` 替代 |
| BranchType.try | Rust 无 try 块语法，使用 `?` 操作符和 `Result`/`Option` 类型 |
| BranchType.catch | Rust 无 catch 语法，使用 `?` 传播或 `match` 处理 `Result` |
| BranchType.finally | Rust 无 finally，资源清理通过 `Drop` trait 实现 |

---

## ImportType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `use_declaration` | IMPORT (type=use) | `use` 声明，如 `use std::io`、`use crate::module::item` |

**import 路径提取：**
- 从 `scoped_identifier`、`use_list` 或 `scoped_use_list` 子节点提取路径文本
- 支持 `use path::{item1, item2}` 等多项目导入

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| ImportType.import | Rust 不使用 import 关键字，使用 `use` |
| ImportType.from_import | Rust 不使用 from import 语法 |
| ImportType.include | Rust 无 include 指令 |
| ImportType.require | Rust 无 require 关键字（这是 PHP/Ruby 概念） |
| ImportType.include_once | Rust 不支持 |
| ImportType.require_once | Rust 不支持 |

---

## IdentifierType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `identifier` | IDENTIFIER (type=variable) | 普通标识符 |
| `type_identifier` | IDENTIFIER (type=variable) | 类型名称标识符（在 struct/enum/trait/function 签名中） |
| `field_identifier`（一般上下文） | IDENTIFIER (type=variable) | 字段名标识符（通用上下文） |
| `field_identifier`（在 `field_declaration` 内） | IDENTIFIER (type=field) | struct 字段声明中的字段名 |
| `identifier`（在 `enum_variant` 内） | IDENTIFIER (type=field) | enum 变体名称 |
| `field_identifier`（在 `field_expression` 内） | IDENTIFIER (type=field) | 字段访问表达式 `a.b` 中的字段名 |
| `let_declaration` | IDENTIFIER (type=variable) | let 变量声明 |
| `parameter` | PARAMETER (type=variable) | 函数/闭包参数 |
| `self` | IDENTIFIER (type=this) | self 引用（等同于其他语言的 this） |
| `scoped_identifier`（无 `::`） | IDENTIFIER (type=static) | 简单作用域标识符 |

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| IdentifierType.property | Rust 中字段访问使用 `field_expression`（映射为 FIELD），property 概念不适用 |
| IdentifierType.global | Rust 无全局变量关键字，全局作用域通过 `pub use` 或 `pub static` 实现 |
| IdentifierType.super | Rust 无 super 关键字作为标识符（`super::` 是路径前缀，被映射为 scoped_identifier） |

---

## ConstType 映射

| Rust AST 节点 | Unified Schema | 说明 |
|----------------|---------------|------|
| `integer_literal` | CONST (type=number) | 整数（如 `42`、`0xFF`、`0o77`、`0b1111`） |
| `float_literal` | CONST (type=number) | 浮点数（如 `3.14`、`1.0f32`） |
| `string_literal` | CONST (type=string) | 字符串（如 `"hello"`、`r"raw"`、`b"bytes"`） |
| `char_literal` | CONST (type=string) | 字符（如 `'a'`） |
| `true` | CONST (type=boolean) | 布尔字面量 true |
| `false` | CONST (type=boolean) | 布尔字面量 false |

**Rust 不支持的类型：**

| Unified Schema | 说明 |
|---------------|------|
| ConstType.null | Rust 无 null 值，使用 `Option::None` 或 `Option<T>` 表示可空语义 |

---

## Edge Type Mapping

| 边类型 | Rust 中的使用场景 |
|--------|-----------------|
| OWN | file→annotation, file→import, file→class, class→field, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, method_call→object, binary→left/right, return→value, assign→lhs/rhs, match→arm, if→else |
| FRG | import→dependency（外部依赖，type=use） |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression（if/match/while/for 的条件） |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand |
| OPERAND | unary→operand, method_call→object, await→future, try→result, cast→expr |
| VALUE | return→expression, let→initializer, break/continue→label |
| LHS | assignment→left side |
| RHS | assignment→right side |
| IFTRUE | match→match_arm |
| IFFALSE | if→else |

---

## tree-sitter Rust 关键陷阱

1. **Rust 使用 `function_item` 而非 `function_declaration`** — 与 Go 的 `function_declaration` 命名不同
2. **`impl_item` 是无节点容器** — impl 块本身不生成 UnifiedNode，仅遍历内部 function_item
3. **函数类型判断需要综合信息** — constructor 需检查函数名（`new`/`default`），method 需检查 self_parameter 或 in_impl 上下文
4. **match_expression 的 arm 区分 case/default** — 通过检查 pattern 是否为 wildcard（`_`）决定使用 BranchType.CASE 或 DEFAULT
5. **`loop_expression` 映射为 BranchType.WHILE** — 因为无限循环本质上是 `while true`，condition 设为 `"true"`
6. **`try_expression` 是 `?` 操作符** — 不同于其他语言的 try/catch，Rust 的 try 节点是错误传播操作符
7. **宏调用被视为 OPERATOR.CALL** — `println!`、`vec!`、`dbg!` 等宏统一映射为 call 类型
8. **`scoped_identifier` 双重映射** — 含 `::` 的映射为 STATIC_CALL（OPERATOR），不含的映射为 STATIC（IDENTIFIER）
9. **关键字/标点是叶节点** — `"if"`、`"{"`、`"+"`、`"::"` 都是独立节点，需通过 `_SKIP_TYPES` 过滤
10. **`true`/`false` 是叶节点** — 不是 identifier，需特殊处理映射到 CONST.BOOLEAN
11. **Rust 无 null** — 不存在 null 字面量节点，需使用 `Option<T>` 类型表示可空语义
12. **`self` 是独立节点类型** — tree-sitter 将 `self` 作为特殊节点类型，映射为 IdentifierType.THIS

---

## Rust 语言特性限制总结

Rust 的语言设计与统一 Schema 之间存在一些概念差异：

| 统一 Schema 概念 | Rust 等价物 | 说明 |
|------------------|------------|------|
| `class` | `struct` + `impl` | Rust 没有类，数据和行为分离 |
| `interface` | `trait` | trait 可定义默认实现和关联类型 |
| `null` | `Option<T>` / `None` | Rust 不允许空值，通过 Option 类型系统保证安全 |
| `ternary` | `if expression` | Rust if 是表达式，可直接赋值 |
| `switch` | `match expression` | Rust match 更强大，支持模式匹配 |
| `try/catch/finally` | `Result<T,E>` / `?` / `Drop` | 错误处理通过类型系统和操作符实现 |
| `for` (C-style) | `while` + 手动控制 | Rust 只有 `for...in` 迭代器循环 |
| `goto` | 不支持 | Rust 无 goto 语句 |
| `throw` | `panic!` / `Result::Err` | panic 不可恢复，Err 通过 Result 传播 |
| `destructor` | `Drop` trait | 编译器自动调用，非显式声明 |
