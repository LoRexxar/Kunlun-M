# Kotlin AST → Unified Graph Mapping

## Parser: tree-sitter-kotlin

Kotlin 使用 `tree-sitter-kotlin` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"class_declaration"`、`"fun_declaration"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"fun"`、`"{"`、`"+"` |

---

## Node Type Mapping

### Class (5 types)

| Kotlin AST Node | Unified Label | ClassType | 备注 |
|------------------|---------------|-----------|------|
| `class_declaration` | CLASS | class | 类定义，含 primary_constructor |
| `object_declaration` | CLASS | class | Kotlin 单例对象，映射为 CLASS |
| `interface_declaration` | CLASS | interface | 接口定义 |
| `enum_declaration` | CLASS | enum | 枚举定义 |
| — | — | struct | Kotlin 无 struct |

**class_body**：遍历内部成员声明（property_declaration、fun_declaration、secondary_constructor 等）。

**secondary_constructor**：映射为 FUNCTION/CONSTRUCTOR，与 primary_constructor 独立处理。

### Import (1 type)

| Kotlin AST Node | Unified Label | ImportType | 备注 |
|------------------|---------------|------------|------|
| `import_statement` | IMPORT | import | `import package.Name` |
| `import_statement` (with `*`) | IMPORT | import | 通配符导入 |

import 指令通过 FRG USE 边链接到 FILE 节点。

### Function (5 types)

| Kotlin AST Node | Unified Label | FunctionType | 备注 |
|------------------|---------------|-------------|------|
| `fun_declaration` (top-level) | FUNCTION | function | 顶层函数 |
| `fun_declaration` (in class, non-static) | FUNCTION | method | 成员方法 |
| `fun_declaration` (companion object) | FUNCTION | function | companion object 方法 |
| `primary_constructor` | FUNCTION | constructor | 主构造函数 |
| `secondary_constructor` | FUNCTION | constructor | 次构造函数 |
| `lambda_literal` | FUNCTION | lambda | lambda 表达式 `{ x -> x + 1 }` |
| `anonymous_function` | FUNCTION | lambda | 匿名函数 `fun(x) { }` |

**函数参数：** 从 `value_parameters` 中提取 `parameter` 子节点的 `simple_identifier`，生成 PARAMETER 节点。

### Branch (8 types)

| Kotlin AST Node | Unified Label | BranchType | 备注 |
|------------------|---------------|------------|------|
| `if_expression` | BRANCH | if | if 条件表达式（Kotlin 中 if 是表达式） |
| `else` clause | BRANCH | else | else 分支 |
| `for_statement` | BRANCH | foreach | `for (x in collection)` — Kotlin for 始终是 foreach |
| `while_statement` | BRANCH | while | while 循环 |
| `do_while_statement` | BRANCH | while | do-while 循环（映射为 while） |
| `when_expression` | BRANCH | switch | Kotlin when 表达式（类似 switch） |
| `when_entry` | BRANCH | case / default | when 分支条目，else→default |
| `try_expression` | BRANCH | try | try 表达式（Kotlin 中 try 是表达式） |
| `catch_block` | BRANCH | catch | catch 块 |
| `finally_block` | BRANCH | finally | finally 块 |

### Operator (11 types)

| Kotlin AST Node | Unified Label | OperatorType | 备注 |
|------------------|---------------|-------------|------|
| `call_expression` | OPERATOR | call | 函数调用 `foo(args)` |
| `assignment` | OPERATOR | assign | 赋值 `x = value` |
| `binary_expression` | OPERATOR | binary_op | 二元运算（含 Kotlin 特有操作符 rangeTo、===、!==） |
| `prefix_expression` | OPERATOR | unary_op | 前缀一元（-, !, ++, --, +, ~） |
| `postfix_expression` | OPERATOR | unary_op | 后缀一元 |
| `throw_expression` | OPERATOR | throw | 抛出异常 |
| `return_expression` | RETURN | — | 返回语句（非 OPERATOR） |
| `break_expression` | OPERATOR | break | break |
| `continue_expression` | OPERATOR | continue | continue |
| `is_expression` | OPERATOR | binary_op | 类型检查 `x is String` |
| `as_expression` | OPERATOR | type_cast | 类型转换 `x as String` |

### Identifier (5 types)

| Kotlin AST Node | Unified Label | IdentifierType | 备注 |
|------------------|---------------|---------------|------|
| `simple_identifier` | IDENTIFIER | variable | 普通标识符 |
| `property_declaration` | IDENTIFIER | property | 属性声明 `val x / var y` |
| `this` | IDENTIFIER | this | this 关键字 |
| `super` | IDENTIFIER | super | super 关键字 |
| — | — | static | Kotlin 无 static，使用 companion object |

### Const (5 types)

| Kotlin AST Node | Unified Label | ConstType | 备注 |
|------------------|---------------|-----------|------|
| `integer_literal` | CONST | number | 整数 |
| `real_literal` | CONST | number | 浮点数 |
| `string_literal` | CONST | string | 双引号字符串 |
| `true` / `false` | CONST | boolean | 布尔值（在 _SKIP_TYPES 中特殊处理） |
| `null` | CONST | null | null 值（在 _SKIP_TYPES 中特殊处理） |

### Parameter

| Kotlin AST Node | Unified Label | 备注 |
|------------------|---------------|------|
| `parameter` (in `value_parameters`) | PARAMETER | 函数参数 |

### Return

| Kotlin AST Node | Unified Label | 备注 |
|------------------|---------------|------|
| `return_expression` | RETURN | 返回表达式 |

---

## Edge Type Mapping

| 边类型 | Kotlin 中的使用场景 |
|--------|-------------------|
| OWN | file→import, file→class, file→function, class→method, class→property, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, binary→left/right, return→value, assign→lhs/rhs, switch→case |
| FRG | file→import (USE) |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand |
| VALUE | return→expression |
| LHS | assignment→left side |
| RHS | assignment→right side |
| OPERAND | throw→exception, unary→operand |
| IFTRUE | when→case, if→then |
| IFFALSE | try→catch/finally |

---

## 语言特性限制

| 统一类型 | Kotlin 支持情况 | 说明 |
|----------|----------------|------|
| ClassType.STRUCT | ❌ | Kotlin 无 struct，只有 data class |
| FunctionType.FUNCTION | ✅ | 顶层函数、companion object 方法 |
| FunctionType.METHOD | ✅ | 类成员方法 |
| FunctionType.CONSTRUCTOR | ✅ | primary + secondary constructor |
| FunctionType.DESTRUCTOR | ❌ | Kotlin 无析构函数 |
| FunctionType.LAMBDA | ✅ | lambda_literal, anonymous_function |
| OperatorType.STATIC_CALL | ❌ | Kotlin 无 static，使用 companion object 调用 |
| OperatorType.METHOD_CALL | ❌ | Kotlin 不区分 call 和 method_call，统一为 call |
| OperatorType.NEW | ❌ | Kotlin 无 new 关键字，使用构造函数调用 |
| OperatorType.AWAIT | ❌ | Kotlin 使用协程 suspend（非 async/await 模式） |
| OperatorType.YIELD | ❌ | Kotlin 使用序列生成器（Sequence） |
| OperatorType.AUG_ASSIGN | ❌ | Kotlin 无 +=/-= 等（使用算术赋值函数） |
| OperatorType.GOTO | ❌ | Kotlin 无 goto 语句 |
| BranchType.FOR | ❌ | Kotlin for 只有 foreach 形式 |
| BranchType.ELIF | ❌ | Kotlin 使用 else if（嵌套处理） |
| BranchType.TERNARY | ❌ | Kotlin 无三元运算符，使用 if 表达式 |
| BranchType.MATCH | ❌ | 使用 when 表达式（映射为 switch/case） |
| ImportType.REQUIRE | ❌ | Kotlin 使用 import，不支持 require |
| IdentifierType.STATIC | ❌ | Kotlin 无 static |
| IdentifierType.GLOBAL | ❌ | Kotlin 顶层声明不在 import 中体现 |

---

## tree-sitter Kotlin 关键陷阱

1. **if/when/try 都是表达式** — Kotlin 中 `if_expression`、`when_expression`、`try_expression` 有返回值，normalizer 将它们映射为 BRANCH 节点
2. **object_declaration 映射为 CLASS** — Kotlin 的单例对象 `object Foo` 被映射为 CLASS/class 节点，而非特殊类型
3. **for_statement 始终是 foreach** — Kotlin 的 `for (x in collection)` 没有传统 C 风格 for 循环，全部映射为 BranchType.FOREACH
4. **fun_declaration 的上下文决定 FunctionType** — 在 class_body 内且非 static 修饰时为 METHOD，在顶层为 FUNCTION
5. **value_parameters vs parameter_list** — Kotlin 使用 `value_parameters` 作为参数容器，内部包含 `parameter` 节点
6. **simple_identifier 是标识符节点** — Kotlin 的标识符类型为 `simple_identifier`（非 `identifier`）
7. **when_expression 中 else 分支** — when_entry 中含 `else` 子节点时映射为 BranchType.DEFAULT
8. **companion object 是特殊 object_declaration** — 需要在 class_body 内部检测
9. **lambda_literal 是匿名块** — `{ x -> x + 1 }` 的参数提取需要从 lambda_parameters 中获取
10. **Kotlin 特有操作符名称** — `rangeTo`、`and`、`or`、`xor`、`shl`、`shr`、`ushr` 是独立叶节点类型
