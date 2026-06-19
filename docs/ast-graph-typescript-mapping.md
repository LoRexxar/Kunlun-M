# TypeScript AST → Unified Graph Mapping

## Parser: tree-sitter-typescript (typescript)

TypeScript 使用 `tree-sitter-typescript` 的 `language_typescript()` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"function_declaration"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"{"`、`"+"` |

---

## Node Type Mapping

### Class (5 types)

| TypeScript AST Node | Unified Label | ClassType | 备注 |
|----------------------|---------------|-----------|------|
| `class_declaration` | CLASS | class | 类定义 |
| `abstract_class_declaration` | CLASS | class | 抽象类定义（映射为 class） |
| `interface_declaration` | CLASS | interface | 接口定义 |
| `enum_declaration` | CLASS | enum | 枚举定义 |
| `type_alias_declaration` | — | — | 类型别名，仅遍历子节点，不生成 CLASS 节点 |
| — | — | struct | TypeScript 无 struct |

### Import (1 type)

| TypeScript AST Node | Unified Label | ImportType | 备注 |
|----------------------|---------------|------------|------|
| `import_statement` | IMPORT | import | ES Module import |
| `import_statement` (default import) | IMPORT | import | `import X from "module"` — 生成默认 import IDENTIFIER |
| `import_statement` (named imports) | IMPORT | import | `import { A, B } from "module"` — 遍历 import_specifier |
| `import_statement` (namespace import) | IMPORT | import | `import * as NS from "module"` — 遍历 namespace_import |

import 指令通过 FRG USE 边链接到 DEPENDENCY 节点。

### Function (4 types)

| TypeScript AST Node | Unified Label | FunctionType | 备注 |
|----------------------|---------------|-------------|------|
| `function_declaration` | FUNCTION | function | 函数声明 |
| `generator_function_declaration` | FUNCTION | function | 生成器函数 `function*` |
| `async_function_declaration` | FUNCTION | function | 异步函数 `async function` |
| `arrow_function` | FUNCTION | lambda | 箭头函数 `() => expr`，name 为 `<arrow>` |
| `method_definition` | FUNCTION | method | 类方法 `foo() { }` |
| `constructor` | FUNCTION | constructor | 构造函数 |

**函数参数：** 从 `formal_parameters` 中提取 `required_parameter`、`optional_parameter`、`rest_parameter`、`parameter` 的 `identifier` 子节点，生成 PARAMETER 节点。

### Branch (10 types)

| TypeScript AST Node | Unified Label | BranchType | 备注 |
|----------------------|---------------|------------|------|
| `if_statement` | BRANCH | if | if 条件语句 |
| `for_statement` | BRANCH | for | C 风格 `for(init;cond;update)` |
| `for_in_statement` | BRANCH | foreach | `for (x in obj)` |
| `while_statement` | BRANCH | while | while 循环 |
| `do_statement` | BRANCH | while | do-while 循环（映射为 while） |
| `switch_statement` | BRANCH | switch | switch 语句 |
| `switch_case` | BRANCH | case / default | 根据 `case` vs `default` 判断 |
| `try_statement` | BRANCH | try | try 块 |
| `catch_clause` | BRANCH | catch | catch 子句，提取 catch_variable 作为 IDENTIFIER |
| `finally_clause` | BRANCH | finally | finally 子句 |
| `ternary_expression` | BRANCH | if | 三元条件 `cond ? a : b` |

### Operator (14 types)

| TypeScript AST Node | Unified Label | OperatorType | 备注 |
|----------------------|---------------|-------------|------|
| `call_expression` | OPERATOR | call | 函数调用 `foo(args)` |
| `call_member_expression` | OPERATOR | method_call | 方法调用 `obj.method(args)` |
| `new_expression` | OPERATOR | new | `new ClassName(args)` |
| `assignment_expression` | OPERATOR | assign | 赋值 `x = value` |
| `augmented_assignment_expression` | OPERATOR | aug_assign | 复合赋值 `x += 1`、`x -= 1` 等 |
| `binary_expression` | OPERATOR | binary_op | 二元运算（含 TS 特有 `??`、`**`、`in`、`instanceof`） |
| `unary_expression` | OPERATOR | unary_op | 一元运算（含 typeof、void、delete） |
| `as_expression` | OPERATOR | type_cast | TypeScript 类型断言 `expr as Type` |
| `non_null_expression` | OPERATOR | unary_op | TypeScript 非空断言 `expr!` |
| `await_expression` | OPERATOR | await | 异步等待 |
| `yield_expression` | OPERATOR | yield | 生成器 yield |
| `throw_statement` | OPERATOR | throw | 抛出异常 |
| `break_statement` | OPERATOR | break | break |
| `continue_statement` | OPERATOR | continue | continue |

### Identifier (5 types)

| TypeScript AST Node | Unified Label | IdentifierType | 备注 |
|----------------------|---------------|---------------|------|
| `identifier` | IDENTIFIER | variable | 普通标识符 |
| `property_identifier` | IDENTIFIER | variable | 属性标识符 |
| `private_property_identifier` | IDENTIFIER | variable | 私有属性 `#prop` |
| `shorthand_property_identifier` | IDENTIFIER | variable | 简写属性 `{ x }` |
| `member_expression` | IDENTIFIER | field | 成员访问 `obj.prop` |
| `this` | IDENTIFIER | this | this 关键字（在 _SKIP_TYPES 中特殊处理） |
| `super` | IDENTIFIER | super | super 关键字（在 _SKIP_TYPES 中特殊处理） |
| `import_specifier` → `identifier` | IDENTIFIER | global | 命名导入 |

### Const (6 types)

| TypeScript AST Node | Unified Label | ConstType | 备注 |
|----------------------|---------------|-----------|------|
| `number` | CONST | number | 数字 |
| `string` | CONST | string | 字符串 |
| `true` / `false` | CONST | boolean | 布尔值 |
| `null` | CONST | null | null |
| `undefined` | CONST | null | undefined（映射为 NULL） |
| `template_string` | CONST | string | 模板字符串 `` `...` `` |
| `regex` | CONST | constant | 正则表达式字面量 |

### Parameter

| TypeScript AST Node | Unified Label | 备注 |
|----------------------|---------------|------|
| `required_parameter` → `identifier` | PARAMETER | 必选参数 |
| `optional_parameter` → `identifier` | PARAMETER | 可选参数 `x?: Type` |
| `rest_parameter` → `identifier` | PARAMETER | 剩余参数 `...args` |
| `parameter` → `identifier` | PARAMETER | 通用参数节点 |

### Return

| TypeScript AST Node | Unified Label | 备注 |
|----------------------|---------------|------|
| `return_statement` | RETURN | return 语句 |

---

## Edge Type Mapping

| 边类型 | TypeScript 中的使用场景 |
|--------|-----------------------|
| OWN | file→import, file→class, file→function, class→method, class→constructor, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, binary→left/right, return→value, assign→lhs/rhs, switch→case |
| FRG | import→dependency (USE) |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand |
| VALUE | return→expression, var_decl→initializer |
| LHS | assignment→left side |
| RHS | assignment→right side |
| OPERAND | unary→operand, await→awaited, throw→exception, as→value |
| IFTRUE | switch→case |
| IFFALSE | ternary→alternate, if→else, try→catch/finally |

---

## 语言特性限制

| 统一类型 | TypeScript 支持情况 | 说明 |
|----------|--------------------|------|
| ClassType.CLASS | ✅ | class_declaration, abstract_class_declaration |
| ClassType.INTERFACE | ✅ | interface_declaration |
| ClassType.STRUCT | ❌ | TypeScript 无 struct |
| ClassType.ENUM | ✅ | enum_declaration |
| FunctionType.FUNCTION | ✅ | 函数声明 |
| FunctionType.METHOD | ✅ | method_definition |
| FunctionType.CONSTRUCTOR | ✅ | constructor |
| FunctionType.LAMBDA | ✅ | arrow_function |
| FunctionType.DESTRUCTOR | ❌ | 无析构函数 |
| OperatorType.STATIC_CALL | ❌ | 静态调用通过类名.方法（统一为 METHOD_CALL） |
| OperatorType.GOTO | ❌ | JavaScript/TypeScript 无 goto |
| BranchType.ELIF | ❌ | 使用 else if（嵌套处理） |
| BranchType.MATCH | ❌ | TypeScript 无 match 表达式 |
| ConstType.CONSTANT | ✅ | regex 字面量 |
| IdentifierType.STATIC | ❌ | 无 static 标识符类型 |
| IdentifierType.FIELD | ❌ | 无独立 field 标识符（使用 FIELD 用于成员访问） |

---

## tree-sitter TypeScript 关键陷阱

1. **大量类型语法节点需要跳过** — `type_annotation`、`type_parameter_declaration`、`type_arguments`、`type_identifier`、`generic_type`、`union_type`、`intersection_type`、`conditional_type`、`mapped_type`、`indexed_access_type`、`tuple_type`、`array_type` 等 20+ 种类型节点全部在 _SKIP_TYPES 中
2. **修饰器/访问修饰符是叶节点** — `abstract_modifier`、`readonly_modifier`、`static_modifier`、`accessibility_modifier`（public/private/protected）、`override_modifier` 在 _SKIP_TYPES 中
3. **箭头函数参数有两种形式** — 单参数省略括号 `x => x + 1`（bare identifier）和带括号 `(x, y) => ...`（formal_parameters），normalizer 分别处理
4. **非空断言 `!` 是表达式节点** — `non_null_expression`（如 `obj!.prop`），映射为 OPERATOR/UNARY_OP
5. **as 表达式是类型断言** — `as_expression`（如 `x as string`），映射为 OPERATOR/TYPE_CAST，跳过类型注解部分
6. **export_statement 在 _SKIP_TYPES 中** — 导出声明不独立处理，由内部的 class_declaration/function_declaration 等节点通过 export 修饰隐式处理
7. **implement/extends/interface/enum 等关键字在 _SKIP_TYPES 中** — 作为叶节点被跳过
8. **catch_variable 作为 IDENTIFIER 节点** — `catch (e)` 中的 `e` 被提取为 IDENTIFIER/VARIABLE 节点
9. **shorthand_property_identifier** — `{ x }` 简写属性语法中的标识符，映射为 IDENTIFIER/VARIABLE
10. **template_string 整体作为常量** — 模板字符串 `` `Hello ${name}` `` 映射为 CONST/STRING，不拆分插值表达式
11. **三元表达式的角色映射** — `ternary_expression` 的三个子节点分别映射为 CONDITION、IFTRUE、IFFALSE
12. **import_specifier 的 identifier** — 命名导入 `import { Foo } from "mod"` 中的 Foo 通过 identifier 节点识别
