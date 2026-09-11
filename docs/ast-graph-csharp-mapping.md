# C# AST → Unified Graph Mapping

## Parser: tree-sitter-c-sharp

C# 使用 `tree-sitter-c-sharp` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"class_declaration"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"{"`、`"+"` |

---

## Node Type Mapping

### Class (5 types)

| C# AST Node | Unified Label | ClassType | 备注 |
|-------------|---------------|-----------|------|
| `class_declaration` | CLASS | class | 类定义 |
| `interface_declaration` | CLASS | interface | 接口定义 |
| `struct_declaration` | CLASS | struct | 结构体定义 |
| `enum_declaration` | CLASS | enum | 枚举定义（枚举成员展开为 IDENTIFIER/FIELD 节点） |
| `delegate_declaration` | — | — | 委托声明，仅遍历子节点，不生成 CLASS 节点 |

**namespace_declaration**：仅作为容器，不生成节点，直接遍历内部 `declaration_list`。

### Import (1 type)

| C# AST Node | Unified Label | ImportType | 备注 |
|-------------|---------------|------------|------|
| `using_directive` | IMPORT | use | `using System.IO;` → qualified_name 提取路径 |
| `global_using_directive` | — | — | 在 _SKIP_TYPES 中，被跳过 |

using 指令通过 FRG USE 边链接到 FILE 节点。

### Function (6 types)

| C# AST Node | Unified Label | FunctionType | 备注 |
|-------------|---------------|-------------|------|
| `method_declaration` (static) | FUNCTION | function | 静态方法 |
| `method_declaration` (non-static) | FUNCTION | method | 实例方法 |
| `constructor_declaration` | FUNCTION | constructor | 构造函数 |
| `destructor_declaration` | FUNCTION | destructor | 析构函数（C# ~ClassName()） |
| `lambda_expression` | FUNCTION | lambda | Lambda 表达式 `=>` |
| `local_function_statement` | FUNCTION | function | 本地函数（嵌套在方法内） |

**函数参数：** 从 `parameter_list` 中提取 `parameter` 子节点的 `identifier`，生成 PARAMETER 节点。

### Branch (9 types)

| C# AST Node | Unified Label | BranchType | 备注 |
|-------------|---------------|------------|------|
| `if_statement` | BRANCH | if | 条件为第一个非关键字子节点 |
| `else_clause` (含 `block`) | BRANCH | else | else 分支 |
| `else_clause` (含 `if_statement`) | BRANCH | if (递归) | else if 嵌套处理 |
| `for_statement` | BRANCH | for | C 风格 `for(init;cond;update)` |
| `foreach_statement` | BRANCH | foreach | `foreach (var x in collection)` |
| `while_statement` | BRANCH | while | while 循环 |
| `do_statement` | BRANCH | while | do-while 循环（映射为 while） |
| `switch_statement` | BRANCH | switch | switch 语句 |
| `switch_section` | BRANCH | case / default | 根据 `case_pattern_clause` 中是否含 "default" 判断 |
| `try_statement` | BRANCH | try | try 块 |
| `catch_clause` | BRANCH | catch | catch 子句 |
| `finally_clause` | BRANCH | finally | finally 子句 |

### Operator (14+ types)

| C# AST Node | Unified Label | OperatorType | 备注 |
|-------------|---------------|-------------|------|
| `invocation_expression` (identifier callee) | OPERATOR | call | 普通函数调用 |
| `invocation_expression` (member_access callee) | OPERATOR | method_call | 方法调用 |
| `object_creation_expression` | OPERATOR | new | `new ClassName()` |
| `assignment_expression` (=) | OPERATOR | assign | 普通赋值 |
| `assignment_expression` (+=, -=, etc.) | OPERATOR | aug_assign | 复合赋值 |
| `binary_expression` | OPERATOR | binary_op | 二元运算 |
| `prefix_unary_expression` | OPERATOR | unary_op | 前缀一元（!, -, ++, --, *, ~） |
| `postfix_unary_expression` | OPERATOR | unary_op | 后缀一元（++, --） |
| `cast_expression` | OPERATOR | type_cast | 类型转换 `(Type)expr` |
| `await_expression` | OPERATOR | await | await 异步等待 |
| `yield_statement` | OPERATOR | yield | yield return / yield break |
| `throw_statement` / `throw_expression` | OPERATOR | throw | 抛出异常 |
| `break_statement` | OPERATOR | break | break |
| `continue_statement` | OPERATOR | continue | continue |
| `goto_statement` | OPERATOR | goto | goto 跳转 |
| `member_access_expression` | IDENTIFIER | property | 属性访问 a.b |

### Identifier (6 types)

| C# AST Node | Unified Label | IdentifierType | 备注 |
|-------------|---------------|---------------|------|
| `identifier` | IDENTIFIER | variable | 普通标识符 |
| `generic_name` | IDENTIFIER | variable | 泛型标识符 `List<int>` |
| `qualified_name` | IDENTIFIER | variable | 限定名 `System.IO.File` |
| `this` | IDENTIFIER | this | this 关键字 |
| `base` | IDENTIFIER | super | base 关键字 |
| `property_declaration` | IDENTIFIER | property | 属性声明 |
| `field_declaration` → `variable_declarator` | IDENTIFIER | field | 字段声明 |
| `local_variable_declaration` → `variable_declarator` | IDENTIFIER | variable | 局部变量声明 |
| `enum_member_declaration` | IDENTIFIER | field | 枚举成员 |

### Const (6 types)

| C# AST Node | Unified Label | ConstType | 备注 |
|-------------|---------------|-----------|------|
| `integer_literal` | CONST | number | 整数 |
| `real_literal` | CONST | number | 浮点数 |
| `string_literal` | CONST | string | 双引号字符串 |
| `character_literal` | CONST | string | 字符 |
| `true` / `false` | CONST | boolean | 布尔值（在 _SKIP_TYPES 中，被特殊处理） |
| `null_literal` | CONST | null | 空值 |
| `interpolated_string_expression` | CONST | string | 插值字符串 `$"..."`，整体作为常量 |
| `default_expression` | CONST | constant | `default` 表达式 |

### Parameter

| C# AST Node | Unified Label | 备注 |
|-------------|---------------|------|
| `parameter` (in `parameter_list`) | PARAMETER | 函数参数，含 ref/out/params 修饰 |

### Return

| C# AST Node | Unified Label | 备注 |
|-------------|---------------|------|
| `return_statement` | RETURN | return 语句 |

---

## Edge Type Mapping

| 边类型 | C# 中的使用场景 |
|--------|----------------|
| OWN | file→import, file→class, class→method, class→property, class→field, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, binary→left/right, return→value, assign→lhs/rhs, if→else |
| FRG | file→import (USE) |
| MEMBER | — |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand |
| VALUE | return→expression, unary→operand, throw→exception |
| LHS | assignment→left side |
| RHS | assignment→right side |
| OPERAND | await→awaited, cast→casted |
| IFTRUE | switch→case |
| IFFALSE | if→else, try→catch |

---

## 语言特性限制

| 统一类型 | C# 支持情况 | 说明 |
|----------|------------|------|
| ClassType.CLASS | ✅ | class_declaration |
| ClassType.INTERFACE | ✅ | interface_declaration |
| ClassType.STRUCT | ✅ | struct_declaration |
| ClassType.ENUM | ✅ | enum_declaration |
| FunctionType.FUNCTION | ✅ | 静态方法、本地函数 |
| FunctionType.METHOD | ✅ | 实例方法 |
| FunctionType.CONSTRUCTOR | ✅ | constructor_declaration |
| FunctionType.DESTRUCTOR | ✅ | destructor_declaration |
| FunctionType.LAMBDA | ✅ | lambda_expression |
| OperatorType.STATIC_CALL | ❌ | C# 无独立静态调用语法，统一为 call |
| BranchType.ELIF | ❌ | C# 使用 else if（嵌套处理） |
| BranchType.TERNARY | ❌ | conditional_expression 未独立映射 |
| BranchType.MATCH | ❌ | C# 使用 switch/pattern matching |
| ImportType.REQUIRE | ❌ | C# 使用 using，不支持 require |
| ConstType.CONSTANT | ✅ | default_expression |

---

## tree-sitter C# 关键陷阱

1. **expression_statement 是透明包装** — `expression_statement` 内部嵌套实际的表达式节点（invocation_expression、assignment_expression 等），normalizer 递归进入内部节点
2. **namespace_declaration 不生成节点** — 仅作为容器遍历内部 declaration_list，不创建 CLASS 节点
3. **interpolated_string_expression 整体作为常量** — `$"Hello {name}"` 被映射为单个 CONST/STRING，不拆分插值部分
4. **declaration_list 是容器节点** — 在 _SKIP_TYPES 中，不生成节点
5. **modifier 关键字（public/private/static 等）是独立叶节点** — 需要在子节点中遍历检测，用于区分 method vs function
6. **type_parameter / type_argument / type_annotation 全部跳过** — 泛型参数、类型注解等类型语法节点在 _SKIP_TYPES 中
7. **accessor_declaration / accessor_list 跳过** — 属性的 get/set 访问器列表在 _SKIP_TYPES 中
8. **true/false/null 在 _SKIP_TYPES 中** — 作为关键字叶节点被特殊处理映射到 CONST 节点
9. **variable_declarator 在 _SKIP_TYPES 中** — 作为字段和局部变量声明的子节点，被上层处理直接遍历
10. **qualified_name / generic_name 是标识符变体** — 均映射为 IDENTIFIER/VARIABLE
