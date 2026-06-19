# Java AST → 图节点映射表

> 本文档描述 javalang AST 节点类型到统一图结构的映射规则。
> 基于 `core/graph/normalizers/java/normalizer.py`。
> **必须与代码同步维护**。

---

## 1. 映射分类总览

| 图标签 | javalang AST 节点类型集合 | Normalizer 方法 |
|--------|--------------------------|-----------------|
| `class` | `ClassDeclaration`, `EnumDeclaration`, `InterfaceDeclaration`, `RecordDeclaration` | `_walk_class` |
| `function` | `MethodDeclaration`, `ConstructorDeclaration`, `LambdaExpression` | `_walk_function` |
| `parameter` | `FormalParameter`（通过 MethodDeclaration.parameters） | `_walk_parameter` |
| `import` | `Import` | `_walk_import` |
| `branch:if` | `IfStatement` | `_walk_if` |
| `branch:else` | `IfStatement.else_statement`（非 IfStatement 时） | `_walk_if` 内部生成 |
| `branch:ternary` | `TernaryExpression` | `_walk_ternary` |
| `branch:for` | `ForStatement`（ForControl） | `_walk_for` |
| `branch:foreach` | `ForStatement`（EnhancedForControl） | `_walk_for` 内部判断 |
| `branch:while` | `WhileStatement`, `DoStatement` | `_walk_while`, `_walk_do_while` |
| `branch:switch` | `SwitchStatement` | `_walk_switch` |
| `branch:case` | `SwitchStatementCase`（有 case 值） | `_walk_switch` 内部生成 |
| `branch:default` | `SwitchStatementCase`（无 case 值） | `_walk_switch` 内部生成 |
| `branch:try` | `TryStatement` | `_walk_try` |
| `branch:catch` | `CatchClause` | `_walk_catch` |
| `branch:finally` | `TryStatement.finally_block` | `_walk_try` 内部生成 |
| `operator:call` | `MethodInvocation`（无 qualifier） | `_walk_call` |
| `operator:method_call` | `MethodInvocation`（有 qualifier 节点） | `_walk_call` |
| `operator:static_call` | `MethodInvocation`（qualifier 为类型名字符串，如 `Class.method()`） | `_walk_call` |
| `operator:new` | `ClassCreator` | `_walk_new` |
| `operator:assign` | `Assignment`, `LocalVariableDeclaration` | `_walk_assign`, `_walk_var_decl` |
| `operator:binary_op` | `BinaryOperation` | `_walk_binary` |
| `operator:unary_op` | `Literal`/`MemberReference`（有 prefix/postfix operators，如 `!x`/`x++`） | `_walk_literal`, `_walk_member_ref` |
| `operator:type_cast` | `Cast`（如 `(Type)expr`） | `_walk_cast` |
| `operator:member` | `MemberReference`（无 prefix/postfix operators） | `_walk_member_ref` |
| `identifier:this` | `This` | 直接 emit |
| `identifier:super` | `SuperMethodInvocation`/`SuperConstructorInvocation` 中的 `super` 关键字 | `_walk_super_call` |
| `identifier:field` | `FieldDeclaration`（class 成员变量） | `_walk_field_decl` |
| `const` | `Literal`（string / number / boolean / **null**） | `_walk_literal` |
| `return` | `ReturnStatement` | `_walk_return` |
| `operator:throw` | `ThrowStatement` | `_walk_throw` |
| `operator:break` | `BreakStatement` | `_walk_break` |
| `operator:continue` | `ContinueStatement` | `_walk_continue` |
| `operator:yield` | `YieldStatement` | `_walk_yield` |
| `annotation` | `Annotation` | `_walk_annotation` |

---

## 2. Class 节点

**源节点**: `ClassDeclaration` / `EnumDeclaration` / `InterfaceDeclaration` / `RecordDeclaration`

| 图属性 | 来源 | 说明 |
|--------|------|------|
| `label` | 固定 | `class` |
| `name` | `node.name` | 类名 |
| `attrs.fullname` | `node.name` | 同 name |
| `attrs.type` | 推导 | `class` / `interface` / `enum` |
| `attrs.raw_type` | `type(node).__name__` | 原 AST 类型 |

**边**:
- `CRG(extends)`: `node.extends` → ReferenceType → 创建外部 class 节点
- `CRG(implements)`: `node.implements` → 每个创建外部 interface 节点
- `OWN`: 内部 body（methods, fields, inner classes）

---

## 3. Function 节点

**源节点**: `MethodDeclaration` / `ConstructorDeclaration` / `LambdaExpression`

| 图属性 | 来源 | 说明 |
|--------|------|------|
| `label` | 固定 | `function` |
| `name` | `node.name` / `"<lambda>"` | 方法名 |
| `attrs.fullname` | 同 name | |
| `attrs.type` | 推导 | `method`(MethodDeclaration) / `constructor`(ConstructorDeclaration) / `lambda`(LambdaExpression) |
| `attrs.signature` | 拼接 | `"ReturnType name(ParamType param, ...)"` |
| `attrs.static` | `"static" in node.modifiers` | 是否静态方法 |

**javalang 特点**:
- `MethodDeclaration.body` 是 **list**（直接语句列表），不是 BlockStatement 包装
- `LambdaExpression.body` 可能是表达式或 block
- `ConstructorDeclaration.name` 是类名，不是 `"<init>"`

**函数类型细分**（`attrs.type`）:
| attrs.type 值 | 源 AST 节点 | 对应 FunctionType 枚举 |
|---------------|-------------|----------------------|
| `method` | `MethodDeclaration` | `FunctionType.METHOD` |
| `constructor` | `ConstructorDeclaration` | `FunctionType.CONSTRUCTOR` |
| `lambda` | `LambdaExpression` | `FunctionType.LAMBDA` |

---

## 4. Branch 节点（branch_constraint）

### 4.1 IfStatement（if / elif / else）

```
IfStatement:
  condition: BinaryOperation     → CONDITION 边
  then_statement: BlockStatement → OWN 子节点
  else_statement: IfStatement    → 递归处理（elif）
  else_statement: BlockStatement → 生成 <else> 节点（IFFALSE 边）
```

**elif 处理**: 如果 `else_statement` 是 `IfStatement`，递归处理为 elif 链。

### 4.2 TernaryExpression

```
TernaryExpression:
  condition  → CONDITION 边
  if_true    → IFTRUE 边
  if_false   → IFFALSE 边
```

### 4.3 ForStatement（for / for-each）

```
ForStatement:
  control: ForControl          → branch:for
    init       → LHS 边
    condition  → CONDITION 边
    update[]   → RHS 边
  control: EnhancedForControl  → branch:foreach
    var        → LHS 边
    iterable   → RHS 边
```

**javalang 特点**: `ForControl` vs `EnhancedForControl` 通过 `type(control).__name__` 区分。

### 4.4 WhileStatement / DoStatement

```
WhileStatement: condition → CONDITION 边, body → OWN 子节点
DoStatement:    body 先走, condition 后走 (do-while 语义)
```

### 4.5 SwitchStatement

```
SwitchStatement:
  expression → CONDITION 边
  cases[]:
    case=[val1, val2]  → branch:case (name=expr_text)
    case=[]            → branch:default (name="<default>")
```

**javalang 特点**: `SwitchStatementCase.case` 是 **list**（Java 支持多值 case 如 `case A, B:`）。

### 4.6 TryStatement

```
TryStatement:
  block          → OWN 子节点 (index 0)
  catches[]      → 每个 catch: CatchClause → OWN 子节点
    parameter.name    → exception_name
    parameter.types[] → exception_type
    block             → OWN 子节点
  finally_block  → <finally> → OWN 子节点
```

---

## 5. Operator 节点

### 5.1 MethodInvocation

`MethodInvocation` 根据 qualifier 类型细分为三种 operator:

| 图属性 `attrs.type` | 条件 | 示例 |
|---------------------|------|------|
| `call` | 无 qualifier | `method()` |
| `method_call` | qualifier 为 AST 节点（表达式） | `obj.method()` |
| `static_call` | qualifier 为字符串（类型名） | `Class.method()` |

**边**: `CALLEE`(qualifier), `CALLEE`(member identifier), `ARG`(arguments)

### 5.2 ClassCreator

`new ClassName(args)` → `operator:new`, name=`"new ClassName"`

### 5.3 BinaryOperation

`operandl OP operandr` → `operator:binary_op`, name=operator 符号

### 5.4 MemberReference

`qualifier.member` → 根据 prefix/postfix operators 存在与否，映射为 `operator:unary_op` 或 `operator:method_call`:

| 图属性 `attrs.type` | 条件 | 示例 |
|---------------------|------|------|
| `method_call` | 无 prefix/postfix operators | `obj.field` |
| `unary_op` | 有 prefix/postfix operators | `x++`, `++x`, `x--`, `--x` |

**javalang 特点**: `MemberReference` 包含 `postfix_operators`（`x++`, `x--`）和 `prefix_operators`（`++x`, `--x`）。

### 5.5 Assignment

`expressionl = expressionr` → `operator:assign`

### 5.6 一元运算符 (unary_op)

**来源**: `Literal` 或 `MemberReference` 带有 prefix/postfix operators

| AST 节点 | 示例 | 映射 |
|----------|------|------|
| `Literal`（prefix） | `!true`, `-1` | `operator:unary_op` |
| `MemberReference`（prefix/postfix） | `++x`, `x--` | `operator:unary_op` |

**javalang 特点**: javalang 不提供独立的 UnaryExpression 节点，一元运算符作为 Literal/MemberReference 的 `prefix_operators` 或 `postfix_operators` 附加。

### 5.7 类型转换 (type_cast)

**源节点**: `Cast`

`(Type) expression` → `operator:type_cast`, name=`"(Type)"`

**边**: `AST(role=RIGHT)` 指向被转换的表达式。

### 5.8 Super 标识符 (identifier:super)

**来源**: `SuperMethodInvocation` / `SuperConstructorInvocation`

`super.method()` / `super()` 调用中，`super` 关键字被提取为独立的 `identifier` 节点，`attrs.type` = `super`。

**边**: `AST(role=CALLEE)` 从 super 调用节点指向 super 标识符节点。

### 5.9 Field 标识符 (identifier:field)

**源节点**: `FieldDeclaration`（class 成员变量）

`FieldDeclaration` 中的每个 declarator 映射为独立的 `identifier` 节点（而非 `operator:assign`），`attrs.type` = `field`。

**边**: `OWN`（从 class 节点）, `AST(role=VALUE)`（若有初始化表达式）。

### 5.10 null 常量 (const:null)

**源节点**: `Literal`（value 为 `"null"`）

Java `null` 字面量映射为 `const` 节点，`attrs.type` = `null`。与其他 const 类型（string / number / boolean）并列。

---

## 6. 与 Python / PHP / JS 的差异

| 特性 | Python | PHP | JS (esprima) | Java (javalang) |
|------|--------|-----|-------------|----------------|
| 解析器 | ast 模块 | phply | esprima | javalang |
| 位置信息 | `.lineno` | `.lineno` | `.loc.start.line` | `.position.line` |
| 函数体 | list of stmts | Block node list | BlockStatement | **直接 list** |
| switch case 值 | 标量 | 标量 | 标量 | **list**（支持多值） |
| for-each | 无 | foreach | ForOfStatement | EnhancedForControl |
| elif | Elif 关键字 | elseif | else if 嵌套 | else if 嵌套 |
| 函数类型 | FunctionDef/Async | function | FunctionDeclaration/Expression | Method/Constructor/Lambda |
| 匿名函数 | lambda | closure | ArrowFunctionExpression | LambdaExpression |
| this/self | self (identifier) | $this (variable) | ThisExpression | This 节点 |
| 构造函数 | __init__ | __construct | constructor | ConstructorDeclaration |
| 枚举 | 无 | enum (JD) | 无 | EnumDeclaration |
| 注解/装饰器 | @decorator | attribute (@) | decorator (@) | Annotation (@) |
| 修饰符 | 无 | public/private 等 | 无 | modifiers (set) |
| 静态方法调用 | 无特殊 | `::` 运算符 | 无特殊 | **static_call**（qualifier 为类型名） |
| 一元运算符 | UnaryOp 节点 | 前缀/后缀运算符 | UnaryExpression | **附加在 Literal/MemberReference 上** |
| 类型转换 | 无特殊 | 无特殊 | 无特殊 | **Cast 节点 → type_cast** |
| super 关键字 | super() | parent:: | super | **Super 标识符节点** |
| null 字面量 | None | null | null/null | **const:null** |
| 类成员变量 | 无特殊 | 无特殊 | 无特殊 | **identifier:field**（非 assign） |

---

## 7. javalang 关键注意事项

1. **SwitchStatementCase.case 是 list**: Java 语法支持 `case A, B:` 多值匹配
2. **ForControl vs EnhancedForControl**: 普通 for 和 for-each 共用 ForStatement 节点，通过 control 类型区分
3. **Method body 是 list**: 不像其他语言有 BlockStatement 包装
4. **位置在 .position.line**: 不是 `.lineno`
5. **Literal.value 直接是 Python 类型**: 字符串值是 `str`，数字是 `int`/`float`
6. **Modifiers 是 set**: `{"public", "static", "final"}` 等
7. **ReferenceType 用于 extends/implements**: 不是简单的字符串
8. **Assignment 是独立节点**: 有 `expressionl` 和 `expressionr` 属性
9. **MethodInvocation.qualifier 类型区分静态调用**: qualifier 为 `str`（类型名）→ `static_call`；qualifier 为 AST 节点 → `method_call`；无 qualifier → `call`
10. **一元运算符无独立 AST 节点**: `prefix_operators`/`postfix_operators` 附加在 Literal 或 MemberReference 上，需在 Normalizer 中检测并映射为 `unary_op`
11. **类型转换有独立 Cast 节点**: `(Type)expr` → `operator:type_cast`
12. **Super 关键字作为独立标识符**: `SuperMethodInvocation`/`SuperConstructorInvocation` 中的 `super` 提取为 `identifier:super`
13. **FieldDeclaration 映射为 identifier:field**: 类成员变量不再映射为 `operator:assign`，而是 `identifier` 节点，`attrs.type` = `field`
14. **null 是 const 子类型**: `Literal` 值为 `"null"` 时，`attrs.type` = `null`
15. **函数类型三分**: `ConstructorDeclaration` → `constructor`，`LambdaExpression` → `lambda`，`MethodDeclaration` → `method`
