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
| `operator:call` | `MethodInvocation` | `_walk_call` |
| `operator:new` | `ClassCreator` | `_walk_new` |
| `operator:assign` | `Assignment`, `LocalVariableDeclaration`, `FieldDeclaration` | `_walk_assign`, `_walk_var_decl`, `_walk_field_decl` |
| `operator:binary_op` | `BinaryOperation` | `_walk_binary` |
| `operator:member` | `MemberReference` | `_walk_member_ref` |
| `identifier:this` | `This` | 直接 emit |
| `const` | `Literal` | `_walk_literal` |
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
| `attrs.type` | 推导 | `method` / `function`(lambda) |
| `attrs.signature` | 拼接 | `"ReturnType name(ParamType param, ...)"` |
| `attrs.static` | `"static" in node.modifiers` | 是否静态方法 |

**javalang 特点**:
- `MethodDeclaration.body` 是 **list**（直接语句列表），不是 BlockStatement 包装
- `LambdaExpression.body` 可能是表达式或 block
- `ConstructorDeclaration.name` 是类名，不是 `"<init>"`

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

| 图属性 | 来源 | 说明 |
|--------|------|------|
| `attrs.type` | 推导 | `method_call`(有 qualifier) / `call`(无 qualifier) |
| `name` | 拼接 | `"qualifier.method"` 或 `"method"` |

**边**: `CALLEE`(qualifier), `CALLEE`(member identifier), `ARG`(arguments)

### 5.2 ClassCreator

`new ClassName(args)` → `operator:new`, name=`"new ClassName"`

### 5.3 BinaryOperation

`operandl OP operandr` → `operator:binary_op`, name=operator 符号

### 5.4 MemberReference

`qualifier.member` → `operator:method_call`

**javalang 特点**: `MemberReference` 还包含 `postfix_operators`（`x++`, `x--`）和 `prefix_operators`（`++x`, `--x`）。

### 5.5 Assignment

`expressionl = expressionr` → `operator:assign`

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
| this | self (identifier) | $this (variable) | ThisExpression | This 节点 |
| 构造函数 | __init__ | __construct | constructor | ConstructorDeclaration |
| 枚举 | 无 | enum (JD) | 无 | EnumDeclaration |
| 注解/装饰器 | @decorator | attribute (@) | decorator (@) | Annotation (@) |
| 修饰符 | 无 | public/private 等 | 无 | modifiers (set) |

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
