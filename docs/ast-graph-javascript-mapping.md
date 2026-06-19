# JavaScript AST → 图节点映射表

> 本文档描述 esprima AST 节点类型到统一图结构的映射规则。
> 基于 `core/graph/normalizers/javascript/normalizer.py`。
> **必须与代码同步维护**。

---

## 1. 映射分类总览

| 图标签 | esprima AST 节点类型集合 | Normalizer 方法 |
|--------|----------------------|-----------------|
| file | （顶层入口，非 esprima 节点） | `normalize()` |
| class | `ClassDeclaration`, `ClassExpression` | `_walk_class()` |
| function | `FunctionDeclaration`, `FunctionExpression`, `ArrowFunctionExpression`, `AsyncFunctionDeclaration`, `AsyncFunctionExpression`, `AsyncArrowFunctionExpression` | `_walk_function()` |
| parameter | 函数 `params` 中的 Identifier / AssignmentPattern / RestElement / ObjectPattern / ArrayPattern | `_walk_parameter()` |
| return | `ReturnStatement` | `_walk_return()` |
| branch | `IfStatement`, `ConditionalExpression`, `ForStatement`, `WhileStatement`, `DoWhileStatement`, `ForInStatement`, `ForOfStatement`, `SwitchStatement`, `SwitchCase`, `TryStatement`, `CatchClause` | 各 `_walk_*()` 方法 |
| operator | `CallExpression`, `NewExpression`, `AssignmentExpression`, `BinaryExpression`, `LogicalExpression`, `UnaryExpression`, `UpdateExpression`, `ThrowStatement`, `BreakStatement`, `ContinueStatement`, `YieldExpression`, `AwaitExpression`, `VariableDeclaration` | 各 `_walk_*()` 方法 |
| operator | `StaticMemberExpression`, `ComputedMemberExpression` | `_walk_member()` |
| identifier | `Identifier`, `PrivateIdentifier` | `_walk_identifier()` |
| identifier | `ThisExpression`, `Super`, `MetaProperty` | `_emit_identifier()` |
| const | `StringLiteral`, `NumericLiteral`, `BooleanLiteral`, `NullLiteral`, `RegExpLiteral`, `TemplateLiteral` | `_walk_literal()`, `_walk_template()` |
| import | `ImportDeclaration`, `ExportNamedDeclaration`, `ExportDefaultDeclaration`, `ExportAllDeclaration` | `_walk_import()` |

**透明节点**（不创建独立图节点，直接 walk 子节点）：

| esprima AST 节点类型 | 处理方式 |
|---------------------|---------|
| `BlockStatement` | 直接 walk `.body` 列表 |
| `ExpressionStatement` | 直接 walk `.expression` |
| `SequenceExpression` | 依次 walk `.expressions` 列表 |
| `SpreadElement` | 直接 walk `.argument` |
| `ChainExpression` | 直接 walk `.expression` |
| `LabeledStatement` | 直接 walk `.body` |
| `EmptyStatement` | 跳过 |
| `DebuggerStatement` | 跳过 |

**模式节点**（解构赋值/参数）：

| esprima AST 节点类型 | 处理方式 |
|---------------------|---------|
| `ObjectPattern` | 提取 properties 中的 identifier |
| `ArrayPattern` | 提取 elements 中的 identifier |
| `AssignmentPattern` | walk `.left`（默认值 walk `.right`） |
| `RestElement` | walk `.argument` |

---

## 2. Class 节点映射

### `_walk_class()`

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|-------------|-------------|-------------|--------|--------|-----------|
| `ClassDeclaration` | class | `class` | 类名 | fullname, raw_type, async=False | own→ method/property; CRG→ parent class |
| `ClassExpression` | class | `class` | 类名（或 `<anonymous>`） | 同上 | 同上 |

**继承关系：**
- `extends SuperClass` → 创建外部 class 节点 + `CRG[type=extends]` 边
- decorators 通过 own 边连接

---

## 3. Function 节点映射

### `_walk_function()`

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `FunctionDeclaration` | function | `function` | 函数名 | fullname, signature, async=False | own→ parameter, body |
| `FunctionExpression` | function | `function` | 函数名（或 `<anonymous>`） | 同上 | 同上 |
| `ArrowFunctionExpression` | function | `lambda` | `<ArrowFunction>` | async=False | own→ parameter, body(可能是表达式) |
| `AsyncFunctionDeclaration` | function | `function` | 函数名 | async=True | 同上 |
| `AsyncFunctionExpression` | function | `function` | 函数名（或 `<anonymous>`） | async=True | 同上 |
| `AsyncArrowFunctionExpression` | function | `lambda` | `<ArrowFunction>` | async=True | 同上 |

**Arrow 函数注意：** body 可能是表达式（非 BlockStatement），直接 walk 该表达式。

---

## 4. Parameter 节点映射

### `_walk_parameter()`

| esprima 类型 | graph label | graph `type` | `name` | 处理方式 |
|-------------|-------------|-------------|--------|---------|
| `Identifier` | parameter | `variable` | 参数名 | 直接创建 parameter 节点 |
| `AssignmentPattern` | parameter | `variable` | 左侧参数名 | walk `.left` |
| `RestElement` | parameter | `variable` | 参数名 | walk `.argument` |
| `ObjectPattern` | parameter | `variable` | `<destructured>` | 作为整体创建 |
| `ArrayPattern` | parameter | `variable` | `<destructured_array>` | 作为整体创建 |

---

## 5. Import 节点映射

### `_walk_import()`

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `ImportDeclaration` | import | `import` | 模块路径 | source=模块路径 | FRG→ dependency 节点 |
| `ExportNamedDeclaration` | import | `from_import` | `export` / `export <source>` | source | FRG→ dependency（如有 source） |
| `ExportDefaultDeclaration` | import | `from_import` | `export default` | — | walk declaration |
| `ExportAllDeclaration` | import | `from_import` | `export * <source>` | source | — |

**Specifier 处理：** `ImportSpecifier`、`ImportDefaultSpecifier`、`ImportNamespaceSpecifier`、`ExportSpecifier` 作为子节点 walk。

---

## 6. Branch 节点映射

### `_walk_if()` — IfStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `IfStatement` | branch | `if` | 条件文本 | condition, raw_type=IfStatement | ast[condition] → test |
| elif（嵌套 If） | branch | `if` | elif 条件 | condition, raw_type=IfStatement | 同上，own 连接到父 if |
| else（alternate 非 If） | branch | `else` | `<else>` | condition=空, raw_type=Else | ast[iffalse] 连接到父 if |

**结构规则：**
- consequent body 通过 `ctx_stack` own 连接到 if branch
- elif 作为嵌套 If 处理，own 连接到父 if
- else 通过 `ast[role=iffalse]` 边连接到父 if，else body 通过 own 连接到 else branch

### `_walk_ternary()` — ConditionalExpression

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `ConditionalExpression` | branch | `ternary` | 条件文本 | condition, raw_type=ConditionalExpression | ast[condition] → test; ast[iftrue] → consequent; ast[iffalse] → alternate |

### `_walk_for()` — ForStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `ForStatement` | branch | `for` | `<for>` | condition=test文本, raw_type=ForStatement | ast[lhs] → init; ast[condition] → test; ast[rhs] → update; own→ body |

### `_walk_while()` — WhileStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `WhileStatement` | branch | `while` | 条件文本 | condition, raw_type=WhileStatement | ast[condition] → test; own→ body |

### `_walk_do_while()` — DoWhileStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `DoWhileStatement` | branch | `while` | `<do-while>` | condition, raw_type=DoWhileStatement | own→ body; ast[condition] → test |

### `_walk_for_in()` — ForInStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `ForInStatement` | branch | `foreach` | `<for-in>` | condition=空, raw_type=ForInStatement | ast[lhs] → left; ast[rhs] → right; own→ body |

### `_walk_for_of()` — ForOfStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `ForOfStatement` | branch | `foreach` | `<for-of>` | condition=空, raw_type=ForOfStatement | ast[lhs] → left; ast[rhs] → right; own→ body |

### `_walk_switch()` — SwitchStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `SwitchStatement` | branch | `switch` | `switch subject` | condition=subject文本, raw_type=SwitchStatement | ast[condition] → discriminant; own→ case/default |
| `SwitchCase`(有 test) | branch | `case` | test 文本 | condition=test文本, raw_type=SwitchCase | ast[condition] → test; own→ body |
| `SwitchCase`(无 test) | branch | `default` | `<default>` | condition=空, raw_type=SwitchCase | own→ body |

**⚠️ esprima 陷阱：** switch case 的 `test` 被解析为 `StringLiteral`（如 `case 1:` 的 `1` 是 StringLiteral，raw=`'1'`）。`_expr_text` 优先使用 `raw` 属性返回源码文本。

### `_walk_try()` — TryStatement

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `TryStatement` | branch | `try` | `<try>` | raw_type=TryStatement | own→ body; own→ catch; own→ finally |
| `CatchClause` | branch | `catch` | `catch exc_name` | condition=异常名, exception_name, raw_type=CatchClause | ast[lhs] → param; own→ body |
| `Finally` | branch | `finally` | `<finally>` | raw_type=Finally | own→ body |

---

## 7. Operator 节点映射

### CallExpression (`_walk_call()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `CallExpression` | operator | `call` | callee 文本 | raw_type=CallExpression, optional | ast[callee] → callee; ast[arg, arg_index=N] → arguments |

**callee 类型判断：**
- `StaticMemberExpression` callee → type 改为 `method_call`
- `Super` callee → type 改为 `method_call`

### NewExpression (`_walk_new()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `NewExpression` | operator | `new` | callee 文本 | raw_type=NewExpression | ast[callee] → callee; ast[arg] → arguments |

### AssignmentExpression (`_walk_assign()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `AssignmentExpression` (`=`) | operator | `assign` | `=` | raw_type=AssignmentExpression | ast[lhs] → left; ast[rhs] → right |
| `AssignmentExpression` (其他) | operator | `aug_assign` | 操作符（如 `+=`） | operator, raw_type=AssignmentExpression | 同上 |

### BinaryExpression / LogicalExpression (`_walk_binary()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `BinaryExpression` | operator | `binary_op` | 操作符符号（如 `+`, `===`） | operator, raw_type=BinaryExpression | ast[left] → left; ast[right] → right |
| `LogicalExpression` | operator | `binary_op` | 操作符符号（`&&`, `||`, `??`） | operator, raw_type=LogicalExpression | ast[left] → left; ast[right] → right |

**⚠️ 关键约定：** `name` 是操作符符号，analyzer 的约束检查直接匹配 `name`。

### UnaryExpression (`_walk_unary()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `UnaryExpression` | operator | `unary_op` | `prefix/unfix op`（如 `!x`, `x++`） | operator, prefix, raw_type=UnaryExpression | ast[operand] → argument |

### UpdateExpression (`_walk_update()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `UpdateExpression` | operator | `unary_op` | `prefix/postfix ++/--` | operator, prefix, raw_type=UpdateExpression | ast[operand] → argument |

### VariableDeclaration (`_walk_var_decl()`)

| esprima 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-------------|-------------|-------------|--------|--------|--------|
| `VariableDeclaration` | operator | `assign` | `var`/`let`/`const` | raw_type=VariableDeclaration | ast[rhs] → each declarator |

### 其他 Operator

| esprima 类型 | graph label | graph `type` | `name` |
|-------------|-------------|-------------|--------|
| `ReturnStatement` | return | — | `<return>` |
| `ThrowStatement` | operator | `throw` | `<throw>` |
| `BreakStatement` | operator | `break` | `<break>` |
| `ContinueStatement` | operator | `continue` | `<continue>` |
| `YieldExpression` | operator | `yield` | `yield` / `yield*` |
| `AwaitExpression` | operator | `await` | `<await>` |

---

## 8. Member 访问映射

### `_walk_member()`

| esprima 类型 | graph label | graph `type` | `name` | member 边 |
|-------------|-------------|-------------|--------|-----------|
| `StaticMemberExpression` | operator | `method_call` | `obj.prop` | obj → member[property] → pos |
| `ComputedMemberExpression` | operator | `method_call` | `obj[prop]` | obj → member[array_offset] → pos |

**示例：** `console.log(msg)`
```
identifier(name=console) --member[property]--> operator(name=console.log, type=method_call) --ast[callee]--> ...
```

---

## 9. Identifier / Const 节点映射

### Identifier (`_walk_identifier()`)

| esprima 类型 | graph label | graph `type` | `name` |
|-------------|-------------|-------------|--------|
| `Identifier` | identifier | `variable` | 变量名 |

### 特殊 Identifier

| esprima 类型 | graph label | graph `type` | `name` |
|-------------|-------------|-------------|--------|
| `ThisExpression` | identifier | `this` | `this` |
| `Super` | identifier | `super` | `super` |
| `PrivateIdentifier` | identifier | `property` | `#name` |
| `MetaProperty` | identifier | `property` | `new.target` / `import.meta` |

### Literal (`_walk_literal()`)

| esprima 类型 | graph label | graph `type` | `name` |
|-------------|-------------|-------------|--------|
| `StringLiteral` | const | `string` | raw 值（如 `'hello'`） |
| `NumericLiteral` | const | `number` | raw 值（如 `42`） |
| `BooleanLiteral` | const | `boolean` | `true` / `false` |
| `NullLiteral` | const | `null` | `null` |
| `RegExpLiteral` | const | `constant` | raw 值（如 `/pattern/`） |

**⚠️ esprima 特殊行为：** `NumericLiteral.raw` 对于整数可能返回带引号的字符串（如 `1` 的 raw 是 `'1'`）。`_expr_text()` 优先使用 `raw` 属性返回源码文本。

### TemplateLiteral (`_walk_template()`)

| esprima 类型 | graph label | graph `type` | `name` |
|-------------|-------------|-------------|--------|
| `TemplateLiteral` | const | `string` | `` `quasis text` `` |

仅提取 quasis（静态部分），忽略 expressions（动态插值）。

---

## 10. 与 Python / PHP Normalizer 的关键差异

### 10.1 AST 解析器差异

| | Python | PHP | JavaScript |
|---|---|---|---|
| 解析器 | stdlib `ast` 模块 | phply | esprima（Python 包装） |
| 调用方式 | `ast.parse(source)` | `phpparse.parse(source)` | `esprima.parse(source, {"loc": True})` |
| AST 入口 | `Module` / `Interactive` | 顶层 node 列表 | `Module`（有 `.body` 列表） |
| 位置信息 | `.lineno` / `.end_lineno` | 无内置，需额外处理 | `.loc.start.line` / `.loc.end.line` |

### 10.2 Operator `name` 规范

| 操作符类型 | PHP (phply) | Python (stdlib ast) | JavaScript (esprima) |
|---|---|---|---|
| 比较 | `==`, `===`, `!=` | `==`, `is` | `==`, `===`, `!=` |
| 逻辑 OR | `\|\|` | `Or` | `\|\|` |
| 逻辑 AND | `&&` | `And` | `&&` |
| 赋值 | 操作符符号 | 操作符符号 | 操作符符号 |

### 10.3 Branch 结构差异

| 分支类型 | PHP | Python | JavaScript |
|---------|-----|--------|-----------|
| If/else | 统一 `_walk_branch()` | `_walk_if()` | `_walk_if()` — 同 Python 模式 |
| Ternary | `ast[iftrue]` / `ast[iffalse]` own | `ast[iftrue]` / `ast[iffalse]` ast 边 | `ast[iftrue]` / `ast[iffalse]` ast 边 |
| Switch/Match | switch(own)→case(own) | match(own)→case(own) | switch(own)→case(own) — 同 PHP |
| 循环 | For/While/DoWhile/Foreach | For/While/AsyncFor | For/While/DoWhile/ForIn/ForOf |
| Try | Try/Catch/Finally | Try/ExceptHandler | Try/CatchClause/Finally — 同 PHP 结构 |

### 10.4 函数类型差异

| | Python | PHP | JavaScript |
|---|---|---|---|
| 普通函数 | `FunctionDef` | `Function` | `FunctionDeclaration` |
| 匿名函数 | `Lambda` | `Closure`, `ArrowFunction` | `FunctionExpression`, `ArrowFunctionExpression` |
| 异步 | `AsyncFunctionDef` | 无 | `AsyncFunctionDeclaration`, `AsyncFunctionExpression`, `AsyncArrowFunctionExpression` |
| 方法 | 统一 | `Method`（单独类型） | 统一（class body 内的 FunctionDeclaration） |
| Generator | `FunctionDef` + `yield` | 无 | `FunctionDeclaration` + `yield` |
| 箭头函数 body | 无 | expression body | **可能是表达式（非 BlockStatement），需特殊处理** |

### 10.5 Member 访问差异

| | Python | PHP | JavaScript |
|---|---|---|---|
| 属性访问 | `Attribute` → identifier(property) + member | `ObjectProperty` → identifier(property) + member | `StaticMemberExpression` → operator(method_call) + member |
| 索引访问 | `Subscript` → operator(call) | `ArrayOffset` → identifier(key) + member | `ComputedMemberExpression` → operator(method_call) + member |
| 可选链 | 无 | `NullsafeProperty` | `ChainExpression` 包装 |
