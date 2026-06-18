# Python AST → 图节点映射表

> 本文档描述 Python stdlib `ast` 模块节点类型到统一图结构的映射规则。
> 基于 `core/graph/normalizers/python/normalizer.py`。
> **必须与代码同步维护**。

---

## 1. 映射分类总览

| 图标签 | stdlib ast 节点类型集合 | Normalizer 方法 |
|--------|----------------------|-----------------|
| file | （顶层入口，非 ast 节点） | `normalize()` |
| class | `ClassDef` | `_walk_class()` |
| function | `FunctionDef`, `AsyncFunctionDef` | `_walk_function()` |
| function | `Lambda` | `_walk_lambda()` |
| parameter | `ast.arg`（函数定义参数） | `_walk_parameter()` |
| return | `Return` | `_walk_return()` |
| branch | `If`, `IfExp` | `_walk_if()`, `_walk_ifexp()` |
| branch | `While`, `For`, `AsyncFor` | `_walk_while()`, `_walk_for()` |
| branch | `Try`（含 ExceptHandler） | `_walk_try()`, `_walk_excepthandler()` |
| branch | `Match`, `match_case` | `_walk_match()`, `_walk_match_case()` |
| operator | `Compare`, `BoolOp`, `BinOp`, `UnaryOp` | `_walk_compare()`, `_walk_boolop()`, `_walk_binop()`, `_walk_unaryop()` |
| operator | `Assign`, `AugAssign` | `_walk_assign()`, `_walk_augassign()` |
| operator | `Call`（含 Attribute callee） | `_walk_call()` |
| operator | `Subscript` | `_walk_subscript()` |
| operator | `Raise`, `Break`, `Continue` | `_walk_raise()`, `_walk_break()`, `_walk_continue()` |
| operator | `Yield`, `YieldFrom`, `Await` | `_walk_yield()`, `_walk_yield_from()`, `_walk_await()` |
| identifier | `Name`, `Attribute`（member chain） | `_walk_name()`, `_walk_attribute()` |
| const | `Constant` | `_walk_constant()` |
| import | `Import`, `ImportFrom` | `_walk_import()` |

**透明节点**（不创建图节点，直接 walk 子节点）：
| stdlib ast 节点类型 | 处理方式 |
|---------------------|---------|
| `List`, `Tuple`, `Set`, `Dict` | 直接 walk 所有元素 |
| `ListComp`, `SetComp`, `DictComp`, `GeneratorExp` | 直接 walk generators 和元素 |
| `Starred`, `NamedExpr` | 直接 walk 子节点 |
| `Expr`（顶层表达式语句） | 直接 walk value |
| `Delete`, `Global`, `Nonlocal`, `Assert`, `Pass` | 直接 walk 或跳过 |
| `With`, `AsyncWith` | 直接 walk body 和 items |
| `AnnAssign`, `TypeAlias` | 直接 walk |
| `JoinedStr`, `FormattedValue`（f-string） | 直接 walk |

**Match pattern 节点**（不创建独立分支，委托给子节点处理）：
| stdlib ast 节点类型 | 处理方式 |
|---------------------|---------|
| `MatchValue` | walk `.value`（通常是 Constant） |
| `MatchSingleton` | emit const（`True`/`False`/`None`） |
| `MatchStar` | emit const（`"_"`） |
| `MatchAs` | walk `.pattern`（如无 pattern 则 emit `"_"`） |
| `MatchOr` | walk 第一个 `.patterns[0]` |
| `MatchSequence` | walk 第一个 `.patterns[0]` |
| `MatchMapping` | walk children |
| `MatchClass` | walk children |

---

## 2. Class 节点映射

### `_walk_class()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `ClassDef` | class | `class` | 类名 | fullname=完整路径, bases=基类列表, decorators | own→ method/attribute |

**命名约定：**
- `fullname` 包含模块路径前缀（如 `django.http.HttpResponse`）
- decorators 作为 ast[role=decorator] 子节点

---

## 3. Function 节点映射

### `_walk_function()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `FunctionDef` | function | `function` | 函数名 | fullname, decorators, is_async=False | own→ parameter |
| `AsyncFunctionDef` | function | `function` | 函数名 | fullname, decorators, is_async=True | own→ parameter |

### `_walk_lambda()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Lambda` | function | `lambda` | `<lambda>` | — | own→ parameter |

---

## 4. Parameter 节点映射

### `_walk_parameter()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` |
|----------|-------------|-------------|--------|--------|
| `ast.arg` | parameter | `parameter` | 参数名 | default=默认值文本, annotation=类型注解文本, pos=位置索引 |

**参数方向：** 参数节点是 function 的 own 子节点，通过 ast[role=arg] 连接。DFG builder 将 `function → parameter` 标记为 `passthrough_arg`（参数透传）。

---

## 5. Import 节点映射

### `_walk_import()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Import` | import | `import` | `import x` | module=x | ast[role=import_name] → identifier |
| `ImportFrom` | import | `from_import` | `from x import y` | module=模块名, level=相对层级 | ast[role=import_name] → identifier（导入的名称） |

**注意：** Python import 不创建 function 节点。`from django.http import HttpResponse` 创建 import 节点 + identifier 节点。如果后续使用了 `HttpResponse()` 作为调用，analyzer 通过 `use` 边找到 identifier 节点。

---

## 6. Branch 节点映射

### `_walk_if()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `If` | branch | `if` | 条件文本 | condition=条件文本, raw_type=If | ast[role=condition] → 条件表达式 |
| elif（嵌套 If） | branch | `elif` | elif 条件 | condition, raw_type=If | 同上 |
| else（orelse body） | branch | `else` | `<else>` | condition=空, raw_type=Else | ast[role=iffalse] 连接到父 if |

**结构规则：**
- If body 语句通过 `own` 边连接到 if branch（通过 `ctx_stack` 上下文）
- Else 通过 **`ast[role=iffalse]`** 边连接到 if branch（不是 own）
- Else body 语句通过 `own` 连接到 else branch
- elif 作为嵌套 If 处理，own 连接到父 if

### `_walk_ifexp()` — 三元表达式

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `IfExp` | branch | `ternary` | 条件文本 | condition, raw_type=IfExp | ast[role=condition] → test; ast[role=iftrue] → body; ast[role=iffalse] → orelse |

**与 PHP 的差异：** PHP 的 TernaryOp 也有 iftrue/iffalse，但 Python IfExp 的 iftrue 是 body（单个表达式），iffalse 是 orelse。

### `_walk_while()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `While` | branch | `while` | 条件文本 | condition, raw_type=While | ast[role=condition] → test |

### `_walk_for()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `For` | branch | `for` | `for ... in ...` | raw_type=For, iter=迭代器文本 | ast[role=condition] → target; ast[role=rhs] → iter |
| `AsyncFor` | branch | `for` | `for ... in ...` | raw_type=AsyncFor | 同上 |

### `_walk_try()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `Try` | branch | `try` | `<try>` | raw_type=Try | own→ body 语句; ast[role=handler] → ExceptHandler |
| `ExceptHandler` | branch | `except` | `<except>` | raw_type=ExceptHandler, type=异常类型 | ast[role=condition] → 异常类型表达式 |

**Python 3.11+ TryStar (try/except*)** — 未单独处理，fallback 到 `_walk_children`。

### `_walk_match()` / `_walk_match_case()`

| ast 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|----------|-------------|-------------|--------|--------|--------|
| `Match` | branch | `match` | `match subject` | condition=subject 文本, raw_type=Match | ast[role=condition] → subject; own→ match_case |
| `match_case` | branch | `case` | `case pattern` | condition=pattern 文本, raw_type=match_case | ast[role=condition] → pattern 节点 |

**Match pattern 特殊处理：**
- `MatchValue` → walk `.value`（通常是 Constant，生成 const 节点）
- `MatchStar` / `MatchAs`(无 pattern) → emit const `"_"`（wildcard）
- `MatchSingleton`(True/False/None) → emit const
- `MatchOr` → walk 第一个 pattern
- `MatchSequence` → walk 第一个元素
- `MatchMapping` / `MatchClass` → walk children

**约束检测：** `case _` (wildcard) 不阻断污点（等同于 else/default）。具体值（如 `case 'start'`）阻断匹配的变量。

---

## 7. Operator 节点映射

### Compare (`_walk_compare()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Compare` | operator | `binary_op` | **操作符符号**（如 `"=="`, `"!="`） | operator=同name, raw_type=Compare, expr_text=完整表达式文本 | ast[role=left] → left; ast[role=right] → right(首个comparator) |

**⚠️ 关键约定：** `name` 必须是操作符符号（如 `"=="`），不是完整表达式文本。analyzer 的 `_SAFE_CONSTRAINT_OPS` 直接检查 `name`。`expr_text` 属性保存完整表达式文本供调试。

**操作符映射（`_COMPARE_SYMBOLS`）：**
| ast op 类型 | 符号 |
|-------------|------|
| `ast.Eq` | `==` |
| `ast.NotEq` | `!=` |
| `ast.Lt` | `<` |
| `ast.LtE` | `<=` |
| `ast.Gt` | `>` |
| `ast.GtE` | `>=` |
| `ast.Is` | `is` |
| `ast.IsNot` | `is not` |
| `ast.In` | `in` |
| `ast.NotIn` | `not in` |

### BoolOp (`_walk_boolop()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `BoolOp` | operator | `binary_op` | **操作符名称**（`And`/`Or`） | operator=同name, raw_type=BoolOp | ast[role=left] → values[0]; ast[role=right] → values[1]; 依次连接 |

### BinOp (`_walk_binop()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `BinOp` | operator | `binary_op` | **操作符符号**（如 `+`, `*`, `//`） | operator=同name, raw_type=BinOp | ast[role=left] → left; ast[role=right] → right |

**操作符映射（`_BINOP_SYMBOLS`）：** `Add→+, Sub→-, Mult→*, Div→/, FloorDiv→//, Mod→%, Pow→**, LShift→<<, RShift→>>, BitOr→\|, BitXor→^, BitAnd→&, MatMult→@`

### UnaryOp (`_walk_unaryop()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `UnaryOp` | operator | `binary_op` | **操作符符号**（如 `not`, `-`） | operator=同name, raw_type=UnaryOp | ast[role=operand] → operand |

### Assign (`_walk_assign()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Assign` | operator | `assign` | `lhs = rhs` | raw_type=Assign, expr_text=完整文本 | ast[role=lhs] → target; ast[role=rhs] → value |

**多目标赋值**（`a = b = value`）：多个 target 通过 ast[role=lhs] 连接，但图上只处理第一个 target。

### AugAssign (`_walk_augassign()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `AugAssign` | operator | `assign` | **操作符符号**（如 `+=`, `*=`） | operator=符号, raw_type=AugAssign | ast[role=lhs] → target; ast[role=rhs] → value |

### Call (`_walk_call()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Call` | operator | `call` | callee 名称 | raw_type=Call | ast[role=callee] → callee节点; ast[role=arg] → 每个参数 |

**callee 解析规则：**
- `func` 是 `Name` → callee 名称 = `node.id`
- `func` 是 `Attribute` → 生成 member chain，callee 名称 = 最后一段属性名（如 `os.system` 的 callee = `"system"`）
- `func` 是 `Call`（IIFE） → callee 名称 = `"lambda"` 或递归

**Member chain 表达：** `os.system(cmd)` 创建：
- `identifier:os` → member → `identifier:system`（property）
- `operator:call(system)` → ast[callee] → `identifier:system`
- 如果 `os` 已通过 import 注册，analyzer 通过 `_is_superglobal_method_call` 检查

### Subscript (`_walk_subscript()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|----------|-------------|-------------|--------|--------|-----------|
| `Subscript` | operator | `call` | `__getitem__` | raw_type=Subscript | ast[role=callee] → value 的名称（fake callee）; ast[role=arg] → slice |

### Attribute (`_walk_attribute()`)

| ast 类型 | graph 表示 | Normalizer 方法 |
|----------|-----------|-----------------|
| `Attribute` | identifier(property) + member[access_type=property] | `_walk_attribute()` |

**member chain 构建：** 递归处理 `a.b.c`：
- `a` → identifier(variable)
- `b` → identifier(property) ← member ← `a`
- `c` → identifier(property) ← member ← `b`

### 其他 Operator

| ast 类型 | graph label | graph `type` | `name` |
|----------|-------------|-------------|--------|
| `Return` | return | — | — |
| `Raise` | operator | `throw` | `raise` |
| `Break` | operator | `break` | `break` |
| `Continue` | operator | `continue` | `continue` |
| `Yield` | operator | `yield` | `yield` |
| `YieldFrom` | operator | `yield` | `yield from` |
| `Await` | operator | `await` | `await` |

---

## 8. Identifier / Const 节点映射

### Name (`_walk_name()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` |
|----------|-------------|-------------|--------|--------|
| `Name` | identifier | 根据 ctx 确定变量类型 | `node.id` | `scope`=`Load`/`Store`/`Del` |

**ctx 类型映射：**
| ast ctx | identifier type |
|---------|----------------|
| `ast.Load` | `variable` |
| `ast.Store` | `variable`（赋值目标） |
| `ast.Del` | `variable` |

### Constant (`_walk_constant()`)

| ast 类型 | graph label | graph `type` | `name` | `attrs` |
|----------|-------------|-------------|--------|--------|
| `Constant` | const | 根据 value 类型 | `repr(value)` | — |

**const type 映射：**
| Python value 类型 | graph `type` |
|------------------|-------------|
| `None` | `null` |
| `bool` | `boolean` |
| `int`, `float`, `complex` | `number` |
| `str` | `string` |
| 其他 | `constant` |

**⚠️ `name` 使用 `repr()` 包装**：字符串字面量 `'hello'` 在图中的 name 是 `"'hello'"`（带引号）。analyzer 处理时需要 `strip("'\"")` 去掉引号。

---

## 9. 与 PHP Normalizer 的关键差异

### 9.1 Operator `name` 规范

| | PHP (phply) | Python (stdlib ast) |
|---|---|---|
| Compare | `name = op_symbol`（如 `"=="`) | `name = op_symbol`（如 `"=="`），✅ 一致 |
| BoolOp | `name = "AND"/"OR"` | `name = "And"/"Or"` |
| BinOp | `name = op_symbol`（如 `"+"`) | `name = op_symbol`（如 `"+"`)，✅ 一致 |
| UnaryOp | `name = op_symbol`（如 `"!"`) | `name = op_symbol`（如 `"not"`, `"-"`) |
| Assign | `name = "lhs = rhs"` 文本 | `name = "lhs = rhs"` 文本 |
| Call | `name = callee_name` | `name = callee_name` |

**统一规范：** 所有二元/一元/比较操作符的 `name` 必须是操作符符号，不是完整表达式文本。完整表达式文本存放在 `attrs.expr_text`。

### 9.2 Branch 结构差异

| 分支类型 | PHP | Python |
|---------|-----|--------|
| If/else | if→body(own), else(own→parent if) | if→body(own), else→if(`ast[iffalse]`) |
| Ternary | TernaryOp→iftrue(own), iffalse(own) | IfExp→iftrue(`ast[iftrue]`), iffalse(`ast[iffalse]`) |
| Switch/Match | switch(own)→case(own), default(own) | match(own)→case(own) |
| case pattern | — | MatchValue→const(值), MatchStar→const(`_`) |

### 9.3 Super Global 差异

| | PHP Super Globals | Python Source |
|---|---|---|
| 直接变量 | `$_GET`, `$_POST`, `$_SERVER`... | 无直接等价物 |
| Member chain | — | `request.GET.get('cmd')` |
| 检测方式 | `_is_source_variable` 直接匹配 | `_is_superglobal_method_call` 沿 member chain 检查 |
| 已注册名称 | 9 个（`$_GET` 等） | 12 个（`request.GET`, `request.POST`, `request.data` 等） |

### 9.4 约束函数差异

| | PHP | Python |
|---|---|---|
| 类型验证 | `is_numeric`, `ctype_digit` 等 | `isinstance`, `isdigit`, `isalpha` 等 |
| 方法调用检查 | 不需要（PHP 的 `ctype_digit($x)` 是函数调用） | 需要检查 member chain receiver（`$x.isdigit()`） |
| 正则 | `preg_match`（PHP 格式 `/pattern/flags`） | `re.match`/`re.fullmatch`（Python 原始字符串 `r'pattern'`） |
| 正则安全判定 | 去 `/` 分隔符后检查 `^...$` 锚定 | 直接检查 `^...$` 锚定（已无分隔符） |

### 9.5 透明节点差异

| 节点 | PHP (phply) | Python (stdlib ast) |
|------|-----------|--------------------|
| 语句块 | `Block`（直接 walk `.nodes`） | 无 Block 节点（body 是语句列表） |
| 函数调用参数 | `Parameter` 包装器（解包 `.node`） | `ast.Call.args`（直接迭代，无需解包） |
| 生成器/推导式 | 无 | `ListComp`, `SetComp`, `DictComp`, `GeneratorExp`（透明处理） |
| f-string | 无 | `JoinedStr` + `FormattedValue`（透明处理） |

### 9.6 DFG 追溯行为差异

Python 的 `match/case` 引入了一个重要差异：**分支约束检查使用 sink arg 的 branch chain（预计算），而非 BFS 当前节点的 branch chain**。这是因为变量可能在 match 外赋值、在 case 内使用，BFS 追到赋值处时离开了 case scope。

当 sink arg 不在任何 branch 内时（如 ternary 外使用 ternary 结果），回退到 BFS 当前节点的 branch chain。
