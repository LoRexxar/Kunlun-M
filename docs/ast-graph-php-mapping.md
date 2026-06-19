# PHP AST → 图节点映射表

> 本文档描述 phply AST 节点类型到统一图结构的映射规则。
> 基于 `core/graph/normalizers/php/normalizer.py`。
> **必须与代码同步维护**。

---

## 1. 映射分类总览

| 图标签 | phply AST 节点类型集合 | Normalizer 方法 |
|--------|----------------------|-----------------|
| file | （顶层入口，非 phply 节点） | `normalize()` |
| class | `Class`, `Interface`, `Trait`, `Enum` | `_walk_class()` |
| function | `Function`, `Method`, `Closure`, `ArrowFunction` | `_walk_function()` |
| parameter | `FormalParameter`（函数定义参数） | `_walk_function()` 内部 |
| return | `Return` | `_walk_return()` |
| branch | `If`, `ElseIf`, `Else`, `TernaryOp`, `For`, `While`, `DoWhile`, `Foreach`, `Switch`, `Case`, `Default`, `Try`, `Catch`, `Finally`, `Match` | `_walk_branch()` |
| operator | `Assignment`, `AssignOp`, `BinaryOp`, `UnaryOp`, `PostIncDecOp`, `PreIncDecOp`, `New`, `Cast`, `Throw`, `Yield`, `Break`, `Continue`, `Echo`, `Print`, `Eval`, `Silence`, `IsSet`, `Empty`, `Unset`, `Clone`, `Exit`, `ListAssignment` | `_walk_operator()` |
| identifier | `Variable`, `NamedParameter`, `StaticVariable`, `Global` | `_walk_node()` / `_emit_identifier()` |
| const | `Constant`, `ClassConstant`, `MagicConstant`, Python 原始类型(str/int/float/bool) | `_emit_const()` |
| import | `Include`, `Require`, `UseDeclaration` | `_walk_import()` |
| dependency | 由 import/use 生成的依赖节点 | `_walk_import()` 内部 |

**特殊类型**（不直接映射为图节点，而是生成 `member` 边）：
| phply AST 节点类型 | 图表示 | Normalizer 方法 |
|-------------------|--------|-----------------|
| `ObjectProperty` | identifier(property) + member[access_type=property] | `_walk_node()` |
| `NullsafeProperty` | identifier(property) + member[access_type=property] | `_walk_node()` |
| `ArrayOffset` | identifier(key) + member[access_type=array_offset] | `_walk_node()` |
| `StaticProperty` | identifier(prop) + member[access_type=static_property] | `_walk_node()` |
| `StringOffset` | identifier(key) + member[access_type=array_offset] | `_walk_node()` |

**透明节点**（不创建图节点，直接 walk 子节点）：
| phply AST 节点类型 | 处理方式 |
|-------------------|---------|
| `Block` | 直接 walk `.nodes`（不是 `.children()`） |
| `Namespace` | 直接 walk `.nodes` |
| `Parameter`（函数调用参数包装器） | 解包 `.node` 后 walk |
| `ForeachVariable` | Emit identifier（variable 或 static） |

---

## 2. Class 节点映射

### `_walk_class()`

| phply 类型 | graph label | graph `type` | `name` | `attrs` | ast 子节点 |
|-----------|-------------|-------------|--------|--------|-----------|
| `Class` | class | `class` | 类名 | fullname=namespace\Class, parent_class, interfaces | own→ method/property/constant |
| `Interface` | class | `interface` | 接口名 | fullname | own→ method |
| `Trait` | class | `trait` | trait 名 | fullname | own→ method/property |
| `Enum` | class | `enum` | enum 名 | fullname | own→ method/case |

**命名约定：**
- `fullname` 包含命名空间前缀：`App\Models\User`
- Method 的 fullname 为 `Class::method`

---

## 3. Function 节点映射

### `_walk_function()`

| phply 类型 | graph label | graph `type` | `name` | `attrs` | 子节点 |
|-----------|-------------|-------------|--------|--------|--------|
| `Function` | function | `function` | 函数名 | fullname, params, visibility, static, namespace, modifiers | own→ parameter/operator/branch/return |
| `Method` | function | `method` | 方法名 | fullname=Class::method | 同上 |
| `Method`（`__construct`） | function | `constructor` | `__construct` | fullname=Class::__construct | 同上 |
| `Method`（`__destruct`） | function | `destructor` | `__destruct` | fullname=Class::__destruct | 同上 |
| `Closure` | function | `lambda` | `{closure}` | params | own→ parameter/operator/branch/return |
| `ArrowFunction` | function | `lambda` | `{closure}` | params | own→ parameter/operator/branch/return |

**参数处理：**
- `FormalParameter` → `parameter` 节点，`attrs.param_index` = 顺序索引
- `attrs.params` = 参数名列表（字符串列表）

---

## 4. Branch 节点映射

### `_walk_branch()`

#### 映射表

| phply 类型 | graph label | graph `type` | 条件处理 | own 子节点 | ⚠️ 注意事项 |
|-----------|-------------|-------------|---------|-----------|------------|
| `If` | branch | `if` | `ast[condition]→ expr`（walk 子树） | body 中所有 operator/branch/return | — |
| `ElseIf` | branch | `elif` | `ast[condition]→ expr` | body | — |
| `Else` | branch | `else` | 无条件 | body | **不继承父 if 的条件约束** |
| `TernaryOp` | branch | `ternary` | `ast[condition]→ expr` | `ast[iftrue]→ value`, `ast[iffalse]→ value` | **iftrue 继承条件约束，iffalse 不继承** |
| `For` | branch | `for` | 无 | body | — |
| `While` | branch | `while` | `ast[condition]→ expr` | body | — |
| `DoWhile` | branch | `while` | 无 | body | — |
| `Foreach` | branch | `foreach` | 无 | body + own→ keyvar/valvar identifiers | key/value 变量 walk 为 identifier |
| `Switch` | branch | `switch` | `ast[condition]→ expr` | own→ case/default branches | — |
| `Case` | branch | `case` | `ast[condition]→ expr`（⚠️ 见下） | body | **expr 可能是 Python str/int 原始类型 → 自动创建 const 节点** |
| `Default` | branch | `default` | 无条件 | body | **不继承 switch 的条件约束** |
| `Try` | branch | `try` | 无 | own→ body/catch/finally | — |
| `Catch` | branch | `catch` | 无 | body | — |
| `Finally` | branch | `finally` | 无 | body | — |
| `Match` | branch | `match` | 无 | own→ arms | — |

#### 条件表达式处理（`_COND_EXPR_NODES`）

branch 的条件表达式（`node.expr`）如果是以下类型，会被 walk 成 AST 子树并连接到 branch：
- `BinaryOp`、`UnaryOp`、`FunctionCall`、`MethodCall`、`StaticMethodCall`
- `Variable`（identifier）
- `IsSet`、`Empty`（call 类型 operator）
- `Boolean`、`Number`（phply 节点）
- `ArrayOffset`、`ObjectProperty`、`StaticProperty`（member 模式）
- Python 原始类型 `str`/`int`/`float`/`bool`（自动创建 const 节点）

**连接方式**：`branch --ast[role=condition]--> condition_root_node`

#### ⚠️ phply 已知陷阱

| 陷阱 | 说明 | 处理方式 |
|------|------|---------|
| Case.expr 是 Python str | `$x == 'a'` 的 Case.expr 直接是字符串 `'a'`，不是 AST 节点 | Normalizer 自动创建 const 节点 |
| BinaryOp.left/right 是 Python str | `$x == 'a'` 的 right 可能是 Python str `'a'` | Normalizer 自动创建 const 节点 |
| Echo.node 是列表 | Echo 节点的 `.node` 属性返回一个列表 | 遍历列表每个元素 walk |
| Print.node 是单个节点 | Print 节点的 `.node` 属性返回单个 AST 节点（不是列表） | 直接 walk 单个节点 |

---

## 5. Operator 节点映射

### `_walk_operator()` / `_walk_call()`

| phply 类型 | graph `type` | `name` | ast 子节点 | ⚠️ 注意事项 |
|-----------|-------------|--------|-----------|------------|
| `FunctionCall` | `call` | 函数名 | `ast[callee]→ callee_name`, `ast[arg, arg_index=N]→ args` | params 是 `Parameter` 包装对象，需 `.node` 解包；`.node` 可能是 Python str/int 原始类型 |
| `MethodCall` | `method_call` | method 名 | 对象通过 member 边连接, `ast[callee]→ method_name`, `ast[arg]→ args` | |
| `StaticMethodCall` | `static_call` | `Class::method` | 类通过 member 边连接, `ast[callee]→ method_name`, `ast[arg]→ args` | |
| `NullsafeMethodCall` | `method_call` | method 名 | 同 MethodCall | |
| `Assignment` | `assign` | LHS 变量名文本 | `ast[lhs]→ target`, `ast[rhs]→ expression` | |
| `AssignOp` | `aug_assign` | LHS 变量名文本 + 操作符 | `ast[lhs]→ target`, `ast[rhs]→ expression` | |
| `BinaryOp` | `binary_op` | 操作符符号 (`==`, `+`, `.`等) | `ast[left]→ left`, `ast[right]→ right` | **left/right 可能是 Python str/int 原始类型 → 自动创建 const** |
| `UnaryOp` | `unary_op` | 操作符符号 (`!`, `-`等) | `ast[operand]→ expr` | |
| `PostIncDecOp` | `unary_op` | 操作符 (`++`, `--`) | `ast[operand]→ expr` | |
| `PreIncDecOp` | `unary_op` | 操作符 (`++`, `--`) | `ast[operand]→ expr` | |
| `New` | `new` | 类名 | `ast[arg]→ params` | ⚠️ 使用 `node.params` 而非通用参数接口 |
| `Cast` | `type_cast` | 目标类型 (`(int)`等) | `ast[value]→ expression` | |
| `Throw` | `throw` | — | `ast[value]→ expression` | |
| `Yield` | `yield` | — | `ast[value]→ expression` | |
| `Break` | `break` | — | — | 叶子节点，无子节点 |
| `Continue` | `continue` | — | — | 叶子节点，无子节点 |
| `Echo` | `call` | `echo` | `ast[arg]→ expressions` (多个) | **`.node` 是列表，需遍历** |
| `Print` | `call` | `print` | `ast[arg]→ expression` (单个) | **`.node` 是单个节点，不是列表** |
| `Eval` | `call` | `eval` | `ast[arg]→ expression` | |
| `Silence` | `call` | `@` | `ast[value]→ expression` | |
| `IsSet` | `call` | `isset` | `ast[arg]→ args` | |
| `Empty` | `call` | `empty` | `ast[arg]→ args` | |
| `Unset` | `call` | `unset` | `ast[arg]→ args` | |
| `Clone` | `call` | `clone` | `ast[arg]→ expression` | |
| `Exit` | `call` | `exit` | `ast[arg]→ expression` | |
| `ListAssignment` | `assign` | LHS 变量名 | `ast[lhs]→ target`, `ast[rhs]→ expression` | |

### `_walk_call()` 详细流程

1. 创建 operator(type=call/static_call/method_call) 节点
2. 解析 callee 名称：
   - `FunctionCall`: 直接取 `node.name` 的文本（可能是 Variable 或 MemberAccess）
   - `MethodCall`: object 通过 member 边处理，method name 为 `node.name`
   - `StaticMethodCall`: class 通过 member 边处理，method name 为 `node.name` + `node.class_`
3. 添加 `use` 边：`operator → function`（如果找到同名 function 节点）
4. 遍历 `node.params`（Parameter 包装列表）：
   - 取 `param.node`（unwrap）
   - walk 成图节点
   - 添加 `ast[arg, arg_index=idx]` 边

---

## 6. Identifier 节点映射

| phply 类型 | graph label | graph `type` | `name` | 说明 |
|-----------|-------------|-------------|--------|------|
| `Variable` | identifier | `variable` | 含 `$` 前缀（如 `$id`） | phply 的 `Variable.name` 自带 `$` |
| `Variable`（`$this`/`$self`） | identifier | `this` | `$this` 或 `$self` | PHP 当前对象引用 |
| `NamedParameter` | identifier | `variable` | 参数名 | PHP 8 命名参数 |
| `StaticVariable` | identifier | `static` | 变量名 | 静态变量 |
| `Global` | identifier | `global` | 变量名 | global 声明 |
| `ForeachVariable` | identifier | `variable` 或 `static` | 变量名 | foreach key/value 变量 |

---

## 7. Const 节点映射

| phply 类型 | graph label | graph `type` | `name` | 说明 |
|-----------|-------------|-------------|--------|------|
| `Constant`（`true`/`false`） | const | `boolean` | `true` 或 `false` | PHP 布尔常量 |
| `Constant`（`null`） | const | `null` | `null` | PHP null 常量 |
| `Constant`（其他） | const | `constant` | 常量名 (`PHP_INT_MAX`等) | — |
| `ClassConstant` | const | `constant` | 常量名 | 如 `MyClass::CONST` |
| `MagicConstant` | const | `constant` | 魔术常量名 (`__LINE__`/`__FILE__`等) | — |
| Python `str` | const | `string` | `repr(value)` | ⚠️ 自动创建，来自 Parameter.node、BinaryOp.right、Case.expr |
| Python `int`/`float` | const | `number` | `repr(value)` | 同上 |
| Python `bool` | const | `boolean` | `repr(value)` | 同上 |

**⚠️ repr 的影响：**
- Python str `"hello"` → `repr` → `"\"hello\""` → 图上 `name = "'hello'"`
- PHP string `'/^\d+$/'` → phply 传为 Python str → `repr` → `"'/^\\\\d+$/'"`
- 在条件检查中需要 `strip("'\"")` 还原

---

## 8. Import 节点映射

### `_walk_import()`

| phply 类型 | graph label | graph `type` | `name` | `attrs` |
|-----------|-------------|-------------|--------|--------|
| `Include` | import | `include` | 文件路径 | — |
| `Require` | import | `require` | 文件路径 | — |
| `UseDeclaration` | import | `use` | 类/命名空间名 | `alias`（如有别名） |

`Include`/`Require` 的后缀（`_once`）通过 `expr_type` 区分 → 对应 `include_once`/`require_once`。

### DEPENDENCY 节点（`_walk_import()` 内部生成）

每个 import 节点会额外生成一个 `dependency` 子节点，通过 `frg` 边连接：

| 图标签 | graph `type` | `name` | `attrs` | 边 | 说明 |
|--------|-------------|--------|--------|-----|------|
| dependency | `dependency` | 导入的类/命名空间/文件名 | `source`=导入名 | `import --frg[type=import/use/include]--> dependency` | 表示文件的外部依赖关系 |

**注意**：`dependency` 节点本身无语句级语义，主要用于文件级依赖追踪。

---

## 9. Member 边映射

### `_walk_node()` 中的 member 处理

Member 访问不创建独立的图节点标签，而是用 `member` 边表达。

| phply 类型 | 处理流程 | member 边 |
|-----------|---------|-----------|
| `ObjectProperty` | 1. walk `node.node`(object) → 返回 obj_pos<br>2. emit identifier(name=prop_name, type=property)<br>3. add member edge: obj_pos → prop_pos | `member[access_type=property]` |
| `NullsafeProperty` | 同 ObjectProperty | `member[access_type=property]` |
| `ArrayOffset` | 1. walk `node.node`(array) → 返回 arr_pos<br>2. walk `node.expr`(index) → 返回 idx_pos（或 auto-create const for str/int）<br>3. emit identifier(name=index_text, type=property)<br>4. add member edge: arr_pos → idx_pos | `member[access_type=array_offset]` |
| `StaticProperty` | 1. walk `node.node`(class) → 返回 cls_pos<br>2. emit identifier(name=prop_name, type=property)<br>3. add member edge: cls_pos → prop_pos | `member[access_type=static_property]` |
| `StringOffset` | 同 ArrayOffset | `member[access_type=array_offset]` |

**示例**：`$_GET['id']`
```
identifier(name=$_GET, type=variable) --member[array_offset]--> identifier(name=id, type=property)
```

---

## 10. 透传节点

这些 phply AST 节点不创建图节点，只负责递归 walk 子节点。

| phply 类型 | 处理方式 | 说明 |
|-----------|---------|------|
| `Block` | walk `.nodes` 列表 | phply 的 Block 用 `.nodes`（不是 `.children()`） |
| `Namespace` | walk `.nodes` 列表 | 命名空间是透明容器 |
| `Parameter`（调用参数） | walk `.node` 属性 | `Parameter(expr, default)` 包装函数调用参数 |
| `ForeachVariable` | emit identifier | 作为 foreach 的 own 子节点 |
| `InlineHTML` | 忽略 | PHP 模板外的 HTML 片段 |
