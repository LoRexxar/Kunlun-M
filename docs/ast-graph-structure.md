# AST 图完整结构文档

> 本文档描述 AST 图引擎的完整图结构，包括节点/边 Schema、边的生成方式、推导边逻辑、分支约束分析机制、以及守卫体系（parameters_back 后置检查）。
> **必须与代码同步维护**：`core/graph/node_edge_schema.py`、`core/graph/normalizers/`、`core/graph/edge_builders/`、`core/graph/graph_analyzer.py`。

---

## 1. 总览

| 项目 | 数量 |
|------|------|
| 节点标签 | 12 |
| 边标签 | 8（7 基础 + use 引用边） |
| 边类型 | 结构边（Normalizer 生成）+ 推导边（edge_builders 生成） |
| 节点类型枚举 | ClassType(4), FunctionType(5), OperatorType(16), BranchType(14), ImportType(7), IdentifierType(8), ConstType(5) |

**边的分类：**
- **结构边**（Normalizer 遍历 AST 时生成）：`own`、`ast`、`use`、`member`、`frg`
- **推导边**（edge_builders/ 独立模块生成）：`dfg`、`cg`、`alias`、`crg`

---

## 2. 节点 Schema（12 种）

### 2.1 通用属性

所有节点共享以下属性：

| 属性 | 类型 | 说明 |
|------|------|------|
| `label` | string | 节点标签（12 种之一） |
| `name` | string | 主显示名（文件名、函数名、变量名等） |
| `lineno` | int | 起始行号 |
| `end_lineno` | int | 结束行号（0 表示不可用） |
| `language` | string | 语言标识（php/javascript/java/python/go/c） |

### 2.2 各标签详情

#### file
| 属性 | 说明 |
|------|------|
| `type` | 无（file 无子类型） |
| `attrs.path` | 文件绝对路径 |

图的根节点。所有 class、function、import、顶层 operator/branch/return 通过 `own` 边连接到 file。

#### class
| 属性 | 说明 |
|------|------|
| `type` | `class` / `interface` / `struct` / `enum` |
| `attrs.fullname` | 完整限定名（含命名空间和类名前缀） |
| `attrs.namespace` | 命名空间 |
| `attrs.parent_class` | 父类名（如有） |
| `attrs.interfaces` | 实现的接口列表 |
| `attrs.modifiers` | 修饰符（abstract/final） |

通过 `own` 边包含 method、property、constant 等子节点。

#### function
| 属性 | 说明 |
|------|------|
| `type` | `function` / `method` / `constructor` / `lambda` / `destructor` |
| `attrs.fullname` | 完整限定名（类方法包含 `Class::method`） |
| `attrs.params` | 参数名列表 |
| `attrs.visibility` | 可见性（public/protected/private） |
| `attrs.static` | 是否为静态方法 |
| `attrs.namespace` | 命名空间 |
| `attrs.modifiers` | 修饰符（abstract/final） |

`own` 子节点：parameter(0..N)、branch、operator、return。

**taint 属性**（由 DFG builder 的步骤 6 注入）：
| 属性 | 说明 |
|------|------|
| `attrs.taint_type` | `"safe"` / `"passthrough_arg"` / `"repair"` / `""`（空=未标注） |
| `attrs.taint_passthrough` | 污点透传参数索引列表，如 `[0]` 表示第 1 个参数透传 |

#### parameter
| 属性 | 说明 |
|------|------|
| `type` | 无（parameter 无子类型） |
| `attrs.param_index` | 参数索引（从 0 开始） |
| `attrs.default_value` | 默认值（如有） |
| `attrs.is_ref` | 是否为引用传递 |

通过 `own` 边连接到 function 父节点。

#### return
| 属性 | 说明 |
|------|------|
| `type` | 无 |

通过 `own` 边连接到 function 父节点。返回值通过 `ast[child]` 边连接到返回表达式。

#### identifier
| 属性 | 说明 |
|------|------|
| `type` | `variable` / `property` / `field` / `global` / `static` / `super` / `this` |

`name` 包含变量名（PHP 包含 `$` 前缀，如 `$id`）。

#### const
| 属性 | 说明 |
|------|------|
| `type` | `string` / `number` / `boolean` / `null` / `constant` |

`name` 存储值的文本表示。PHP 常量（`true`/`false`/`null`）和字面量均映射到此标签。

#### operator（16 种子类型）
| `type` 值 | 说明 | `name` 含义 | ast 子节点 |
|-----------|------|-------------|------------|
| `call` | 函数调用 | 函数名 | `ast[callee]→ callee_name`, `ast[arg, arg_index=N]→ args` |
| `static_call` | 静态方法调用 | `Class::method` | `ast[callee]→ method_name`, `ast[arg]→ args` |
| `method_call` | 实例方法调用 | `method` | `ast[callee]→ method_name`, `ast[arg]→ args` |
| `assign` | 赋值 | LHS 变量名 | `ast[lhs]→ target`, `ast[rhs]→ expression` |
| `aug_assign` | 复合赋值 | LHS 变量名 | `ast[lhs]→ target`, `ast[rhs]→ expression` |
| `binary_op` | 二元运算 | 运算符符号 | `ast[left]→ left_operand`, `ast[right]→ right_operand` |
| `unary_op` | 一元运算/自增减 | 运算符符号 | `ast[operand]→ operand` |
| `new` | 对象实例化 | 类名 | `ast[arg]→ class_name/params` |
| `type_cast` | 类型转换 | 目标类型 | `ast[value]→ expression` |
| `throw` | 抛出异常 | — | `ast[value]→ expression` |
| `yield` | 生成器 yield | — | `ast[value]→ expression` |
| `await` | 异步等待 | — | — |
| `break` | 跳出循环 | — | — |
| `continue` | 继续循环 | — | — |
| `goto` | 跳转 | — | — |

#### branch（14 种子类型）
| `type` 值 | 说明 | 条件 | own 子节点 |
|-----------|------|------|------------|
| `if` | if 语句 | `ast[condition]→ expr` | body 中的 operator/branch/return |
| `elif` | elseif | `ast[condition]→ expr` | body |
| `else` | else 分支 | 无（不继承父 if 的条件约束） | body |
| `ternary` | 三元表达式 | `ast[condition]→ expr`, `ast[iftrue]→ value`, `ast[iffalse]→ value` | iftrue 继承条件约束，iffalse 不继承 |
| `for` | for 循环 | — | body |
| `while` | while 循环 | `ast[condition]→ expr` | body |
| `foreach` | foreach 循环 | — | body + key/value 变量 |
| `switch` | switch 语句 | `ast[condition]→ expr` | case/default 分支 |
| `case` | case 分支 | `ast[condition]→ expr`（匹配值，可以是 const 节点） | body（不继承 switch 的条件约束） |
| `default` | default 分支 | 无（不继承 switch 的条件约束） | body |
| `try` | try 块 | — | catch/finally 分支 |
| `catch` | catch 块 | — | body |
| `finally` | finally 块 | — | body |
| `match` | match 表达式 | — | arms |

#### import
| 属性 | 说明 |
|------|------|
| `type` | `import` / `from_import` / `include` / `require` / `include_once` / `require_once` / `use` |
| `attrs.alias` | 别名（如有） |
| `attrs.module_path` | 模块/文件路径 |

#### annotation
| 属性 | 说明 |
|------|------|
| `type` | 无 |

装饰器/注解节点（PHP 无原生支持，保留用于其他语言）。

#### dependency
| 属性 | 说明 |
|------|------|
| `type` | 无 |

外部库依赖（如 Composer 包）。

---

## 3. 边 Schema（8 种）

### 3.1 结构边（Normalizer 生成）

#### own — 包含层级
| 属性 | 值 |
|------|------|
| 方向 | parent → child |
| 说明 | 表达 AST 节点的包含关系 |

层级结构：
```
file own→ class / function / import / operator / branch / return
class own→ function(method) / operator / branch / return
function own→ parameter(0..N) / operator / branch / return
branch own→ operator / branch / return  (嵌套)
```

边属性：`index`（子节点在父节点中的顺序）。

#### ast — AST 父子关系
| 属性 | 值 |
|------|------|
| 方向 | parent → child |
| 说明 | AST 节点之间的语法父子关系 |

`role` 枚举值（`AstRole`）：
| role | 用于 |
|------|------|
| `lhs` | 赋值运算符的左值 |
| `rhs` | 赋值运算符的右值 |
| `arg` | 函数调用的参数（配合 `arg_index` 指定位置） |
| `callee` | 函数调用的被调用方名称 |
| `left` | 二元运算符的左操作数 |
| `right` | 二元运算符的右操作数 |
| `operand` | 一元运算符的操作数 |
| `value` | cast/throw/yield 等的表达式 |
| `condition` | branch 的条件表达式 |

#### use — 引用关系
| 属性 | 值 |
|------|------|
| 方向 | operator(call) → function(callee) |
| 说明 | call operator 引用 function 节点，**不是 cg 边** |

边属性：`call_type`（`direct` / `static` / `method` / `dynamic`）。

#### member — 成员访问
| 属性 | 值 |
|------|------|
| 方向 | object → property |
| 说明 | 对象属性、数组下标、静态属性访问 |

`access_type` 枚举值：
| access_type | 说明 | PHP 示例 |
|-------------|------|----------|
| `property` | 对象属性 | `$obj->prop` |
| `array_offset` | 数组/字符串下标 | `$arr[0]`、`$_GET['id']` |
| `static_property` | 静态属性 | `Class::$prop` |

#### frg — 文件依赖
| 属性 | 值 |
|------|------|
| 方向 | file → file |
| 说明 | 文件间的 include/import/require 关系 |

`type` 枚举值：`include` / `import` / `from_import` / `use`。

### 3.2 推导边（edge_builders 生成）

#### dfg — 数据流图
| 属性 | 值 |
|------|------|
| 方向 | 数据源 → 数据消费者 |
| 生成 | `DataFlowBuilder`（`edge_builders/dfg.py`） |
| 说明 | 追踪数据在程序中的流动 |

`type` 枚举值：
| type | 说明 |
|------|------|
| `forward_slice` | 正向切片：值从上游传播到下游 |
| `same` | 同名变量在不同作用域的链接 |

**生成管线（6 步，顺序执行）：**
1. **Operator Flows**：operator 的 ast 子节点 → operator 自身
2. **Assignment Propagation**：`assign RHS → LHS`。特殊处理：RHS 为 ternary branch 时，iftrue/iffalse 子节点分别 → LHS
3. **Parameter Passing**：`call arg[0..N] → function parameter[0..N]`
4. **Return Values**：`return 表达式 → function 节点`
5. **Same Variables**：同名 identifier 在不同作用域的 `dfg[same]` 链接
6. **Builtin & Summary**：注入 `taint_type` 和 `taint_passthrough` 到 function 节点

#### cg — 调用图
| 属性 | 值 |
|------|------|
| 方向 | caller function → callee function |
| 生成 | `CallGraphBuilder`（`edge_builders/cg.py`） |
| 说明 | function→function 的调用关系 |

生成逻辑：遍历 function 节点 → 找 own 下的 call operator → 沿 use 边找到 callee function → 建立 cg 边。

#### alias — 间接调用别名

| 属性 | 值 |
|------|------|
| 方向 | function placeholder（use→function target） → resolved function |
| 生成 | `AliasBuilder`（`edge_builders/alias.py`） |
| 说明 | 间接函数调用的 callee 名解析结果 |

边属性：

| 属性 | 说明 |
|------|------|
| `alias_type` | 解析方式（见下表） |
| `resolved_name` | 解析出的完整函数名（如 `os.system`） |

`alias_type` 枚举值：

| type | 说明 | 示例 |
|------|------|------|
| `direct` | 直接赋值 `func = eval` | leaf identifier 无 DFG 上游 |
| `via_dfg_chain` | 多层传递 `func2 = func; func = eval` | DFG 链跨多个 identifier |
| `via_member` | 成员访问组合 `func = obj.method` | identifier + member 边组合为 `obj.method` |
| `via_getattr` | `getattr(obj, 'method')` | 从 call 参数提取字符串 |
| `via_globals` | `globals().get('func_name')` | 从 call 参数提取字符串 |
| `via_function_pointer` | C 函数指针 `int (*func)(...) = system; func(cmd)` | 从 `function_declarator > parenthesized > pointer > identifier` 提取 LHS，assign operator 的 RHS 为目标函数 |
| `via_function_reference` | Lua 函数引用 `local f = os.execute; f(cmd)` | `dot_index_expression` 的最后一个 identifier + member 边组合为目标函数名 |

生成逻辑：

1. 遍历所有 call operator → 找 `use→function` target
2. 跳过有 `own` children 的（真实函数定义）
3. 从 callee identifier 沿 DFG 反向追踪（最多 8 层）
4. 终止条件：identifier leaf（可能组合 member 边）、const(string)、function 节点、已知 resolver operator（getattr/globals().get）
5. 创建 alias 边：`use→function target → resolved function placeholder`

消费方：`graph_analyzer._resolve_callee_name` 在 `ast[callee]` 和 `use` 两条路径中均检查 alias 边，优先返回 `resolved_name`。

#### crg — 类关系图
| 属性 | 值 |
|------|------|
| 方向 | class → class |
| 说明 | 类之间的继承/实现关系 |

`type` 枚举值：`extends` / `implements` / `trait` / `mixin`。

---

## 4. 分支约束分析

分支约束是 DFG 回溯的自然延伸：回溯路径经过 branch 节点时，检查条件是否约束了变量使其变为安全值。

### 4.1 核心方法

| 方法 | 说明 |
|------|------|
| `get_enclosing_branch(vid)` | 沿 ast+own 反向边找到最近的 branch 节点 |
| `get_branch_chain(vid)` | 收集从 vid 到 function/file 的所有 branch 节点。**else/default/case 为断点**——不继承父 branch（if/switch）的条件 |
| `check_branch_constraint(branch_vid, var_name)` | 对 branch 的条件子树进行约束分析 |
| `_is_in_ternary_iffalse(vid, ternary_vid)` | BFS 判断 vid 是否在 ternary 的 iffalse 分支下 |

### 4.2 条件判定规则（`_check_condition_node`）

| 模式 | 条件 | 判定 | 示例 |
|------|------|------|------|
| `==` 固定值 | BinaryOp(op=`==`/`===`)，一侧是 identifier，另一侧是 const | ✅ 安全 | `$x == 'admin'` |
| `\|\|` 枚举 | BinaryOp(op=`\|\|`)，每个分支都是 `var==const` | ✅ 安全 | `$x == 'a' \|\| $x == 'b'` |
| `&&` 组合 | BinaryOp(op=`&&`)，任一侧约束了变量 | ✅ 安全 | `is_numeric($x) && $x > 0` |
| 类型验证函数 | FunctionCall，name 在 `_TYPE_VALIDATION_FUNCS` 中 | ✅ 安全 | `is_numeric($x)`、`ctype_digit($x)` |
| preg_match | FunctionCall(name=preg_match)，正则 `^...$` 锚定 | ✅ 安全 | `preg_match('/^\d+$/', $x)` |
| switch case | branch(type=case)，case 匹配值约束 switch 变量 | ✅ 安全 | `switch($x) { case 'a': ... }` |

**验证函数列表（`_TYPE_VALIDATION_FUNCS`）：**
`is_numeric`、`is_int`、`is_integer`、`is_float`、`is_double`、`is_string`、`is_bool`、`is_null`、`is_array`、`is_object`、`is_callable`、`ctype_digit`、`ctype_alpha`、`ctype_alnum`、`ctype_upper`、`ctype_lower`、`ctype_space`、`ctype_cntrl`、`ctype_graph`、`ctype_print`、`ctype_punct`

### 4.3 集成到回溯

在 `parameters_back` 中通过两道防线集成：
1. **pre-check**：BFS 开始前，检查 start_vid 是否在 branch 内且被约束（针对 identifier 类型）
2. **Rule 6**：BFS 遍历中，遇到 identifier 类型的上游节点时检查分支约束

**三元表达式特殊处理**：iffalse 分支的变量不受 condition 约束（条件取反），iftrue 分支正常约束。

---

## 5. 守卫体系（parameters_back 后置检查）

分支约束分析回答"这个变量在分支内被约束了吗"；守卫体系回答"到达 sink 这件事本身是否证明污点无意义"。两者互补：前者作用于 BFS 遍历内部，后者作为后置检查作用于 BFS 返回 code=1（可控）之后。

### 5.1 执行模型

`parameters_back` 公共入口（`graph_analyzer.parameters_back`）的执行顺序：

```
1. Fix 20b 两遍 redirect 分析（BFS impl 可能跑两次）
2. BFS 返回 r1（code=1 时才继续）
3. 守卫链按序短路（命中任一 → 返回 code=-1，chain 带 guard step）：
   a. Fix 21a  negated whitelist guard   !in_array($v, [...]) 终止分支
   b. Fix 21d  existence whitelist guard  is_dir/is_file(前缀.$t) 存在性守卫
   c. Fix 21f  xxe disabled guard         libxml_disable_entity_loader() 先于 XML sink
   d. Fix 21h-2 dead code guard           无条件 die/exit 之后的语句
   e. Fix 21h-3 ctor property guard       构造函数属性白名单
4. Fix 21a 后置检查（遍历 r1.path 逐变量验证）
5. 返回 r1（或守卫翻转结果）
```

### 5.2 各守卫判据

| 守卫 | 触发形态 | 判定依据 |
|---|---|---|
| **21a negated whitelist** | `if (!in_array($v, ['a','b'])) die;` 在 sink 前、同函数内 | 到达 sink 证明 `in_array` 为真 → 变量受白名单约束 |
| **21d existence whitelist** | `if ($_GET[t] && is_dir(PREFIX . $_GET[t])) { $v = $_GET[t]; } echo $v;` | 守卫使赋值值为常量前缀下的真实目录/文件名 → 服务端语义值 |
| **21f xxe disabled** | `libxml_disable_entity_loader()` 先于 simplexml/DOM/xml_parse sink | 外部实体展开已关闭 → 内容不可引用 file:// 实体 |
| **21h-2 dead code** | sink 语句前存在顶层裸 `die()/exit()`（仅 own 父边、无 ast 父边） | sink 不可达 → 任何污点流均无意义 |
| **21h-3 ctor property** | `new C(...)` 后读 `$obj->prop`，构造函数内 `$this->prop = array_key_exists(...) ? ... : 默认` | 存储值被白名单三元约束 → 读值不可控 |
| **19b path jail**（遍历内） | 调用方 `strpos($_POST['p'],'../') !== FALSE ... die` 守护传入被调方文件 sink | jail 检查先于 sink 执行 → 路径穿越被阻断 |

### 5.3 图结构防御（守卫自身的正确性前提）

守卫依赖"顶层语句枚举"，Normalizer 的图保真行为直接影响判定，已知两个陷阱及防御：

1. **`@` 一元算子 hoist**：`print_r(@$_GET)` 的 `@` 操作数可能被 hoist 为独立 index=0 顶层语句，与真语句脱钩 → sink 语句容器必须取 **own-index 最大** 的命中（21h-2b）
2. **`&&` 短路守卫操作数**：`(!defined(...)) && die(...)` 的 die 操作数带 own 边，貌似裸 die 语句 → 裸终止符必须**无 ast 父边**（21h-2c），否则守卫误杀其后全部活代码 sink

### 5.4 守卫开发约定

- 新守卫独立成函数（`_xxx_guard`），在守卫链中按序插入，命中返回带 `{"step": "xxx_guard"}` 的 chain
- sink 入口形态多样（property / 对象变量 / echo 算子 / new 实参 / 实参标识符），守卫须覆盖 scanner 真实入口，用 env 门控日志（或 graph REPL）验证入口 vid 身份，不凭猜测
- 每个守卫须通过：合成图探针正反例 + 真实项目全量重扫回归（确认既有 TP/FP 判定不变）

---

## 6. 图结构示例

### 6.1 函数定义与调用

```php
function foo($id) {
    system($id);
}
```

```
file own→ function(name=foo)
function own→ parameter(name=$id, param_index=0)
function own→ operator(type=call, name=system)
operator ast[callee]→ identifier(name=system)
operator use→ function(name=system)      // use 边：引用关系
operator ast[arg, arg_index=0]→ identifier(name=$id)
```

### 6.2 赋值与数据流

```php
$id = $_GET['id'];
system($id);
```

```
// 结构边（Normalizer）
operator(type=assign, name=$id)
  ast[lhs]→ identifier($id)
  ast[rhs]→ identifier($_GET)
member($_GET → id)  // access_type=array_offset

// 推导边（DFG builder）
dfg[forward_slice]: identifier($_GET) → operator(assign)
dfg[forward_slice]: identifier($id) → operator(call system)
// 或：operator(assign) → identifier($id) → operator(call)
```

### 6.3 分支条件

```php
if (is_numeric($x)) {
    system($x);
}
```

```
function own→ branch(type=if)
branch ast[condition]→ operator(type=call, name=is_numeric)
  operator ast[arg, arg_index=0]→ identifier($x)
branch own→ operator(type=call, name=system)
  operator ast[arg, arg_index=0]→ identifier($x)

// 回溯 system($x) 时，$x 在 if branch 内
// check_branch_constraint: is_numeric($x) → type validator → 安全
```

### 6.4 三元表达式

```php
$id = $cmd == 'test' ? $_GET['id'] : '1';
```

```
operator(type=assign, name=$id)
  ast[lhs]→ identifier($id)
  ast[rhs]→ branch(type=ternary)
    ast[condition]→ operator(type=binary_op, name==)
      ast[left]→ identifier($cmd)
      ast[right]→ const("'test'")
    ast[iftrue]→ identifier($_GET)
      member($_GET → id)
    ast[iffalse]→ const("'1'")

// DFG 推导：
dfg: identifier($_GET) → identifier($id)     // iftrue 分支
dfg: const('1') → identifier($id)           // iffalse 分支
```

### 6.5 Switch Case

```php
switch ($x) {
    case 'ls':
        system($x);
}
```

```
branch(type=switch)
  ast[condition]→ identifier($x)
  own→ branch(type=case)
    ast[condition]→ const("'ls'")
    own→ operator(type=call, name=system)
```

---

## 7. 节点索引（SQLite）

SQLite 索引仅存储 5 种核心节点，用于快速定位：

| 节点标签 | 索引用途 |
|----------|----------|
| file | 按路径查找文件节点 |
| class | 按类名查找类定义 |
| function | 按函数名查找函数定义（包括方法） |
| operator | 按 name 查找调用点（sink 识别） |
| import | 按模块路径查找 import 节点 |

identifier、const、parameter、return、branch、annotation、dependency 不建索引（数量大且不需要按名查找）。
