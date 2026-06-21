# Kunlun-M 图数据库扫描引擎 — 设计文档

> **版本**: v1.0-draft
> **日期**: 2026-06-17
> **状态**: 预研设计阶段，不涉及代码修改

## 1. 背景与动机

### 1.1 现有架构痛点

当前 Kunlun-M 的扫描引擎采用 **"解析-内存分析-丢弃"** 模式：

```
parse → 内存 AST → grep/match/回溯 → chain → 结果 → AST 丢弃
```

**关键问题：**

1. **AST 不持久化** — 每次扫描从头 parse，无法复用已解析的 AST
2. **分析过程不持久化** — chain 只存最终节点（type/content/path/lineno），中间判定逻辑全部丢失
3. **无法二次分析** — 无法在扫描结束后追溯"为什么报了这个漏洞"或"为什么没报"
4. **跨文件分析低效** — 每次跨文件追踪都要重新解析被 include/import 的文件

### 1.2 目标

将 AST 持久化为 **igraph 图结构**，实现：

- **一次解析，无限次查询** — AST 只需构建一次，后续分析直接在图上操作
- **完整分析过程可追溯** — 回溯判定、分支约束、tamper 过滤全部在图上标记
- **二次分析 API** — 扫描完成后可加载图进行任意查询
- **增量更新** — 代码变更时只更新变更文件的子图

## 2. 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                       用户接口层                              │
│  CLI (scan/console/web)     二次分析 API (AstGraphSession)    │
├──────────────────────────────────────────────────────────────┤
│                       规则引擎层                              │
│  VulnerabilityMatcher      SingleRule.process()              │
│    ├─ parameters_back()    ├─ function_back()                │
│    ├─ branch_constraint    ├─ TraceCache                     │
│    └─ Source Discovery     └─ Function Summary                │
├──────────────────────────────────────────────────────────────┤
│                    图分析层 (新增)                              │
│  GraphAnalyzer          GraphQueryBuilder                    │
│    ├─ find_paths()        ├─ get_subgraph()                  │
│    ├─ trace_taint()       ├─ get_function_def()               │
│    ├─ analyze_branch()    ├─ get_file_structure()             │
│    └─ mark_decision()     └─ get_cross_file_edges()          │
├──────────────────────────────────────────────────────────────┤
│                   图存储层 (新增)                              │
│  AstGraphBuilder          AstGraphIO                         │
│    ├─ build_file()        ├─ save() → .graphmlz              │
│    ├─ incremental_update()├─ load() ← .graphmlz              │
│    └─ normalize()         └─ get_node_index() → SQLite      │
├──────────────────────────────────────────────────────────────┤
│                   持久化层                                     │
│  igraph (.graphmlz)       SQLite (kunlun.db)                 │
│    ├─ 全量 AST 图          ├─ ast_node_index (节点快速索引)    │
│    └─ 分析决策标记         ├─ file_hashes (增量更新依据)       │
│                            └─ ScanResultTask (漏洞结果, 已有)  │
├──────────────────────────────────────────────────────────────┤
│                   解析层 (保留)                                │
│  Pretreatment          各语言 Parser                           │
│    ├─ PHP: phply         ├─ Java: javalang                   │
│    ├─ JS: esprima        ├─ Python: ast                      │
│    ├─ Go: tree-sitter    └─ C: tree-sitter                   │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 数据流

```
扫描阶段:
  [源代码文件] → Pretreatment.parse() → 原生 AST
                                            ↓
                                      AstGraphBuilder.normalize()
                                            ↓
                                    统一中间表示 (UnifiedASTNode)
                                            ↓
                                    igraph 图构建 (frg/own/cg/ast/crg/member 边)
                                            ↓
                              ┌──────────────┴──────────────┐
                              ↓                              ↓
                       DataFlowAnalyzer              AstGraphIO.save()
                       (独立数据流分析,                  (.graphmlz 持久化)
                        生成 dfg 边)                        ↓
                              ↓                         SQLite 索引更新
                       GraphAnalyzer
                       (图上回溯/判定)
                              ↓
                       分析决策标记
                              ↓
                       漏洞结果 → ScanResultTask

二次分析阶段:
  AstGraphIO.load(.graphmlz) → igraph 图 → GraphQueryBuilder → 任意查询
```

## 3. 统一 AST 中间表示层 (Unified IR)

### 3.1 设计原则

将 6 种语言的异构 AST 映射为一套统一的中间表示，是整个方案的基础。

**核心原则：**
- **语义等价映射** — 不保留语言特有结构，只保留跨语言通用的语义概念
- **保留原始信息** — 每个节点保留 `language` 和 `raw_type` 属性，支持回查原始 AST
- **图友好** — 所有关系显式表达为边，不依赖隐式父子关系

### 3.2 统一节点类型 (NodeLabel)

采用"同类节点合并为一个标签，用 type 属性区分"的设计思路，将原本 26 种节点类型简化为 12 种核心标签。

| 节点标签 | 语义 | 核心属性 |
|---------|------|---------|
| **file** | 文件 | name, location, language, content_hash |
| **class** | 类/接口/结构体 | name, fullname, type, inherits_from, language, lineno, end_lineno |
| **function** | 函数/方法 | name, fullname, type, signature, modifiers, language, lineno, end_lineno, file_path |
| **parameter** | 形参 | name, type_hint, default_value, index, language, lineno |
| **return** | 返回值 | type_hint, lineno, language |
| **identifier** | 变量/属性/全局变量 | name, type, scope, var_type, language, lineno, file_path |
| **const** | 字面量/常量 | name, type, language, lineno |
| **operator** | 执行操作 | name, type, operator, callee, index, language, lineno, end_lineno, file_path, function |
| **branch** | 控制流分支结构 | name, type, condition, lineno, end_lineno, language, function |
| **import** | 导入/引用 | name, fullname, alias, type, lineno, language |
| **annotation** | 注解/装饰器 | name, fullname, arguments, lineno, language |
| **dependency** | 依赖包 | name, version, file |

#### 3.2.1 节点属性详解

**file（文件）节点属性：**
- `name: str` — 文件名
- `location: str` — 文件绝对路径
- `language: str` — 语言标识（php/javascript/java/python/go/c）
- `content_hash: str` — 文件内容 MD5（增量更新用）

**class（类/接口/结构体）节点属性：**
- `name: str` — 类名
- `fullname: str` — 类的完整路径（如 App\Http\Controllers\UserController）
- `type: str` — 类型分类：`class`（类）、`interface`（接口）、`struct`（结构体）、`enum`（枚举）
- `inherits_from: str` — 父类名（如有）
- `language: str` — 语言标识
- `lineno: int` — 起始行号
- `end_lineno: int` — 结束行号

**function（函数/方法）节点属性：**
- `name: str` — 函数/方法名
- `fullname: str` — 完整路径（如 App\Http\Controllers\UserController::index）
- `type: str` — 类型分类：`function`（普通函数）、`method`（类方法）、`constructor`（构造函数）、`lambda`（匿名函数）、`destructor`（析构函数）
- `signature: str` — 函数签名（如 `test($input): string`）
- `modifiers: str` — 修饰符（如 public static，多个空格分隔）
- `language: str` — 语言标识
- `lineno: int` — 起始行号
- `end_lineno: int` — 结束行号
- `file_path: str` — 所属文件路径

**parameter（形参）节点属性：**
- `name: str` — 参数名
- `type_hint: str` — 类型提示（如 string, int, ?string）
- `default_value: str` — 默认值（如有）
- `index: int` — 参数序号（从 0 开始）
- `language: str` — 语言标识
- `lineno: int` — 行号

**return（返回值）节点属性：**
- `type_hint: str` — 返回类型提示
- `lineno: int` — 行号
- `language: str` — 语言标识

**identifier（变量/属性/全局变量）节点属性：**
- `name: str` — 变量名
- `type: str` — 类型分类：`variable`（局部变量）、`property`（类属性）、`field`（结构体字段）、`global`（全局变量）、`static`（静态变量）、`super`（父类引用）、`this/self`（实例引用）
- `scope: str` — 作用域（所属函数名或类名）
- `var_type: str` — 变量的数据类型（如 string, int, array，可从类型推导得出）
- `language: str` — 语言标识
- `lineno: int` — 行号
- `file_path: str` — 所属文件路径

**const（字面量/常量）节点属性：**
- `name: str` — 常量值（如 `"hello"`, `42`, `true`）
- `type: str` — 类型分类：`string`（字符串）、`number`（数字）、`boolean`（布尔）、`null`（空值）、`constant`（命名常量，如 PHP 的 `PHP_EOL`）
- `language: str` — 语言标识
- `lineno: int` — 行号

**operator（执行操作）节点属性：**
- `name: str` — 操作名（函数调用时为被调用的函数名，如 `system`、`echo`；赋值时为赋值目标变量名；运算时为运算符）
- `type: str` — 类型分类：`call`（函数/方法调用）、`static_call`（静态方法调用）、`method_call`（对象方法调用）、`assign`（赋值）、`aug_assign`（复合赋值如 +=）、`binary_op`（二元运算）、`unary_op`（一元运算）、`new`（对象实例化）、`type_cast`（类型转换）、`throw`（抛出异常）、`yield`（生成器 yield）、`await`（异步等待）、`break`（跳出循环）、`continue`（跳过当前迭代）、`goto`（跳转，如 PHP goto）
- `operator: str` — 操作符（仅运算类型有效，如 `+`, `-`, `.*`, `==`）
- `callee: str` — 被调用函数名（仅 call/method_call/static_call 类型有效）
- `index: int` — 操作在该作用域中的序号（按代码顺序）
- `language: str` — 语言标识
- `lineno: int` — 行号
- `end_lineno: int` — 结束行号
- `file_path: str` — 所属文件路径
- `function: str` — 所属函数名

**branch（控制流分支结构）节点属性：**
- `name: str` — 分支描述（如条件表达式文本）
- `type: str` — 类型分类：`if`（if 语句）、`elif`（elif/elseif）、`else`（else）、`ternary`（三元表达式）、`for`（for 循环）、`while`（while 循环）、`foreach`（foreach 循环）、`switch`（switch 语句）、`case`（case 分支）、`default`（default 分支）、`try`（try 块）、`catch`（catch 块）、`finally`（finally 块）、`match`（match 表达式，PHP 8/Python 3.10+）
- `condition: str` — 条件表达式文本（如 `is_numeric($input)`）
- `lineno: int` — 行号
- `end_lineno: int` — 结束行号
- `language: str` — 语言标识
- `function: str` — 所属函数名

**import（导入/引用）节点属性：**
- `name: str` — 导入的模块/类/文件名
- `fullname: str` — 完整路径/命名空间
- `alias: str` — 别名（如有，如 `use App\Http\Controllers\UserController as UserCtrl` 中的 `UserCtrl`，`from os import path as p` 中的 `p`）
- `type: str` — 类型分类：`import`（标准导入）、`from_import`（from...import）、`include`（PHP include）、`require`（PHP require）、`include_once`、`require_once`、`use`（PHP use namespace）
- `lineno: int` — 行号
- `language: str` — 语言标识

**annotation（注解/装饰器）节点属性：**
- `name: str` — 注解名（如 `@Override`, `@Route`, `@app.route`）
- `fullname: str` — 完整路径
- `arguments: str` — 注解参数（如 `(methods={"GET", "POST"})`）
- `lineno: int` — 行号
- `language: str` — 语言标识

**dependency（依赖包）节点属性：**
- `name: str` — 依赖包名（如 `laravel/framework`, `express`）
- `version: str` — 版本号（如 `^10.0`, `4.18.2`）
- `file: str` — 声明该依赖的文件路径（如 `composer.json`, `package.json`）

**通用属性：**
所有节点均包含以下通用属性：
- `language: str` — 语言标识（php/javascript/java/python/go/c）
- `lineno: int` — 起始行号
- `end_lineno: int` — 结束行号（可选）

### 3.3 统一边类型 (EdgeLabel)

采用"同类关系合并为一个标签，通过属性区分"的设计思路，将原本 23 种边类型简化为 8 种核心关系。

| 边标签 | 语义 | 方向 | 属性 |
|---------|------|------|------|
| **frg** | 文件依赖关系，File Relationship Graph | file → file | type: include/import/from_import/use |
| **own** | 层次包含关系 | parent → child | index: 子节点序号 |
| **use** | 函数调用引用（Normalizer 生成，cg 边的前置中间边） | operator(call) → function(callee) | call_type: direct/static/method, lineno: 调用行号 |
| **cg** | 函数调用图，Call Graph（由 use 边 + 函数定义推导） | operator(call) → function(definition) | call_type: direct/static/method/dynamic, lineno: 调用行号 |
| **ast** | 语法树子节点关系 | parent → child | role: lhs/rhs/arg/callee/left/right/operand/value, arg_index: 实参序号 |
| **dfg** | 数据流图，Data Flow Graph（独立模块生成，非 AST 映射） | source → target | type: forward_slice/same |
| **crg** | 类关系图，Class Relationship Graph | source → target | type: extends/implements/trait/mixin |
| **member** | 成员访问关系 | object → member | access_type: property/array_offset/static_property |

#### 3.3.1 边属性详解

**frg（文件依赖关系，File Relationship Graph）：**
- **含义**：描述文件之间的依赖关系
- **方向**：file → file
- **示例**：(A:file)-[:frg]->(B:file) 表示文件 A 依赖（include/import）文件 B
- **属性**：
  - `type: str` — 依赖类型：`include`（PHP include/require）、`import`（标准 import）、`from_import`（from...import）、`use`（PHP use namespace）

**own（层次包含关系）：**
- **含义**：描述节点之间的所有权/层次包含关系
- **方向**：parent → child
- **示例连接**：
  - (file)-[:own]->(function) — 文件包含函数
  - (file)-[:own]->(class) — 文件包含类
  - (file)-[:own]->(import) — 文件包含导入
  - (file)-[:own]->(dependency) — 文件声明依赖
  - (class)-[:own]->(function) — 类包含方法
  - (class)-[:own]->(annotation) — 类上的注解
  - (function)-[:ast {role:'param'}]->(parameter) — 函数包含形参
  - (function)-[:own]->(return) — 函数包含返回
  - (function)-[:own]->(operator) — 函数包含操作
  - (function)-[:own]->(branch) — 函数包含分支
  - (function)-[:own]->(annotation) — 函数上的注解
  - (branch)-[:own]->(branch) — 分支嵌套（if 里面还有 if）
  - (branch)-[:own]->(operator) — 分支包含操作
  - (branch)-[:own]->(return) — 分支包含返回
  - (operator)-[:own]->(operator) — 操作嵌套（如函数调用的参数是另一个函数调用）
- **属性**：
  - `index: int` — 子节点在该父节点中的序号（按代码顺序）

**use（函数调用引用）：**
- **含义**：由 Normalizer 在 `_walk_call`/`_walk_method_call` 中生成，连接函数调用操作符到被调用函数的 callee 目标节点（通常是 `is_external=True` 的占位 function 节点）
- **方向**：operator(call/method_call/static_call) → function(callee)
- **生成时机**：AST 图构建阶段（Normalizer 遍历时）
- **作用**：作为 `cg` 边的中间表示。CallGraphBuilder 在构建阶段通过同名解析，将 `use` 边连接到真正的函数定义节点，并推导出最终的 `cg` 边。同时 DFG builder 的 `_analyze_parameter_passing` 利用 `use` 边查找 callee function 定义，创建实参→形参的 DFG 边
- **覆盖语言**：全 14 语言（PHP/Python/Java/JS/Go/C/C++/C#/Kotlin/Lua/Ruby/Rust/TypeScript）
- **示例**：
  - (operator:exec {type:'call'})-[:use {call_type:'direct', lineno:4}]->(function:exec {is_external:true})
  - (operator:getParameter {type:'method_call'})-[:use {call_type:'method', lineno:10}]->(function:getParameter {fullname:'request.getParameter', is_external:true})
- **属性**：
  - `call_type: str` — 调用类型：`direct`（直接调用）、`static`（静态调用）、`method`（方法调用）
  - `lineno: int` — 调用发生的行号

**cg（函数调用图，Call Graph）：**
- **含义**：描述函数调用操作符到被调用函数**定义**的关系（与 use 边的区别：cg 连接到真正的函数定义节点，use 连接到 callee 占位节点）
- **方向**：operator(function_call/method_call/static_call) → function
- **生成方式**：由 CallGraphBuilder 在图构建阶段从 `use` 边 + `function` 定义节点推导生成
- **示例**：(operator:system {type:'call'})-[:cg {call_type:'direct', lineno:4}]->(function:system {name:'system'})
- **属性**：
  - `call_type: str` — 调用类型：`direct`（直接调用）、`static`（静态调用）、`method`（方法调用）、`dynamic`（动态调用/回调）
  - `lineno: int` — 调用发生的行号

**ast（语法树子节点关系）：**
- **含义**：描述表达式级别的语法结构，即操作符的子节点关系
- **方向**：parent → child
- **示例连接**：
  - (operator:assign)-[:ast]->(identifier:$cmd) — 赋值的左值
  - (operator:assign)-[:ast]->(identifier:$input) — 赋值的右值
  - (operator:call:system)-[:ast]->(identifier:$cmd) — 函数调用的实参
  - (operator:binary_op)-[:ast]->(identifier:$a) — 二元运算的左操作数
  - (operator:binary_op)-[:ast]->(const:1) — 二元运算的右操作数
  - (return)-[:ast]->(identifier:$result) — 返回值的表达式
- **属性**：
  - `role: str` — 子节点角色：`lhs`（赋值左值）、`rhs`（赋值右值/表达式值）、`arg`（函数实参）、`callee`（被调用目标）、`left`（二元运算左操作数）、`right`（二元运算右操作数）、`operand`（一元运算操作数）、`value`（返回值/表达式值）
  - `arg_index: int` — 实参序号（仅 role=arg 时有效，从 0 开始）

**dfg（数据流图，Data Flow Graph）：**

> ⚠️ **独立模块**：dfg 边不属于 AST 映射阶段，而是由专门的数据流分析模块（`DataFlowAnalyzer`）在 AST 图构建完成后，基于 ast/own/member/use 边独立分析并添加到图上。详见第 6 节图分析层。

- **含义**：描述变量/常量/全局变量/参数之间的数据流关系
- **方向**：source → target
- **连接**：identifier/const/parameter → identifier/const/parameter
- **生成时机**：AST 图构建完成后，由 DataFlowAnalyzer 分析 operator(ast) 子节点的数据传播关系，动态添加 dfg 边
- **生命周期**：dfg 边可按需生成（扫描时或二次分析时），不影响基础图结构；分析完成后可选择持久化到 .graphmlz 或丢弃
- **示例连接**：
  - (identifier:$_GET['id'])-[:dfg]->(identifier:$id) — 用户输入传递给局部变量
  - (identifier:$cmd)-[:dfg]->(identifier:$cmd) — type=same，同变量的不同引用
  - (parameter:$cmd)-[:dfg]->(identifier:$cmd) — 函数参数传递到函数体内的变量引用（parameter 节点作为定义端点）
  - (identifier:$input {ast:arg})-[:dfg]->(parameter:$cmd {own:param}) — 实参传递给形参（跨函数调用，依赖 use 边查找 callee 定义）
- **属性**：
  - `type: str` — 数据流类型：`forward_slice`（数据从 source 传递到 target）、`same`（同变量的不同引用位置）

**crg（类关系图，Class Relationship Graph）：**
- **含义**：描述类之间的关系（继承、实现等）
- **方向**：source → target
- **示例**：(A:class)-[:crg]->(B:class) 表示类 A 继承/实现了类 B
- **属性**：
  - `type: str` — 关系类型：`extends`（继承）、`implements`（实现接口）、`trait`（使用 trait）、`mixin`（混入）

**member（成员访问关系）：**
- **含义**：描述对象访问其成员属性/字段的关系（如 `$this->name`、`$arr['key']`、`self::$count`）
- **方向**：object → member
- **连接**：identifier → identifier
- **示例连接**：
  - (identifier:$this)-[:member]->(identifier:name) — 对象属性访问
  - (identifier:$arr)-[:member]->(identifier:'key') — 数组下标访问
  - (identifier:self)-[:member]->(identifier:$count) — 静态属性访问
- 多层链式支持：`$this->db->query($input)` 自然表达为：
  ```
  (identifier:$this)-[:member]->(identifier:db)
  (identifier:$this)-[:member]->(identifier:name)
  (identifier:$this)-[:member]->(identifier:items)
  ```
- **属性**：
  - `access_type: str` — 访问方式：`property`（对象属性 `$this->name`）、`array_offset`（数组下标 `$arr['key']`）、`static_property`（静态属性 `self::$count`）

### 3.4 图存储结构示意

```cypher
# 示例: <?php function test($input) { $cmd = $input; system($cmd); }

(file:app.php {name:'app.php', language:'php'})-[:own]->(function:test {fullname:'test', type:'function', lineno:2})
(function:test)-[:ast {role:'param'}]->(parameter:$input {name:'input', index:0, lineno:2})
(function:test)-[:own]->(operator:$cmd=$input {type:'assign', name:'$cmd', index:0, lineno:3})
  (operator:$cmd=$input)-[:ast {role:'lhs'}]->(identifier:$cmd {name:'$cmd', type:'variable', lineno:3})
  (operator:$cmd=$input)-[:ast {role:'rhs'}]->(identifier:$input {name:'$input', type:'variable', lineno:3})
(function:test)-[:own]->(operator:system {type:'call', name:'system', index:1, lineno:4})
  (operator:system)-[:cg {call_type:'direct', lineno:4}]->(function:system {name:'system', type:'function'})
  (identifier:$this)-[:member {access_type:'property'}]->(identifier:db)
  (operator:system)-[:ast {role:'arg', arg_index:0}]->(identifier:$cmd {name:'$cmd', lineno:4})
```

## 4. 归一化转换层

### 4.1 架构

```
各语言原生 AST
    ↓
{lang}Normalizer.normalize(ast_nodes, file_path) → list[UnifiedNode]
    ↓
AstGraphBuilder.build(nodes) → igraph Graph
```

### 4.2 Normalizer 基类

```python
class BaseNormalizer(ABC):
    """语言 AST → 统一中间表示的转换器基类"""

    language: str  # php / javascript / java / python / go / c

    @abstractmethod
    def normalize(self, ast_nodes, file_path: str) -> list[UnifiedNode]:
        """将原生 AST 转换为统一节点列表"""
        pass

    def _map_label(self, raw_type: str) -> str:
        """原生 AST 类型 → 统一标签映射"""
        return self.TYPE_MAP.get(raw_type, 'AstNode')

    def _extract_code_snippet(self, node, source_lines: list[str]) -> str:
        """提取节点的源码片段"""
        pass
```

### 4.3 各语言 Normalizer

每个语言一个 Normalizer 实现，负责：
1. 遍历原生 AST 树
2. 将每个节点映射为 UnifiedNode
3. 生成统一标签和边关系
4. 提取通用属性

**PHPNormalizer** (`phply` 输出)

```python
class PhpNormalizer(BaseNormalizer):
    language = 'php'

    TYPE_MAP = {
        'Function': 'Function',
        'Method': 'Function',          # 方法统一为 Function
        'Class': 'Class',
        'Assignment': 'Assignment',
        'Return': 'Return',
        'If': 'Conditional',
        'TernaryOp': 'Conditional',
        'For': 'Loop',
        'While': 'Loop',
        'Foreach': 'Loop',
        'FunctionCall': 'FunctionCall',
        'MethodCall': 'FunctionCall',
        'StaticMethodCall': 'FunctionCall',
        'Variable': 'Variable',
        'FormalParameter': 'Parameter',
        'BinaryOp': 'BinaryOp',
        'UnaryOp': 'UnaryOp',
        'ObjectProperty': 'MemberAccess',
        'ArrayOffset': 'MemberAccess',
        'Include': 'Import',
        'Require': 'Import',
        'UseDeclaration': 'Import',
        'New': 'New',
        'Closure': 'Lambda',
        'Throw': 'Throw',
        'Try': 'TryCatch',
        'Cast': 'TypeCast',
        'String': 'Literal',
        'Number': 'Literal',
        'Boolean': 'Literal',
        'Constant': 'Literal',
        'ClassVariable': 'Property',
        # ...其余映射为 'AstNode'
    }
```

**JavaScriptNormalizer** (`esprima` 输出)

```python
class JsNormalizer(BaseNormalizer):
    language = 'javascript'

    TYPE_MAP = {
        'FunctionDeclaration': 'Function',
        'FunctionExpression': 'Function',
        'ArrowFunctionExpression': 'Lambda',
        'ClassDeclaration': 'Class',
        'ClassExpression': 'Class',
        'CallExpression': 'FunctionCall',
        'AssignmentExpression': 'Assignment',
        'ReturnStatement': 'Return',
        'IfStatement': 'Conditional',
        'ConditionalExpression': 'Conditional',
        'ForStatement': 'Loop',
        'WhileStatement': 'Loop',
        'ForInStatement': 'Loop',
        'ForOfStatement': 'Loop',
        'Identifier': 'Variable',
        'Literal': 'Literal',
        'BinaryExpression': 'BinaryOp',
        'UnaryExpression': 'UnaryOp',
        'UpdateExpression': 'UnaryOp',
        'MemberExpression': 'MemberAccess',
        'ImportDeclaration': 'Import',
        'VariableDeclaration': 'Variable',  # JS 特有
        'TryStatement': 'TryCatch',
        'ThrowStatement': 'Throw',
        'NewExpression': 'New',
        # ...
    }
```

**PythonNormalizer** (`ast` 标准库输出)

```python
class PythonNormalizer(BaseNormalizer):
    language = 'python'

    TYPE_MAP = {
        'FunctionDef': 'Function',
        'AsyncFunctionDef': 'Function',
        'ClassDef': 'Class',
        'Call': 'FunctionCall',
        'Assign': 'Assignment',
        'AugAssign': 'Assignment',
        'Return': 'Return',
        'If': 'Conditional',
        'IfExp': 'Conditional',
        'For': 'Loop',
        'While': 'Loop',
        'Name': 'Variable',
        'Constant': 'Literal',
        'Num': 'Literal',
        'Str': 'Literal',
        'BinOp': 'BinaryOp',
        'UnaryOp': 'UnaryOp',
        'Attribute': 'MemberAccess',
        'Subscript': 'MemberAccess',
        'Import': 'Import',
        'ImportFrom': 'Import',
        'Lambda': 'Lambda',
        'Raise': 'Throw',
        'Try': 'TryCatch',
        'ExceptHandler': 'TryCatch',
        'arguments': 'Parameter',
        'ListComp': 'Loop',       # 列表推导语义包含循环
        'DictComp': 'Loop',       # 字典推导
        'Global': 'Variable',     # global 声明
        'Nonlocal': 'Variable',    # nonlocal 声明
        # ...
    }
```

**JavaNormalizer** (`javalang` 输出)

```python
class JavaNormalizer(BaseNormalizer):
    language = 'java'

    TYPE_MAP = {
        'MethodDeclaration': 'Function',
        'ConstructorDeclaration': 'Function',
        'ClassDeclaration': 'Class',
        'InterfaceDeclaration': 'Interface',
        'MethodInvocation': 'FunctionCall',
        'Assignment': 'Assignment',
        'ReturnStatement': 'Return',
        'IfStatement': 'Conditional',
        'ForStatement': 'Loop',
        'WhileStatement': 'Loop',
        'LocalVariableDeclaration': 'Variable',
        'MemberReference': 'Variable',
        'Literal': 'Literal',
        'BinaryOperator': 'BinaryOp',
        'UnaryOperator': 'UnaryOp',
        'FieldAccess': 'MemberAccess',
        'ArrayAccess': 'MemberAccess',
        'Import': 'Import',
        'FormalParameter': 'Parameter',
        'ClassCreator': 'New',
        'CastExpression': 'TypeCast',
        'ThrowStatement': 'Throw',
        'TryStatement': 'TryCatch',
        'LambdaExpression': 'Lambda',
        'Annotation': 'Decorator',
        # ...
    }
```

**GoNormalizer** (tree-sitter 输出)

```python
class GoNormalizer(BaseNormalizer):
    language = 'go'

    TYPE_MAP = {
        'function_declaration': 'Function',
        'method_declaration': 'Function',
        'type_declaration': 'Class',     # struct 语义上接近 Class
        'call_expression': 'FunctionCall',
        'assignment_statement': 'Assignment',
        'return_statement': 'Return',
        'if_statement': 'Conditional',
        'for_statement': 'Loop',
        'identifier': 'Variable',
        'literal': 'Literal',
        'binary_expression': 'BinaryOp',
        'unary_expression': 'UnaryOp',
        'selector_expression': 'MemberAccess',
        'index_expression': 'MemberAccess',
        'import_declaration': 'Import',
        'parameter_list': 'Parameter',
        'go_statement': 'Loop',          # goroutine 语义
        'defer_statement': 'TryCatch',   # defer 语义接近 finally
        'type_assert_expression': 'TypeCast',
        'func_literal': 'Lambda',
        # ...
    }
```

**CNormalizer** (tree-sitter 输出)

```python
class CNormalizer(BaseNormalizer):
    language = 'c'

    TYPE_MAP = {
        'function_definition': 'Function',
        'call_expression': 'FunctionCall',
        'assignment_expression': 'Assignment',
        'return_statement': 'Return',
        'if_statement': 'Conditional',
        'for_statement': 'Loop',
        'while_statement': 'Loop',
        'identifier': 'Variable',
        'number_literal': 'Literal',
        'string_literal': 'Literal',
        'binary_expression': 'BinaryOp',
        'unary_expression': 'UnaryOp',
        'member_expression': 'MemberAccess',
        'array_subscript_expression': 'MemberAccess',
        'cast_expression': 'TypeCast',
        'declaration': 'Variable',
        'parameter_declaration': 'Parameter',
        'struct_specifier': 'Class',
        # ...
    }
```

### 4.4 转换流程伪代码

```python
def normalize_file(file_path, language, raw_ast, source_lines):
    """单文件 AST → 统一图节点和边"""
    normalizer = NORMALIZERS[language]
    nodes = []    # list[UnifiedNode]
    edges = []    # list[UnifiedEdge]

    # 1. 创建 File 节点
    file_hash = md5(source_lines.join('\n'))
    file_node = UnifiedNode(
        label='File', file_path=file_path, language=language,
        content_hash=file_hash, lineno=1
    )
    nodes.append(file_node)

    # 2. 遍历原生 AST
    def walk(raw_node, parent_unified_id):
        unified_node = normalizer.to_unified(raw_node, source_lines)
        node_id = len(nodes)
        nodes.append(unified_node)

        # 生成父子关系边
        if parent_unified_id is not None:
            edges.append(UnifiedEdge(
                src=parent_unified_id, dst=node_id,
                edge_type='CONTAINS'
            ))

        # 根据节点类型生成语义边
        for edge in normalizer.extract_edges(raw_node, node_id):
            edges.append(edge)

        # 递归子节点
        for child in normalizer.children(raw_node):
            walk(child, node_id)

    # 3. 遍历顶层语句
    for top_stmt in raw_ast:
        walk(top_stmt, file_node.id)

    return nodes, edges
```

## 5. 图存储层设计

### 5.1 igraph 图构建

```python
class AstGraphBuilder:
    """将统一中间表示构建为 igraph 图"""

    def __init__(self):
        self.graph = igraph.Graph(directed=True)
        self.node_id_counter = 0
        self.node_map = {}       # unified_node.id → igraph vertex id
        self.file_nodes = {}     # file_path → vertex id

    def build_from_normalized(self, nodes, edges):
        """批量构建图"""
        # 批量添加节点
        self.graph.add_vertices(len(nodes))
        for i, node in enumerate(nodes):
            v = self.graph.vs[i]
            v['label'] = node.label
            v['language'] = node.language
            v['raw_type'] = node.raw_type
            v['lineno'] = node.lineno
            v['end_lineno'] = node.end_lineno
            v['file_path'] = node.file_path
            v['uid'] = node.id        # unified node id
            for k, v in node.extra_props.items():
                v[k] = str(v)

        # 批量添加边
        edge_pairs = [(e.src, e.dst) for e in edges]
        self.graph.add_edges(edge_pairs)
        for i, edge in enumerate(edges):
            e = self.graph.es[i]
            e['edge_type'] = edge.edge_type
            if edge.order is not None:
                e['order'] = edge.order

    def delete_file_subgraph(self, file_path):
        """删除文件对应的子图（增量更新用）"""
        vids = [v.index for v in self.graph.vs if v['file_path'] == file_path]
        if vids:
            self.graph.delete_vertices(vids)
```

### 5.2 igraph 文件 I/O

```python
class AstGraphIO:
    """igraph 图的持久化和加载"""

    def __init__(self, graph_dir: str):
        self.graph_dir = graph_dir
        self.graph_path = os.path.join(graph_dir, 'ast_graph.graphmlz')

    def save(self, graph: igraph.Graph):
        """保存图到压缩文件"""
        graph.save(self.graph_path)

    def load(self) -> igraph.Graph:
        """从文件加载图"""
        if os.path.exists(self.graph_path):
            return igraph.Graph.Load(self.graph_path)
        return igraph.Graph(directed=True)  # 返回空图

    def exists(self) -> bool:
        return os.path.exists(self.graph_path)

    def file_size(self) -> int:
        return os.path.getsize(self.graph_path) if self.exists() else 0
```

### 5.3 SQLite 索引层

在现有 Django DB 中新增两张表，用于**不加载图时的快速查询**。仅存储 5 种高频查询的核心节点，其余节点需要时从 igraph 图中遍历获取。

```python
# 新增模型 (web/index/models.py)

class AstNodeIndex(models.Model):
    """AST 核心节点快速索引 — 仅存储高频查询的 5 种节点类型"""
    file_path = models.CharField(max_length=500)
    node_label = models.CharField(max_length=50)    # file / class / function / operator / import
    node_name = models.CharField(max_length=200, null=True)
    lineno = models.IntegerField()
    language = models.CharField(max_length=20)
    extra = models.JSONField(null=True)  # 各节点类型特有属性的 JSON，如 function 的 fullname/signature，class 的 inherits_from

    class Meta:
        indexes = [
            models.Index(fields=['file_path', 'node_label']),
            models.Index(fields=['node_label', 'node_name']),
        ]


class FileHash(models.Model):
    """文件内容哈希 — 用于增量更新判断"""
    file_path = models.CharField(max_length=500, primary_key=True)
    content_hash = models.CharField(max_length=32)   # MD5
    language = models.CharField(max_length=20)
    scan_time = models.DateTimeField(auto_now=True)
```

**索引节点范围：**

| 节点类型 | 建索引理由 |
|---------|-----------|
| **file** | 项目文件列表、增量更新依据 |
| **class** | 类/接口定义查询 |
| **function** | 函数定义查询（最高频） |
| **operator** | sink 查询（所有漏洞模式的核心入口） |
| **import** | 跨文件追踪入口 |

**不建索引的节点**：branch、parameter、return、identifier、const、annotation、dependency — 数据量大但查询频率低，需要时从 igraph 图中遍历获取。

**用途示例：**

```sql
-- Web 列表页：不加载图就能查到某文件有哪些函数
SELECT node_name, lineno, extra FROM ast_node_index
WHERE file_path = '/app/routes.php' AND node_label = 'function';

-- Sink 查询：某文件中所有函数调用操作符
SELECT node_name, lineno FROM ast_node_index
WHERE file_path = '/app/routes.php' AND node_label = 'operator';

-- 增量更新：快速判断哪些文件变了
SELECT file_path FROM file_hashes
WHERE content_hash != '<new_hash>';

-- 全局搜索：某函数在哪些文件中定义
SELECT DISTINCT file_path, lineno FROM ast_node_index
WHERE node_name = 'run' AND node_label = 'function';
```

## 6. 图分析层设计

### 6.1 GraphAnalyzer — 图上回溯分析

核心思路：**将现有 `parameters_back` / `function_back` 的逻辑从"递归遍历 AST"改为"在 igraph 上遍历"**。

```python
class GraphAnalyzer:
    """在 igraph 图上执行回溯分析和判定"""

    def __init__(self, graph: igraph.Graph, trace_cache: TraceCache,
                 source_registry: SourceRegistry):
        self.graph = graph
        self.trace_cache = trace_cache
        self.source_registry = source_registry
        self._decision_cache = {}

    # ── 6.1.1 参数可控性追踪 ──

    def parameters_back(self, var_vid: int, context_vid: int) -> AnalysisResult:
        """
        在图上追踪变量可控性

        对应现有 parameters_back() 的图版本:
        - 从 var_vid 开始，沿 ASSIGNS_FROM 边反向追踪
        - 到达 source 节点 → 判定可控 (code=1)
        - 到达 repair function → 判定安全 (code=2)
        - 无法确定 → 判定未确认 (code=3)

        参数:
            var_vid: 待追踪变量的 igraph vertex id
            context_vid: 上下文节点 (函数/文件) id，限定搜索范围

        返回:
            AnalysisResult(code, chain, reason)
        """
        pass

    # ── 6.1.2 函数定义查找 ──

    def find_function_def(self, func_name: str, language: str = None) -> list[int]:
        """
        在图中查找函数定义节点

        对应现有 function_back() 的查找部分:
        - 先查 TraceCache 内置知识库
        - 再在图中搜索 Function 节点

        返回:
            匹配的 vertex id 列表
        """
        pass

    # ── 6.1.3 跨文件追踪 ──

    def cross_file_trace(self, import_vid: int, target_var: str) -> AnalysisResult:
        """
        跨文件追踪：沿 IMPORTS 边跳转到被导入文件

        对应现有 deep_parameters_back():
        - 从 Import 节点找到目标文件
        - 在目标文件中继续追踪
        """
        pass

    # ── 6.1.4 分支约束分析 ──

    def analyze_branch_constraint(self, cond_vid: int, sink_vid: int) -> BranchAnalysis:
        """
        分支约束分析：判断 sink 是否在受保护分支中

        对应现有 _find_sink_branch() + BranchConstraint:
        - 找到 sink 所在的条件分支
        - 检查同分支内是否有安全约束 (is_numeric, ctype_alnum 等)
        - 返回: protected=True/False
        """
        pass

    # ── 6.1.5 数据流路径搜索 ──

    def find_taint_paths(self, source_vid: int, sink_vid: int,
                         max_depth: int = 15) -> list[TaintPath]:
        """
        找从 source 到 sink 的所有数据流路径

        对应现有 analysis() 的完整追踪逻辑:
        - BFS/DFS 沿 ASSIGNS_FROM, CALLER_ARG, RETURNS, FLOWS_TO 边
        - 记录路径上每个节点的决策
        - 路径 + 决策 = 完整分析过程
        """
        pass

    # ── 6.1.6 决策标记 ──

    def mark_decision(self, vid: int, decision_type: str, detail: dict):
        """
        在图上标记分析决策点

        扩展现有 chain.append() 的概念:
        - 在节点的属性中记录分析时的决策
        - 这些标记会被持久化到 .graphmlz，二次分析时可见
        """
        pass
```

### 6.2 AnalysisResult 数据结构

```python
class AnalysisResult:
    """图分析结果 — 对应现有 chain + code 的增强版"""
    code: int           # 1=可控, 2=安全, 3=未确认, -1=不可控
    reason: str         # 分析结论文本
    chain: list[DecisionNode]  # 决策节点链
    path: list[int]     # 图上的 vertex id 路径

class DecisionNode:
    """决策节点 — 现有 chain tuple 的增强版"""
    node_type: str      # 'Assignment', 'FunctionCall', 'Branch'...
    node_content: str   # 代码片段
    file_path: str
    lineno: int
    # 新增字段
    decision_type: str  # 'sink_match', 'taint_flow', 'repair_function',
                         # 'branch_constraint', 'source_discovery', 'cross_file'
    decision_detail: dict  # 额外上下文信息
    vid: int            # igraph vertex id (用于二次分析时回查)

class TaintPath:
    """污点传播路径"""
    source_vid: int     # 源节点
    sink_vid: int       # 汇节点
    vertices: list[int] # 路径上的节点序列
    decisions: list[DecisionNode]  # 每个节点的分析决策
    is_blocked: bool     # 是否被修复函数/分支约束阻断
    blocked_by: str      # 阻断原因
```

## 7. 二次分析 API

### 7.1 AstGraphSession — 二次分析入口

```python
class AstGraphSession:
    """
    二次分析会话 — 加载已构建的图进行任意查询

    使用方式:
        session = AstGraphSession.load('/path/to/project/graph/')
        session.query_functions(name_pattern='*Controller*')
        session.query_taint_paths(source='$_GET', sink='system')
        session.get_decision_chain(vul_id=42)
    """

    def __init__(self, graph: igraph.Graph, project_id: int):
        self.graph = graph
        self.project_id = project_id
        self.analyzer = GraphAnalyzer(graph, trace_cache, source_registry)
        self.query = GraphQueryBuilder(graph)

    # ── 加载 ──

    @classmethod
    def load(cls, graph_dir: str) -> 'AstGraphSession':
        """从文件加载图，创建分析会话"""
        io = AstGraphIO(graph_dir)
        graph = io.load()
        project_id = cls._read_project_id(graph_dir)
        return cls(graph, project_id)

    @classmethod
    def from_scan(cls, graph: igraph.Graph, project_id: int,
                  graph_dir: str) -> 'AstGraphSession':
        """从扫描阶段直接创建 (跳过文件加载)"""
        return cls(graph, project_id)

    # ── 结构查询 ──

    def query_functions(self, name_pattern: str = None,
                        language: str = None,
                        class_name: str = None) -> list[FunctionInfo]:
        """
        查询函数定义

        示例:
            session.query_functions(name_pattern='run')
            session.query_functions(class_name='App')  # App 类的所有方法
            session.query_functions(language='python')
        """
        pass

    def query_classes(self, name_pattern: str = None) -> list[ClassInfo]:
        """查询类/结构体定义"""
        pass

    def query_calls(self, callee_name: str = None,
                    file_path: str = None) -> list[CallInfo]:
        """
        查询函数调用

        示例:
            session.query_calls(callee_name='system')  # 所有 system() 调用点
            session.query_calls(file_path='routes.php')  # 某文件的所有调用
        """
        pass

    def query_variables(self, name: str = None,
                        scope: int = None) -> list[VariableInfo]:
        """查询变量定义和引用"""
        pass

    def query_imports(self, file_path: str = None) -> list[ImportInfo]:
        """查询导入/包含关系"""
        pass

    def query_file_structure(self, file_path: str) -> FileStructure:
        """
        获取文件的结构概览

        返回: 函数列表、类列表、导入列表、代码行数等
        """
        pass

    def get_subgraph(self, file_path: str = None,
                     function_fqn: str = None,
                     lineno_range: tuple = None) -> igraph.Graph:
        """
        提取子图

        示例:
            session.get_subgraph(file_path='app.php')  # 整个文件
            session.get_subgraph(function_fqn='App::run')  # 某个函数
            session.get_subgraph(lineno_range=(100, 200))  # 某代码段
        """
        pass

    # ── 分析查询 ──

    def query_taint_paths(self, source_pattern: str,
                          sink_name: str) -> list[TaintPath]:
        """
        查询从 source 到 sink 的污点传播路径

        示例:
            session.query_taint_paths('$_GET', 'system')
            session.query_taint_paths('request.getParameter', 'query')
        """
        pass

    def query_vulnerability_context(self, vul_result_id: int) -> VulnContext:
        """
        查询漏洞结果的完整分析上下文

        返回:
            - 漏洞的 sink 节点
            - 完整的 taint path
            - 每个节点的分析决策
            - 被过滤掉的中间路径 (如有)
            - 分支约束详情
        """
        pass

    def query_rejected_sinks(self, sink_name: str = None) -> list[RejectedSink]:
        """
        查询被 tamper filter 过滤掉的 sink

        回答"为什么没报"的问题
        """
        pass

    # ── 自定义图查询 ──

    def bfs(self, start_vid: int, edge_types: list[str] = None,
            max_depth: int = 10) -> list[list[int]]:
        """
        自定义 BFS 遍历

        edge_types: 限定边类型 (如 ['ASSIGNS_FROM', 'CALLER_ARG'])
        """
        pass

    def find_shortest_path(self, src_vid: int, dst_vid: int,
                           edge_types: list[str] = None) -> list[int]:
        """查找最短路径"""
        pass

    def get_neighbors(self, vid: int, direction: str = 'both',
                      edge_type: str = None) -> list[int]:
        """获取邻居节点"""
        pass

    def filter_nodes(self, label: str = None, language: str = None,
                     name: str = None, lineno_min: int = None,
                     lineno_max: int = None) -> list[int]:
        """按属性过滤节点"""
        pass

    # ── 导出 ──

    def export_subgraph(self, output_path: str,
                        vids: list[int], format: str = 'graphmlz'):
        """导出子图为文件"""
        pass

    def to_cypher_queries(self) -> list[str]:
        """将图结构导出为 Cypher 查询 (用于迁移到 Neo4j)"""
        pass

    def visualize(self, vids: list[int] = None, output_path: str = None):
        """可视化子图 (使用 matplotlib/Graphviz)"""
        pass
```

### 7.2 CLI 二次分析命令

```
python kunlun.py analyze <query_type> [query_arg] [-g <dir>] [-s <scan_id>] [-l <language>]
# 默认自动查找 workspace 中最新 scan，无需指定 -g
  analyze overview                                       # 项目概览
  analyze file <path>                                    # 文件结构
  analyze function <name>                               # 函数详情
  analyze trace <file:line>                             # 污点路径追溯
  analyze search [label:name]                            # 节点搜索
```

### 7.3 Web 界面集成

```
在 Web 界面中新增 "AST Graph" 页签:

1. 项目概览: 文件列表 + 每个文件的函数/类数量 (读 SQLite 索引)
2. 函数浏览器: 选中函数后展示其子图
3. 调用关系: 选中函数后展示 callers/callees 关系图
4. 漏洞追溯: 选中漏洞结果后展示完整的 taint path + 决策节点
5. 自定义查询: 输入 source + sink，实时展示污点路径
```

## 8. 扫描流程改造

### 8.1 改造后的扫描流程

```
scan()
  │
  ├── 1. Pretreatment.parse()
  │     → 各文件解析为原生 AST
  │     → 同时计算 file_hash 存入 SQLite
  │
  ├── 2. 增量判断
  │     ├── 已有 .graphmlz → 加载旧图
  │     │     └── 对比 file_hash，标记需更新的文件
  │     └── 无 .graphmlz → 全量构建
  │
  ├── 3. AstGraphBuilder.build()
  │     ├── 未变更文件: 保留旧图中的子图
  │     ├── 变更文件:
  │     │     ├── graph.delete_file_subgraph(file_path)
  │     │     ├── {lang}Normalizer.normalize(raw_ast)
  │     │     └── build_from_normalized(nodes, edges)
  │     └── 新增文件: 同上
  │
  ├── 4. VulnerabilityMatcher.scan()
  │     → 使用 GraphAnalyzer 在图上做回溯分析
  │     → 而非直接操作内存 AST
  │
  ├── 5. 结果存储
  │     ├── ScanResultTask (已有)
  │     ├── ResultFlow (已有)
  │     └── AstNodeIndex (新增，SQLite 索引)
  │
  ├── 6. AstGraphIO.save()
  │     └── 图 + 决策标记 → .graphmlz
  │
  └── 7. 关闭 / 清理
```

### 8.2 与现有引擎的兼容策略

**不一次性替换现有引擎，采用双模运行：**

```
Phase 1 (兼容模式):
  parse → igraph 图 + 原有内存 AST 并存
  分析引擎仍用内存 AST (现有逻辑不动)
  图仅用于存档 + 二次分析 API

Phase 2 (切换模式):
  分析引擎改为读 igraph 图
  用 GraphAnalyzer 替代直接 AST 遍历
  结果与 Phase 1 对比验证

Phase 3 (纯图模式):
  移除内存 AST 依赖
  所有分析在图上完成
```

### 8.3 迁移映射表

| 现有模块 | 图版本替代 | 说明 |
|---------|-----------|------|
| `ast_object.get_nodes(file)` | `graph.vs.select(file_path=file)` | 从 SQLite 索引获取子图后加载 |
| `ast_object.pre_result` | `AstGraphIO.load()` | 图文件替代内存字典 |
| `analysis()` 遍历 AST 节点 | `GraphAnalyzer.find_sinks()` | 在图中找 FunctionCall 节点 |
| `parameters_back()` 递归 | `GraphAnalyzer.parameters_back()` | 沿 ASSIGNS_FROM 边反向遍历 |
| `function_back()` 查找 | `GraphAnalyzer.find_function_def()` | 按名称搜索 Function 节点 |
| `deep_parameters_back()` | `GraphAnalyzer.cross_file_trace()` | 沿 IMPORTS 边跨文件 |
| `chain.append(tuple)` | `DecisionNode + mark_decision()` | 在节点属性中记录决策 |
| `TraceCache` | **保留不变** | 图分析层调用 TraceCache |
| `Source Discovery` | **保留不变** | 图分析层调用 Source Discovery |
| `BranchConstraint` | `GraphAnalyzer.analyze_branch_constraint()` | 从图结构分析分支关系 |
| `is_controllable()` | **保留不变** | 判定逻辑不变，输入从图读取 |
| `grep 阶段` | **保留不变** | 正则 grep 仍在文件层面做 |
| `ResultFlow` | **保留不变** | 结果存储格式不变 |
| `ScanResultTask` | **保留不变** | 结果存储格式不变 |

## 9. 性能预估

### 9.1 基于实测数据

| 指标 | 实测值 (python-igraph) | 说明 |
|------|----------------------|------|
| 20万节点创建 | 0.18s | WordPress 级项目 |
| 20万节点 + 28万边 | 1.5MB (.graphmlz) | 压缩后 |
| 图文件加载 | 1.3s | 启动时一次性 |
| 邻居查询 | <0.0001s | 单次 |
| BFS 最短路径 | 0.016s | 20万节点图 |
| 增量删除 1 文件 (200节点) | <0.01s | |
| 增量删除+插入+保存 | 0.02s | 单文件 |
| CI 全流程 (加载+1文件+保存) | ~1.3s | |

### 9.2 对扫描时间的影响

| 阶段 | 现有耗时 (估) | 图化后 (估) | 差异 |
|------|-------------|-----------|------|
| Parse (phply/esprima/ast) | ~5s / 千文件 | ~5s / 千文件 | 不变 (同一 parser) |
| Normalize + 图构建 | — | +2s / 千文件 | 新增 |
| grep 阶段 | ~2s | ~2s | 不变 |
| Match + 回溯分析 | ~10s / 千文件 | ~10-12s | 略增 (图遍历 vs 内存 AST) |
| 结果存储 | ~1s | ~1.5s | 略增 (图保存) |
| **总计** | **~18s** | **~22s** | **+20%** |
| 二次查询 (现有) | 需重新 scan | 直接加载图 (~1.3s) | **巨大改善** |

## 10. 存储路径

```
<project_dir>/
  db/
    kunlun.db              # SQLite (已有)
  .kunlun_graph/
    ast_graph.graphmlz      # igraph 图文件 (~1.5-5MB)
    meta.json               # 项目元信息 (project_id, scan_time, languages)
```

`meta.json` 格式：

```json
{
    "project_id": 1,
    "target_directory": "/path/to/project",
    "scan_time": "2026-06-17T18:30:00",
    "languages": ["php", "javascript"],
    "file_count": 1250,
    "node_count": 185000,
    "edge_count": 260000,
    "kunlun_version": "2.16.0"
}
```

## 11. 实施路线图

### 目录结构

```
core/graph/
  __init__.py              # 模块入口，动态加载 Normalizer
  node_edge_schema.py      # UnifiedNode / UnifiedEdge / 节点边标签枚举
  graph_builder.py         # AST 图构建器（igraph 顶点/边属性映射）
  graph_pipeline.py        # 扫描流水线（pretreatment → normalize → edge_builders → graph）
  graph_analyzer.py        # 图上回溯分析（find_sinks, parameters_back, function_back 等）
  graph_io.py              # 图持久化 save/load .graphmlz
  graph_query_builder.py   # 二次分析查询构建器
  sqlite_index.py          # AstNodeIndex + FileHash 索引操作
  dataflow_analyzer.py     # 数据流分析模块（独立生成 dfg 边）
  knowledge_bridge.py      # TraceCache 知识库桥接
  session.py               # AstGraphSession 二次分析会话
  edge_builders/
    __init__.py
    base.py                # BaseEdgeBuilder 抽象基类
    dfg.py                 # DataFlowBuilder（数据流边构建 + receiver 分析）
    cg.py                  # CallGraphBuilder（调用图边构建）
  normalizers/
    __init__.py            # Normalizer 注册/发现机制（for 循环自动发现）
    php/
      __init__.py
      normalizer.py        # PHP AST → 统一节点映射
    javascript/
      __init__.py
      normalizer.py        # JS AST → 统一节点映射
    python/
      __init__.py
      normalizer.py        # Python AST → 统一节点映射
    java/
      __init__.py
      normalizer.py        # Java AST → 统一节点映射
    go/
      __init__.py
      normalizer.py        # Go tree-sitter AST → 统一节点映射
    c/
      __init__.py
      normalizer.py        # C tree-sitter AST → 统一节点映射
    cpp/
      __init__.py
      normalizer.py        # C++ tree-sitter AST → 统一节点映射
    rust/ ruby/ csharp/ kotlin/ lua/ typescript/
      __init__.py
      normalizer.py        # 各语言 tree-sitter AST → 统一节点映射
```

**动态引入机制**：`normalizers/__init__.py` 维护 `register()` 装饰器，各语言 `__init__.py` 调用 `register('php')(PhpNormalizer)`。`get_normalizer(language)` 首次调用时自动 import 对应语言子包。新增语言零改动核心代码。

### Phase 1: 基础图构建（PHP 单语言验证）

**目标**: 验证 PHP AST → igraph 的完整流程

- [x] `core/graph/node_edge_schema.py` — UnifiedNode / UnifiedEdge / 节点边标签枚举
- [x] `core/graph/normalizers/php/normalizer.py` — PHP AST 归一化
- [x] `core/graph/graph_builder.py` — AstGraphBuilder
- [x] `core/graph/graph_io.py` — AstGraphIO (save/load)
- [x] `core/graph/sqlite_index.py` + Django migration — AstNodeIndex + FileHash 表
- [x] 集成到 Pretreatment — parse 后同步构建图（`graph_pipeline.py`）
- [x] 测试: 与现有引擎结果对比

### Phase 2: 图上分析验证

**目标**: 在图上实现 parameters_back，对比结果

- [x] `core/graph/graph_analyzer.py` — GraphAnalyzer 基础版
- [x] `core/graph/graph_analyzer.py` — parameters_back 图版本
- [x] `core/graph/graph_analyzer.py` — function_back 图版本（`analyze_function_return`）
- [x] 双模运行: 现有引擎 + 图引擎，对比结果（scan() = 图引擎 + fallback oldscan）
- [x] 测试: Go 8 个测试文件验证（22 漏洞检出）

### Phase 3: 二次分析 API

**目标**: 扫描完成后可加载图查询

- [x] `core/graph/session.py` — AstGraphSession（文件已创建，未集成到 CLI/Web）
- [x] `core/graph/query.py` → `core/graph/graph_query_builder.py` — GraphQueryBuilder（文件已创建）
- [x] CLI `analyze` 子命令（支持自动查找最新 scan / 指定 scan_id）
- [ ] Web 页签原型

#### Workspace 存储架构

```
workspace/
  kunlun.db              # 共享 SQLite（scans + ast_node_index + file_hash）
  <scan_id>/              # 例: 1
    graph.graphmlz        # 图持久化（igraph graphmlz 格式）
    meta.json             # 元数据（节点数、边数、哈希、时间）
```

- `core/graph/workspace.py` — WorkspaceManager（目录管理 + DB 路径）
- `core/graph/sqlite_index.py` — ScanRecord 类（scans 表 CRUD）
- 扫描时自动创建 `workspace/<scan_id>/` 并保存图 + 索引
- `analyze` 子命令 `-g` 参数可选，默认从 workspace DB 查最新 scan

### Phase 4: 多语言扩展

**目标**: 所有已支持语言的 Normalizer + 图引擎集成

- [x] PHP Normalizer (esprima/phpl_y) + 双模验证 ✅
- [x] JS Normalizer (esprima) + 双模验证 ✅
- [x] Python Normalizer (ast) ✅
- [x] Java Normalizer (javalang) + 双模验证 ✅
- [x] Go Normalizer (tree-sitter) + 双模验证 ✅（22 漏洞检出）
- [x] C Normalizer (tree-sitter) + 双模验证 ✅（2 漏洞检出）
- [x] C++ Normalizer (tree-sitter) ✅（超额完成）
- [x] Rust Normalizer (tree-sitter) ✅（超额完成）
- [x] Ruby Normalizer (tree-sitter) ✅（超额完成）
- [x] C# Normalizer (tree-sitter) ✅（超额完成）
- [x] Kotlin Normalizer (tree-sitter) ✅（超额完成）
- [x] Lua Normalizer (tree-sitter) ✅（超额完成）
- [x] TypeScript Normalizer (tree-sitter) ✅（超额完成）
- [x] 13 语言全部通过图引擎 E2E 验证 ✅

### Phase 5: 切换图模式

- [x] TypeScript core engine 模块集成（tree-sitter-typescript + pretreatment + scan 流程）
- [x] 分析引擎完全切换到图（scan() 增强 + taint enrichment + 规则覆盖）
  - scan() 增强：rule.main() 二次筛选 + vendor/test 路径过滤 + unconfirm 处理
  - taint enrichment：enrich_taint 集成 + TraceCache 按语言加载 builtin_knowledge
  - JS source roots：location/document/window/process 识别为 source variable
  - find_sinks 扩展：assign 类型属性赋值 sink（innerHTML/outerHTML）+ callee 去重
  - 新建 4 条 JS function-param-regex 规则覆盖 vustomize-match（3005/30051/3006/30061）
  - 新建 16 条 _graph 规则覆盖 JS 所有 function-param-regex 规则
  - 图引擎覆盖：function-param-regex 113 条 + java-function-param-regex 不变
  - oldscan 覆盖：only-regex 17 + framework-dependency 17 + regex-return-regex 6 + special-crx 5 + file-path 3 + vustomize-match 7 + test 2 = 57 条
- [x] 全语言 use 边生成（14 语言 Normalizer 均在 _walk_call 中生成 use 边）
  - 新增：JS/Go/C/C++/C#/Kotlin/Lua/Ruby/Rust/TypeScript（11 个语言）
  - 已有：PHP/Python/Java（3 个语言）
  - 修复：TypeScript 函数参数 label IDENTIFIER → PARAMETER、C# 参数补齐 type 属性
- [x] DFG builder parameter 节点支持（_analyze_same_variables 识别 parameter 标签作为定义端点）
- [x] enrich_taint 跨语言增强
  - SourceRegistry 跨语言统一加载（scanner.py SourceRegistryWrapper 适配 14 语言）
  - SourceRegistry 优先级高于 builtin 知识库（避免 sink 函数被 passthrough 标注覆盖）
  - builtin 完整限定名回退查询（短名+全名双名查询）
  - static_call 类型支持（enrich_taint 处理 Java static_call 节点）
- [x] Java 特殊修复
  - Java normalizer MemberReference 类型修正（无 qualifier → identifier/variable）
  - find_sinks assign LHS 递归 identifier/property 检查
- [ ] 移除内存 AST 依赖 (可选)
- [ ] 性能优化 (批量写入、索引优化)

## 12. 风险和应对

| 风险 | 影响 | 应对 |
|------|------|------|
| Normalizer 遗漏节点类型 | 图不完整 | 原始 AST 类型在 raw_type 属性中保留，可回查 |
| 图遍历性能不如内存 AST | 扫描变慢 | 双模运行验证后再切换；性能瓶颈在 grep 不在遍历 |
| .graphmlz 文件损坏 | 无法加载 | meta.json 记录校验信息；损坏时重新构建 |
| 大项目图文件过大 | 加载慢 | 20 万节点仅 1.5MB，百万级约 7.5MB，可接受 |
| 6 种语言 Normalizer 工作量大 | 开发周期长 | 先做 PHP 验证，其他语言按优先级 |
| 分析结果不一致 | 漏报/误报 | Phase 2 双模运行强制对比，差异即 bug |

## 附录 A: 现有 chain 节点类型完整列表

从调研结果中提取的所有 chain 节点类型:

| chain 类型 | 含义 | 对应图边 |
|-----------|------|---------|
| `start` | 链起始标记 | — |
| `Assignment` | 赋值语句 | ASSIGNS_FROM + ASSIGNS_TO |
| `FunctionCall` | 函数调用 | CALLS + CALLER_ARG |
| `MethodCall` | 方法调用 | CALLS + CALLER_ARG |
| `TernaryOp` | 三元运算 | TRUE_BRANCH / FALSE_BRANCH |
| `Function` | 函数定义进入 | — |
| `EndFunction` | 函数定义退出 | — |
| `Include` | include/require | IMPORTS |
| `IncludePath` | include 路径解析 | IMPORTS |
| `Global` | 全局变量声明 | — |
| `NewFunction` | 新函数定义 | HAS_METHOD |
| `NewIFBack` | if 分支回溯 | TRUE_BRANCH / FALSE_BRANCH |
| `NewWhileBack` | while 回溯 | LOOP_BODY |
| `NewForBack` | for 回溯 | LOOP_BODY |
| `NewTryBack` | try 回溯 | THROWS / CATCHES |
| `Foreach` | foreach 回溯 | LOOP_BODY |
| `NewFind` | 查找标记 | — |
| `Finished` | 修复函数阻断 | — |
| `FindEnd` | 查找结束 | — |

## 附录 B: 各语言 AST 节点数量

| 语言 | 解析器 | AST 节点类型数 | 特点 |
|------|--------|-------------|------|
| Python | ast (标准库) | ~40 | 极简，无声明节点 |
| JavaScript | esprima (ESTree) | ~100+ | Statement/Expression 后缀丰富 |
| Java | javalang | ~35+ | 显式类型系统 |
| PHP | phply (phpast) | 94 | 扁平列表输出，无根节点 |
| Go | tree-sitter-go | ~60+ | 命名节点多，goroutine/channel 独有 |
| C | tree-sitter-c | ~40+ | 指针/struct 特有 |
| C++ | tree-sitter-cpp | ~80+ | 类模板/运算符重载 |
| C# | tree-sitter-csharp | ~70+ | LINQ/async/attribute |
| Kotlin | tree-sitter-kotlin | ~80+ | 协程/扩展函数/scope function |
| TypeScript | tree-sitter-typescript | ~110+ | type annotation/decorator/enum |
| Lua | tree-sitter-lua | ~30+ | 极简，table 驱动 |
| Ruby | tree-sitter-ruby | ~50+ | block/yield/mixin |
| Rust | tree-sitter-rust | ~90+ | trait/lifetime/macro |
| Solidity | 内置 (手工解析) | ~20 | 合约/事件/修饰符 |

## 附录 C: TraceCache 知识库覆盖

| 语言 | 内置条目数 | 覆盖范围 |
|------|----------|---------|
| PHP | ~500+ | 最完善，覆盖常见 Web 函数 |
| Java | ~300+ | 框架方法覆盖好 |
| JavaScript | ~200+ | Node.js 浏览器 API |
| Python | ~200+ | 标准库 + Web 框架 |
| Go | ~150+ | 标准库为主 |
| C | ~120+ | libc + 常见函数 |
| C++ | ~100+ | STL + 常见库 |
| C# | ~100+ | .NET BCL |
| Kotlin | ~100+ | JDK + Kotlin stdlib |
| TypeScript | ~200+ | 继承 JavaScript |
| Ruby | ~100+ | 核心库 + Rails |
| Lua | ~50+ | 基础库 |
| Rust | ~80+ | std + 常见 crate |
| Solidity | ~30+ | 合约 ABI |

## 附录 D: Source Discovery 框架覆盖

| 语言 | SourceDiscovery 模块 | SourceRegistry 接口 | 覆盖的框架/场景 |
|------|---------------------|---------------------|----------------|
| PHP | source_discovery.py | is_source_variable / is_source_member | Laravel, ThinkPHP, CodeIgniter, Symfony |
| Python | source_discovery.py | is_source_variable / is_source_member | Flask, Django, FastAPI |
| JavaScript | source_discovery.py | is_source_member | Express, Koa, Hapi, Fastify; 浏览器: location.hash, document.cookie, window.name |
| Java | source_discovery.py | is_source_producer | Servlet (request.getParameter), Spring |
| Go | source_discovery.py | is_source_member | net/http (r.FormValue, r.URL.Query), os.Args |
| C | source_discovery.py | is_source_member | argv, stdin, getenv |
| C++ | source_discovery.py | is_source_member | 继承 C |
| C# | source_discovery.py | is_source_member | ASP.NET (Request.QueryString) |
| Kotlin | source_discovery.py | is_source_member | 继承 Java |
| TypeScript | source_discovery.py | is_source_member | 继承 JavaScript |
| Ruby | source_discovery.py | is_source_member | Rails (params) |
| Lua | source_discovery.py | is_source_member | 基础输入 |
| Rust | source_discovery.py | is_source_member | std::env, std::io |
| Solidity | source_discovery.py | is_source_member | msg.sender, tx.origin |
