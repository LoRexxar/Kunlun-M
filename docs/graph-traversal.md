# Console Graph Traversal 使用手册

> Graph Traversal 是 KunLun-M Console 模式下的交互式图查询语言，基于 Python REPL，
> 采用类似 Joern CPGQL 的链式遍历语法，支持对 AST 图进行实时的结构探索和数据流分析。

---

## 1. 快速开始

### 1.1 进入图遍历 REPL

首先在 console 中加载一个扫描结果，然后进入图遍历模式：

```
KunLun-M> load 997
[Console] Scan 997 loaded.
KunLun-M(result)> graph
[Console] Graph loaded: 42 nodes, 58 edges
=== KunLun-M Graph Traversal REPL ===
Scan ID: 997
Nodes: 42, Edges: 58

Available:
  g.function            All function nodes
  g.function.cp.ownout   Nodes owned by function 'cp'
  ...
Type 'exit()' or Ctrl+D to return.
>>>
```

### 1.2 基本概念

图遍历以 **`g`** 为入口对象，每次属性访问返回一个新的节点集合（`GraphTraversal` 实例）。
你可以不断链式访问来缩小或变换集合，最后用终端操作符获取结果。

```
>>> g.function.main.ownout.count
14
```

含义：`g` → 所有节点 → function 类型 → 名为 main → own 出边方向 → 计数

---

## 2. 节点过滤

### 2.1 按类型过滤

访问 `g.<node_type>` 返回该类型的所有节点：

```python
>>> g.function              # 所有 function 节点
>>> g.identifier            # 所有 identifier（变量名）节点
>>> g.operator              # 所有 operator（操作/调用）节点
>>> g.file                  # 所有 file 节点
>>> g.branch                # 所有 branch（分支/循环）节点
>>> g.parameter             # 所有 parameter 节点
>>> g.const                 # 所有 const（常量）节点
>>> g.import                # 所有 import 节点
>>> g.dependency            # 所有 dependency 节点
```

**12 种可用节点类型：**

| 类型 | 说明 | 示例 |
|------|------|------|
| `file` | 文件根节点 | `g.file` |
| `class` | 类/接口/结构体 | `g.class` |
| `function` | 函数/方法/构造函数 | `g.function` |
| `parameter` | 函数参数 | `g.parameter` |
| `return` | return 语句 | `g.return` |
| `identifier` | 变量/属性名 | `g.identifier` |
| `const` | 常量（字符串、数字等） | `g.const` |
| `operator` | 操作（赋值、调用、运算等） | `g.operator` |
| `branch` | 分支/循环（if/for/while 等） | `g.branch` |
| `import` | 导入语句 | `g.import` |
| `annotation` | 注解/装饰器 | `g.annotation` |
| `dependency` | 外部依赖 | `g.dependency` |

### 2.2 按名称过滤

在类型过滤后追加 `.name` 进行精确名称匹配：

```python
>>> g.function.main                 # 名为 "main" 的函数
>>> g.function.execute_command     # 名为 "execute_command" 的函数
>>> g.identifier.userInput         # 名为 "userInput" 的变量
>>> g.identifier.argv              # 名为 "argv" 的变量
```

> **注意：** 名称过滤是精确匹配（`==`），不是模糊匹配。
> 如果不确定全名，可以先用 `g.function.l()` 列出所有函数查看。

### 2.3 变量绑定

将中间结果绑定到变量，避免重复输入：

```python
>>> main_fn = g.function.main       # 绑定 main 函数
>>> main_fn.ownout.count            # main 函数拥有的节点数
>>> main_fn.cgout.count             # main 调用了多少函数
>>> main_fn.cgin.count              # 谁调用了 main
```

---

## 3. 边遍历

### 3.1 语法规则

边遍历通过 `{edge_type}{direction}` 属性实现，共 9 种边 × 2 方向 = **18 个遍历属性**：

```python
>>> g.function.main.ownout          # own 边的出方向
>>> g.function.main.dfgin           # dfg 边的入方向
>>> g.function.main.cgout           # cg 边的出方向
```

- **`out`** 后缀：当前节点集作为边的 **source**，收集 target 节点
- **`in`** 后缀：当前节点集作为边的 **target**，收集 source 节点

### 3.2 9 种边类型

| 边类型 | 含义 | out 方向示例 | in 方向示例 |
|--------|------|-------------|-------------|
| `own` | 从属关系（file→函数、函数→语句） | `g.file.ownout` — 文件拥有的所有节点 | `g.function.ownin` — 函数所属的文件 |
| `ast` | AST 子节点（表达式→操作数） | `g.operator.astout` — 操作符的 AST 子节点 | `g.identifier.astin` — 作为 AST 子节点的标识符 |
| `dfg` | 数据流（赋值传播） | `g.identifier.dfgout` — 变量值流向哪 | `g.operator.dfgin` — 操作符的数据来源 |
| `cg` | 调用图（函数调用关系） | `g.function.cgout` — 函数调用了哪些函数 | `g.function.cgin` — 谁调用了这个函数 |
| `use` | 引用关系（operator→function） | `g.operator.useout` — 操作符引用了什么 | `g.function.usein` — 函数被哪些操作符引用 |
| `alias` | 函数别名（$a = $b） | `g.function.aliasout` — 函数的别名目标 | `g.function.aliasin` — 别名指向此函数 |
| `member` | 成员访问（a.b） | `g.identifier.memberout` — 成员的子属性 | `g.identifier.memberin` — 作为成员访问目标的标识符 |
| `frg` | 文件依赖（import/include） | `g.import.frgout` — 导入语句指向的外部依赖 | `g.dependency.frgin` — 依赖被哪些导入语句引用 |
| `crg` | 类关系（继承/实现） | `g.class.crgout` — 类继承/实现了什么 | `g.class.crgin` — 什么类继承/实现了此类 |

### 3.3 通配遍历

`outall` / `inall` 沿所有边类型遍历，不限边类型：

```python
>>> g.function.main.outall           # main 函数通过所有出边能到达的节点
>>> g.function.main.inall            # 通过所有入边能到达 main 的节点
```

### 3.4 多级链式遍历

边遍历可以任意链式组合：

```python
# file → own → function → cg → function（两步调用链）
>>> g.file.ownout.cgout

# function → own → parameter（函数的参数）
>>> g.function.main.ownout

# identifier → dfg → operator → use → function（变量 → 使用处 → 被调用的函数）
>>> g.identifier.userInput.dfgout.useout
```

---

## 4. 终端操作符

终端操作符用于从节点集合中提取最终结果。

### 4.1 属性形式（自动调用，无需括号）

推荐在链式末尾使用，REPL 中直接获取值：

```python
>>> g.function.count                 # 返回 int：函数数量
7

>>> g.function.ids                   # 返回 list[int]：函数的 vid 列表
[11, 15, 19, 23, 28, 33, 37]

>>> g.function.nodes                 # 返回 list[dict]：函数的完整属性字典
[{'label': 'function', 'name': 'main', 'lineno': 10.0, ...}, ...]
```

### 4.2 方法形式（需要括号）

功能完全等价，适合需要显式调用的场景（如作为参数传递）：

```python
>>> g.function.n()                   # 等价于 .count
>>> g.function.vids()                 # 等价于 .ids
>>> g.function._nodes()               # 等价于 .nodes
```

### 4.3 格式化输出

```python
>>> g.function.l()                    # 格式化打印所有函数节点
[function] main  vid=8  L12.0
  file: tests/go/22_indirect_exec.go
  fullname: main
  type: function

[function] cmdFunc  vid=28  L0.0
  file: tests/go/22_indirect_exec.go
  fullname: cmdFunc
  type: function
  is_external: True

>>> g.function.main.l()              # 只打印 main 函数
[function] main  vid=8  L12.0
  file: tests/go/22_indirect_exec.go
  fullname: main
  type: function

>>> g.function.pprint()              # l() 的别名
```

### 4.4 源码位置

```python
>>> g.function.main.code()           # 显示节点的源码位置信息
[function] main  vid=8  L12.0  tests/go/22_indirect_exec.go
```

---

## 5. 分析函数

### 5.1 find_dfg — 数据流追踪

沿 `dfg`（数据流）边进行 BFS 搜索，返回从源到汇的路径：

```python
>>> g.find_dfg(source_vid, sink_vid)
```

**参数：**
- `source_vid` (int): 起点节点 vid
- `sink_vid` (int): 终点节点 vid
- `max_depth` (int, 默认 50): 最大搜索深度

**返回：** vid 路径列表 `[source, ..., sink]`；不可达时返回 `[]`

**示例：**

```python
# 追踪 argv 参数如何流向某个操作符
>>> g.identifier.argv.vids()[0]
17
>>> g.operator.some_op.vids()[0]
16
>>> g.find_dfg(17, 16)
[17, 16]
```

> **注意：** `find_dfg` 仅沿 `dfg` 边搜索。跨函数调用走的是 `cg` 边而非 `dfg` 边，
> 因此 `find_dfg(变量, 被调用函数)` 通常返回空。如需追踪跨函数数据流，
> 可以先通过 `cgout` 找到被调用函数，再分别追踪各函数内的数据流。

### 5.2 shortest_path — 最短路径

计算任意两个节点间的最短路径（忽略边方向）：

```python
>>> g.shortest_path(source_vid, target_vid)
```

**参数：**
- `source_vid` (int): 起点 vid
- `target_vid` (int): 终点 vid

**返回：** vid 路径列表；不可达时返回 `[]`

**示例：**

```python
>>> g.shortest_path(0, 32)
[0, 4, 12, 32]
```

---

## 6. 实战示例

### 6.1 PHP：追踪间接函数调用

场景：`$func` 变量调用 `system()`，分析别名传播链。

```python
# 1. 查看所有函数
>>> g.function.l()
[function] $func  vid=13
[function] system  vid=15

# 2. 查看 $func 的别名关系
>>> g.function._filter_by_name('$func').aliasout.l()
[function] system  vid=15

# 3. 找到 system 函数被谁引用（use 边）
>>> g.function.system.usein.l()
[operator] exec  vid=...
```

### 6.2 JavaScript：多层调用链分析

场景：`processCmd` → `exec` 的调用关系，追踪 `userInput` 污点传播。

```python
# 1. 查看函数数量
>>> g.function.count
23

# 2. 查看 processCmd 的调用目标（cgout）
>>> g.function.processCmd.cgout.l()
[function] exec  vid=32

# 3. 追踪 userInput 的数据流去向（dfgout）
>>> g.identifier.userInput.dfgout.l()
[operator] handleInput  vid=61
[parameter] input  vid=34
[identifier] userInput  vid=63

# 4. handleInput 调用了谁
>>> g.function.handleInput.cgout.l()
[function] trim  vid=41
[function] processCmd  vid=45
```

### 6.3 Java：跨类方法调用

场景：`doGet` → `executeCommand` 的调用链。

```python
# 1. doGet 的 cgout
>>> g.function.doGet.cgout.l()
[function] getParameter  vid=23
[function] executeCommand  vid=27

# 2. 谁调用了 executeCommand（cgin）
>>> g.function.executeCommand.cgin.l()
[function] doGet  vid=16

# 3. 查看所有类
>>> g._filter_by_label('class').l()
[class] MainServlet  vid=...
[class] ExecUtils  vid=...
```

> **注意：** `class` 是 Python 关键字，不能直接写 `g.class`。
> 使用 `g._filter_by_label('class')` 代替。

### 6.4 C：参数到危险函数的路径

场景：`main()` → `execute_command(cmd)` → 潜在命令注入。

```python
# 1. main 调用了什么
>>> g.function.main.cgout.l()
[function] execute_command  vid=24

# 2. 谁调用了 execute_command
>>> g.function.execute_command.cgin.l()
[function] main  vid=13

# 3. argv 的数据流去向
>>> g.identifier.argv.dfgout.l()
[operator] <  vid=16
```

### 6.5 Go：跨函数调用图

```python
# 1. main 调用了哪些函数
>>> g.function.main.cgout.l()
[function] cmdFunc  vid=28
[function] Println  vid=34

# 2. 文件拥有的所有节点
>>> g.file.ownout.count
15
```

### 6.6 Python：跨文件依赖追踪

```python
# 1. 查看所有跨文件依赖（frg 边）
>>> g.import.frgout.l()
[dependency] sys
[dependency] os
[dependency] utils

# 2. process_command 被谁引用
>>> g.function.process_command.usein.l()
[operator] process_command  vid=32

# 3. user_input 的数据流
>>> g.identifier.user_input.dfgout.l()
[operator] process_command  vid=32
[identifier] user_input  vid=34
```

---

## 7. 空结果语义

当过滤或遍历没有匹配任何节点时，返回**空集合**而非错误：

```python
>>> g.function.ZZZZZ_NONEXISTENT.count
0

>>> g.function.ZZZZZ_NONEXISTENT.ids
[]

>>> g.function.ZZZZZ_NONEXISTENT.nodes
[]
```

空集合可以继续链式操作（结果始终为空）：

```python
>>> g.function.ZZZZZ_NONEXISTENT.ownout.count
0
```

---

## 8. REPL 环境

### 8.1 预注入对象

进入图遍历 REPL 后，以下对象已自动注入：

| 对象 | 类型 | 说明 |
|------|------|------|
| `g` | `GraphTraversal` | 图遍历入口（推荐使用） |
| `graph` | `igraph.Graph` | 原始图对象（高级用法） |
| `analyzer` | `GraphAnalyzer` | 图分析器（find_sinks、parameters_back 等） |

### 8.2 Python REPL 能力

由于图遍历 REPL 基于 Python REPL，你可以使用所有 Python 语法：

```python
# 列表推导
>>> [v['name'] for v in g.function.nodes if 'cmd' in v.get('name', '')]
['execute_command']

# 循环
>>> for vid in g.function.ids:
...     v = graph.vs[vid]
...     print(vid, v['name'])

# 条件过滤
>>> main_funcs = [v for v in g.function.nodes if v['name'] == 'main']
>>> len(main_funcs)
1

# 直接访问 igraph API
>>> graph.vcount()
42
>>> graph.ecount()
58
```

### 8.3 退出 REPL

```python
>>> exit()
# 或按 Ctrl+D
```

---

## 9. 边类型详解

### 9.1 结构边（Normalizer 生成）

这些边在 AST 解析阶段由各语言 Normalizer 直接生成：

| 边 | 方向 | 含义 | 典型连接 |
|----|------|------|----------|
| `own` | file → child | 从属/包含 | file→function, file→import, function→operator |
| `ast` | parent → child | AST 子节点 | operator→identifier, operator→const |
| `use` | operator → function | 引用关系 | call operator → 被调用函数 |
| `member` | object → property | 成员访问 | `obj.prop` 中的 obj → prop |
| `frg` | import → dependency | 文件依赖 | `import os` → os dependency |

### 9.2 推导边（Edge Builder 生成）

这些边由独立的 edge_builder 模块在 AST 解析后推导生成：

| 边 | 方向 | 含义 | 典型连接 |
|----|------|------|----------|
| `dfg` | value → consumer | 数据流传播 | 赋值右侧 → 左侧变量 |
| `cg` | caller → callee | 调用图 | 函数 A → 函数 B |
| `alias` | func → target | 函数别名 | `$a = $b` 中 a → b |
| `crg` | child → parent | 类关系 | 子类 → 父类 |

### 9.3 边类型与遍历对照表

```
g.file.ownout     → file 拥有的所有节点（函数、import、顶层语句等）
g.function.ownin  → 函数所属的 file
g.function.cgout  → 函数调用了哪些函数
g.function.cgin   → 谁调用了这个函数
g.identifier.dfgout → 变量值流向哪些节点
g.operator.dfgin    → 操作符的数据来自哪些节点
g.function.aliasout  → 函数的别名目标
g.function.aliasin   → 别名指向此函数
g.import.frgout      → import 语句指向的外部依赖
g.operator.useout    → 操作符引用了什么函数
g.function.usein     → 函数被哪些操作符引用
g.identifier.memberout → 成员访问的子属性
g.class.crgout         → 类继承/实现了什么
g.class.crgin          → 什么类继承了此类
```

---

## 10. 常见问题

### Q: `g.class` 报 SyntaxError？

`class` 是 Python 保留关键字，不能直接作为属性名。使用 `_filter_by_label()` 代替：

```python
>>> g._filter_by_label('class').l()
```

### Q: `.count` / `.ids` / `.nodes` 返回 `<bound method ...>`？

在代码中（非链式末尾）直接访问这些属性时，Python 的 `__getattribute__` 可能优先返回方法对象。
在 REPL 的链式末尾使用时，`__getattr__` 会正确拦截并自动调用。
如果遇到问题，改用方法形式：

```python
>>> g.function.n()       # 代替 .count
>>> g.function.vids()     # 代替 .ids
>>> g.function._nodes()   # 代替 .nodes
```

### Q: `find_dfg` 返回空但两个节点明明相关？

`find_dfg` 只沿 `dfg` 边搜索。跨函数调用走 `cg` 边，不在 `dfg` 搜索范围内。
例如追踪 `userInput → processCmd → exec` 时：

- `userInput → processCmd` 可能通过 `dfg` 可达（同一函数内的变量传播）
- `processCmd → exec` 通过 `cg` 可达（函数调用），不在 `dfg` 搜索范围内

正确做法是分步追踪：

```python
# 先用 cg 找到调用链
>>> g.function.processCmd.cgout.l()
# 再在各函数内用 dfg 追踪数据流
```

### Q: `shortest_path` 返回空？

两个节点之间在图上确实不可达（无路径连接）。可能原因：
- 目标节点是孤立节点（如 Python docstring 被解析为 const 但无连接边）
- 图存在多个不连通的子图
- 使用 `outall`/`inall` 检查连通性

### Q: 节点名称中包含特殊字符（如 `$func`）？

使用 `_filter_by_name()` 方法：

```python
>>> g.function._filter_by_name('$func').l()
```
