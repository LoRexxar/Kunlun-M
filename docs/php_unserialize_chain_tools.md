# php_unserialize_chain_tools：链挖掘与 PoC 生成（深度复盘）

本文档描述插件 `php_unserialize_chain_tools` 的完整工作流：如何从 PHP 代码构建 Codedb（DataFlow DB），如何以“可触发魔术方法”为入口挖掘反序列化利用链，以及如何把链信息渲染为可执行的 PoC。

相关代码入口：
- 插件入口与参数：[core/plugins/phpunserializechain/main.py](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py)
- Codedb 生成：[core/plugins/phpunserializechain/dataflowgenerate.py](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/dataflowgenerate.py)
- DataFlow 动态表：[web/index/models.py](file:///d:/program/Kunlun_M/web/index/models.py#L415-L460)

## 1. 使用方式与前置条件

### 1.1 前置条件
- 插件依赖 Django ORM，会动态创建数据表；首次运行前需完成数据库初始化：
```bash
python kunlun.py init initialize
```

### 1.2 运行方式
```bash
python kunlun.py plugin php_unserialize_chain_tools -t <target_path>
```

常用参数：
- `-t/--target`：扫描目标（建议传目录；若传入文件路径，会自动使用其所在目录作为目标与默认输出目录）
- `-r/--renew`：重建 DataFlow DB（目标第一次跑或代码变化较大时建议使用）
- `-o/--output`：自定义输出目录（默认 `<target>/.kunlunm_unserialize_poc/`）

## 2. 总体流程（从目标到 PoC）

插件主流程非常直接：
1. 构建或加载 DataFlow DB（Codedb）
2. 从“可触发的魔术方法”出发挖掘调用链，得到 `available_chains`
3. 将每条链渲染成 `chain_XX.php`，并生成 `summary.json` 与批量执行器

代码对应：
- 主入口：[PhpUnSerChain.main](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L89-L92)
- 链挖掘入口：[get_unserialize_magic_method](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L94-L134)
- PoC 生成入口：[generate_poc_files](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1259-L1288)

## 3. Codedb（DataFlow DB）是如何生成的

### 3.1 DataFlow DB 的本质
插件不会直接在 AST 上做复杂的跨文件解析，而是先把“类/方法/调用/赋值/控制结构”等关键节点，按一定规则写入一张 DataFlow 表，后续链挖掘只查询这张表完成递归搜索。

DataFlow 表字段（动态 Model）：
- `node_locate`：节点定位字符串（“文件/类/方法”层级路径）
- `node_sort`：同一 locate 下的顺序编号（用于筛选方法体）
- `source_node`：源表达式（例如 `Method-__destruct`、`MethodCall-$this->a->b->foo` 等）
- `node_type`：节点类型（例如 `newMethod`、`MethodCall`、`Assignment` 等）
- `sink_node`：汇表达式（例如调用参数、赋值右侧、控制结构条件等）

定义处：[get_dataflow_table](file:///d:/program/Kunlun_M/web/index/models.py#L415-L447)

### 3.2 DataFlow 表名如何确定
当你传入目标目录 `<target_path>` 时，插件取“目标路径最后一段名称”作为表名后缀：
- `DataFlow_<targetName>`

实现：
- 目标名解析：[DataflowGenerate.main](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/dataflowgenerate.py#L66-L87)
- 创建/重建逻辑：[get_dataflow_class](file:///d:/program/Kunlun_M/web/index/models.py#L449-L460)

`-r/--renew` 会删除并重建该表（仅针对对应目标名的 DataFlow 表）。

### 3.3 代码解析与写表步骤

当 DataFlow 表为空（首次扫描）时，插件会执行 `new_dataflow()`：
- 解析 target：复用 Kunlun 的 `ParseArgs` 来确定目录与 zip 解压逻辑（此插件固定按 PHP 扫描）
- 枚举文件：`Directory.collect_files()`
- AST 预处理：`ast_object.init_pre(...)` + `ast_object.pre_ast_all(['php'])`
- 遍历 PHP 文件：对每个文件 `ast_object.get_nodes(filename)` 得到节点列表
- 构造 `base_locate`：将文件路径里的 `/\\.` 替换为 `#`/`_`，形成文件级定位前缀
- 调用 `base_dataflow_generate(all_nodes, base_locate)` 将 AST 节点转成 DataFlow 行（保存在 `self.dataflows`）
- 批量写入 DB（并对地址引用 `&123` 做全局偏移，避免不同文件的引用 id 冲突）

核心代码：
- [DataflowGenerate.new_dataflow](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/dataflowgenerate.py#L89-L145)

## 4. 链挖掘：从魔术方法入口开始

### 4.1 为什么从魔术方法开始
反序列化利用链往往不要求代码中存在显式 `unserialize()` 调用点；更常见的触发点是对象反序列化后的生命周期与魔术方法（如 `__wakeup/__destruct/__toString/__call` 等）。

插件的策略是：
- 不找 `unserialize` 的调用
- 直接枚举“可能在反序列化场景中被触发”的魔术方法作为入口

入口集合：[get_unserialize_magic_method](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L94-L105)

### 4.2 入口节点如何定位
对每一个入口魔术方法名 `__xxx`：
- 在 DataFlow 表中查询 `node_type='newMethod'` 且 `source_node` 前缀为 `Method-__xxx`
- 每个命中的 `newMethod` 节点都作为一条链的起点
- 以 `node.node_locate + '.' + node.source_node` 为前缀，再取出该方法体内的所有子节点作为搜索空间

实现：[get_unserialize_magic_method](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L106-L121)

### 4.3 deep_search_chain：递归搜索骨架

`deep_search_chain` 是链挖掘的核心递归函数，输入是“某个方法体中的 DataFlow 节点集合”，输出是“是否找到可用链”：
- 每处理一个节点，优先检查是否命中危险 sink（命中即成功）
- 若遇到“可控的 MethodCall”，则将该调用加入链并跟入目标方法继续深搜
- 在分支失败时，会回滚链与关系快照，继续搜索同一方法体的其他节点

入口与签名：[deep_search_chain](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L732-L940)

硬阈值：
- `deepth > 40` 直接终止（防止无限递归）[deep_search_chain](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L744-L746)

## 5. “危险 sink”判定与“参数可控性”判定

### 5.1 危险 sink 判定（check_danger_sink）

插件内置两类 sink：

1) 典型 RCE/写文件类 sink（需要参数可控）
- `call_user_func`
- `call_user_func_array`
- `eval`
- `system`
- `file_put_contents`
- `create_function`

每个 sink 会指定“必须可控”的参数下标（例如 eval 的第 0 个参数），逐一调用 `check_param_controllable(...)`。

实现：[check_danger_sink](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L429-L485)

2) CTF 风格输出 sink（弱判定）
- `echo/printf/print_r/var_dump/die/exit`
- 输出内容若命中 `flag|ctf\{|$flag|key|secret` 也会视为 sink

实现：[check_danger_sink](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L487-L505)

### 5.2 参数可控性判定（check_param_controllable）

这个函数决定“某个调用/赋值的表达式是否可由反序列化 payload 控制”。主要判定路径：
- 若表达式含 `Variable-$this->...`：直接认为可控（对象属性可控）
- 若表达式是局部变量：尝试在同一 locate 中向上找 `Assignment` 回溯来源，直到找到 `$this->...` 或形参来源
- 若表达式匹配当前方法的 `newMethodparams`：认为形参可控（由上层调用传入）
- 内部用 `trace_stack` 做去重防环（避免重复回溯同一参数/节点）

实现：[check_param_controllable](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L606-L706)

## 6. 方法跟入、动态调用与隐式触发

### 6.1 只在“调用目标可控”时跟入 MethodCall
链扩展的关键分支是：
- 当前节点是 `MethodCall`
- 且 `source_node` 可控（通常意味着 `$this->a->b->foo(...)` 的 `$this->a->b` 可控）
满足则：
1) 把该节点 append 到链 `unserchain`
2) 抽取属性路径与属性名（用于后续 PoC 对象图渲染）
3) 尝试在“当前类”中找到对应方法定义并递归进入其方法体
4) 若找不到该方法，则尝试 `__call` 或去继承链中找原型类实现
5) 失败则回滚关系快照并 `unserchain.pop()`，继续扫描其他节点

主逻辑位置：[deep_search_chain MethodCall 分支](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L761-L888)

### 6.2 动态属性/动态方法名（$this->a->$b / $this->a->b）
插件额外支持一部分“动态链”：
- 当检测到 `source_node` 出现多段 `->`，并且 `$this->a` 可控时，会进入动态分支
- 如果方法名本身是变量且可控，会尝试“任意类任意方法”搜索（风险更高，但能覆盖更多链）
- 否则会尝试 “任意方法名匹配” 或通过 `__call` 兜底

实现：
- 动态判定：[check_dynamic_class_var_exist](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L707-L730)
- 动态分支处理：[deep_search_chain 动态分支](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L800-L830)

### 6.3 赋值与控制结构触发 __get/__set 等
插件并不只看“显式 MethodCall”：
- 赋值左值为动态属性时可能触发 `__set(prop, value)`，会尝试跟入 `__set`
- 右值读取动态属性时可能触发 `__get` 或 `__call`，会尝试从 `sink_node` 继续跟踪
- 控制结构（if/while/try 等）里出现动态属性访问，也会触发相同的跟踪逻辑

实现：[deep_search_chain Assignment/switch 分支](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L893-L926)

## 7. 关系与属性：PoC 渲染的“数据燃料”

### 7.1 analysis_properties：可控属性名集合
链挖掘过程中会持续从表达式里提取 `->prop` 形式的属性名，写入 `current_chain_properties`，最终固化到链结果的 `analysis_properties` 字段。

实现：
- 提取函数：[record_chain_properties_from_expression](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1025-L1048)
- 写入链结果：[record_available_chain](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1154-L1173)

### 7.2 recursive_relations：对象关系路径（把下一跳对象挂在哪里）
当挖链命中一个“可控 MethodCall”并准备跟入时，插件会从 `source_node/sink_node` 里抽取属性访问路径（例如 `['a','b']`），并记录一条 relation：
- `from_class`：当前类
- `to_method`：将要跟入的方法
- `property_path`：用于对象图连边的路径（会对长路径进行“去掉末段”的规整）
- `deepth`：递归深度（用于调试/理解链结构）

提取函数：[extract_property_paths](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1049-L1078)

记录点：[deep_search_chain 关系记录段](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L771-L792)

## 8. 链结果结构与去重策略

### 8.1 链结果（available_chains）结构
每条链最终会被固化成一个 dict，核心字段包括：
- `chain_id`：入口类/方法与 sink 的简要标识
- `entry_class` / `entry_method`
- `class_sequence`：链上的类序列（去重后）
- `method_sequence`：链上的方法序列（去重后，主要为 `newMethod*`）
- `chain_items`：链节点详细列表（每个节点包含 type/locate/source/sink 等）
- `recursive_relations`：对象连边路径列表（见上一节）
- `analysis_properties`：可控属性名列表（见上一节）

实现：[parse_chain_nodes](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L947-L977)、[record_available_chain](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1154-L1173)

### 8.2 去重（fingerprint）
为了避免同一条链被重复输出，插件对 `chain_items` 做 JSON 指纹：
- `fingerprint = json.dumps(chain_items, sort_keys=True, ensure_ascii=False)`
- 若 fingerprint 已存在则跳过记录

实现：[record_available_chain](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1154-L1163)

## 9. PoC 生成：从链数据到可执行 PHP

### 9.1 输出目录与生成文件
输出根目录：
- `-o` 指定则使用 `-o`
- 否则 `<target>/.kunlunm_unserialize_poc/`

生成文件：
- `php_unserialize_chain_summary.json`：所有链的汇总
- `chain_XX.php`：每条链一个 PoC
- `poc_all_chains.php`：批量执行器（按文件名顺序执行所有 chain）

实现：[generate_poc_files](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1259-L1288)

### 9.2 单链 PoC 的结构（chain_XX.php）
单链文件的主要内容：
1) class stub：为链上的每个类生成“若不存在则定义”的空类（避免运行时报类缺失）
2) `build_payload_chain_XX()`：构造对象图、设置可控属性、输出 `serialize($root)` 结果
3) trigger code：根据入口魔术方法补充触发语句（可选）

渲染入口：[render_chain_php](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1194-L1240)

### 9.3 对象图构造（关系路径优先 + 回退）
对象图连边的路径选择顺序：
1) 优先使用 `recursive_relations[].property_path`
2) 若为空，则从链节点里临时抽取路径并补 `['next']` 兜底
3) 若仍无路径，则输出注释提示手动补充

实现：
- 关系路径抽取：[build_relation_paths_from_recursive](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1175-L1181)
- 回退路径构造：[build_recursive_relation_paths](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1079-L1088)
- 生成对象图函数：[render_chain_function](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1090-L1153)

### 9.4 可控属性赋值（analysis_properties 优先 + 回退）
PoC 会尽量把链中出现的属性名设为字符串 payload（例如 `PAYLOAD_prop`）以触发后续方法调用/危险 sink。

属性名来源顺序：
1) 优先使用链结果的 `analysis_properties`
2) 若为空，则从链节点 `source_node/sink_node` 再抽一遍
3) 若仍为空，PoC 中会提示“未找到属性名，需要手动补充”

提取函数：[extract_controllable_properties](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1002-L1023)

### 9.5 触发语法（按入口魔术方法生成）
插件会按入口方法生成可读的“触发提示”（hint），默认不在 PoC 内主动触发魔术方法：
- `__toString`：提示 `(string)$root;`
- `__call`：提示 `$root->undefinedMethod('PAYLOAD_CALL');`
- `__invoke`：提示 `$root();`
- `__wakeup`：提示“目标侧 unserialize() 会自动触发 __wakeup”
- `__destruct/default`：提示“由对象生命周期触发”

实现：[build_trigger_code](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1183-L1192)

## 10. 输出文件说明（summary.json）

`php_unserialize_chain_summary.json` 用于辅助人工复核与二次处理，包含：
- 生成时间 `generated_at`
- 目标 `target`
- 链数量 `chain_count`
- 链数组 `chains[]`（每个元素是第 8 节描述的链结构）

写入点：[generate_poc_files](file:///d:/program/Kunlun_M/core/plugins/phpunserializechain/main.py#L1259-L1288)

## 11. 局限性与常见坑

### 11.1 结果可执行性不等价于真实可利用
- 插件是“链挖掘与 PoC 生成辅助工具”，其成功条件是“命中 sink + 判定参数可控”，并不保证真实环境下可利用（例如依赖运行时类型、魔术方法触发条件、框架上下文等）。

### 11.2 可控性判定是启发式的
- 以 `$this->...` 为强可控信号
- 以形参为可控信号（来自上层调用）
- 以赋值回溯做局部传播
这会带来误报与漏报的可能，需要结合 `summary.json` 与生成的 `chain_XX.php` 人工确认。

### 11.3 DataFlow 表名与目标选择
- DataFlow 表名来自目标目录名；若目标传文件路径，表名可能含 `.` 等字符导致建表问题，因此建议传目录（插件已对文件 target 做了自动降级到目录）。
