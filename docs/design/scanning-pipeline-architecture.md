# Kunlun-M 扫描流水线整体架构设计文档

## 1. 概述

Kunlun-M 是一个多语言静态白盒漏洞扫描框架，采用**规则驱动 + AST 回溯分析**的混合架构。核心设计理念是：

1. **规则驱动**：每条漏洞规则定义了敏感函数（sink）和匹配模式，框架负责在目标代码中定位 sink 点
2. **AST 回溯分析**：找到 sink 后，通过 AST 节点反向追踪参数来源，判断是否可达外部可控输入（source）
3. **多语言统一接口**：6 种语言（PHP/JS/Python/Java/Go/C）共享相同的扫描入口和结果判定逻辑

## 2. 扫描流水线总览

```
用户触发扫描
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  pretreatment.py — 文件收集与 AST 预解析                   │
│  • 遍历目标目录，按扩展名收集源文件                          │
│  • 对支持 AST 的语言进行预解析（PHP/JS/Java/Python/Go/C）   │
│  • PHP: lphply → AST 节点缓存                              │
│  • Java: javalang → AST 缓存                              │
│  • JS: esprima → AST 缓存                                 │
│  • Python: ast 模块 → 代码缓存                             │
│  • Go: go/ast (通过 _ast_trace.py)                         │
│  • C: tree-sitter 或文本解析                               │
│  • 结果存入 pre_result: {file_path: {language, nodes...}} │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│  rule.py — 规则加载                                        │
│  • 从 rules/{language}/ 目录动态加载所有规则模块            │
│  • 每个规则文件定义一个类（同名），包含:                       │
│    - match: 匹配正则                                       │
│    - match_mode: 匹配模式                                  │
│    - vul_function: 敏感函数名列表                           │
│    - svid: 漏洞编号 (CVI-XXXX)                            │
│    - vulnerability: 漏洞名称                                │
│    - language: 语言标识                                     │
│    - main(): 可选的二次筛选函数                              │
│    - unmatch: 排除正则                                     │
│    - repair: 修复函数检测                                    │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│  scanner.py — 扫描调度                                     │
│  • scan() 入口，加载所有规则                                 │
│  • 对每条规则创建 SingleRule 任务                            │
│  • asyncio.gather 并发执行所有规则                            │
│  • 每个 SingleRule 独立完成: grep → AST分析 → 判定          │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│  SingleRule.process() — 单规则处理流水线                     │
│                                                           │
│  Step 1: origin_results() — 正则 grep 定位 sink             │
│  ┌───────────────────────────────────────────────────┐    │
│  │ 根据 match_mode 选择 grep 策略:                     │    │
│  │ • only-regex: 直接正则匹配，不需 AST                 │    │
│  │ • function-param-regex: 正则定位敏感函数调用         │    │
│  │ • vustomize-match: 自定义参数匹配                    │    │
│  │ • regex-return-regex: 回馈式正则匹配                  │    │
│  │ • java-function-param-regex: Java 专用模式           │    │
│  │ • go-function-param-regex: Go 专用模式              │    │
│  │ • c-function-param-regex: C/C++ 专用模式             │    │
│  │ • framework-dependency: 框架依赖版本检测             │    │
│  │ 结果: [(file_path, line_number, match_text), ...]   │    │
│  └───────────────────┬───────────────────────────────┘    │
│                      │                                     │
│  Step 2: 对每个 sink 点调用 VulnerabilityMatcher.scan()     │
│  ┌───────────────────▼───────────────────────────────┐    │
│  │ VulnerabilityMatcher (matcher.py)                   │    │
│  │                                                   │    │
│  │ 2.1 前置过滤 (filters.py)                          │    │
│  │     • 白名单过滤                                   │    │
│  │     • 特殊文件过滤                                  │    │
│  │     • 注释过滤                                     │    │
│  │                                                   │    │
│  │ 2.2 初始化修复函数/可控参数列表 (init_php_repair)  │    │
│  │     • 加载 rules/tamper/demo_{lang}.py             │    │
│  │     • 根据 svid 筛选适用的修复函数                   │    │
│  │                                                   │    │
│  │ 2.3 按语言分派到 _scan_{language}()                │    │
│  │                                                   │    │
│  │ 2.4 _scan_{lang}() 内部流程:                       │    │
│  │     a) 根据 match_mode 选择分析路径                  │    │
│  │     b) function-param-* 模式:                       │    │
│  │        - 可选: 调用 rule.main() 二次筛选             │    │
│  │        - 调用 {lang}_scan_parser() 进行 AST 回溯     │    │
│  │     c) 解析结果 → _parse_ast_result()              │    │
│  │     d) 返回 (is_vulnerability, reason, chain)      │    │
│  └───────────────────────────────────────────────────┘    │
│                                                           │
│  Step 3: 结果汇总与存储                                    │
│  ┌───────────────────────────────────────────────────┐    │
│  │ • is_vulnerability=True → 构建 VulnerabilityResult  │    │
│  │ • 存储到数据库 (ScanResultTask + ResultFlow)         │    │
│  │ • code=4 (New Core) → 触发新规则生成                 │    │
│  └───────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## 3. 匹配模式详解

### 3.0 v3.0 图引擎模式（当前主路径）

v3.0 全面基于 AST 图引擎，sink 匹配流程为：`build_ast_graph()` → `find_sinks()` → `parameters_back()`。

大部分规则通过 `vul_function` 的 fullname sink 走图引擎路径，不依赖传统 match_mode 分流。

### 3.1 独立扫描模式（不依赖图引擎）

| match_mode | 说明 | 是否需要 AST |
|---|---|---|
| `file-pattern` | 文件名正则 + 内容正则双重匹配。规则可选设置 `file_pattern` 限制文件名范围（如 `r'.*Mapper\.xml$'`），`match` 定义内容匹配正则。适用场景：MyBatis `${}` 检测等需要按文件名限定扫描范围的规则 | ❌ |
| `framework-dependency` | 框架依赖版本检测 (pom.xml 等) | ❌ |
| `file-path-regex-match` | 敏感文件名/路径匹配 | ❌ |
| `special-crx-keyword-match` | Chrome 扩展关键词匹配 | ❌ |

### 3.2 图引擎 sink 规则的 match_mode

以下 match_mode 的规则会被 `scan()` 收集后通过图引擎处理：

| match_mode | 说明 |
|---|---|
| `function-param-regex` | 通用 sink 规则（PHP/JS/Python/Ruby/TypeScript 等） |
| `java-function-param-controllable` | Java 专用 sink 规则 |
| `go-function-param-controllable` | Go 专用 sink 规则 |
| `c-function-param-controllable` | C/C++ 专用 sink 规则 |

### 3.3 已跳过模式（LEGACY）

以下 match_mode 的规则在 `scan()` 中被跳过，不参与图引擎扫描：

| `only-regex` | 纯正则匹配（已跳过） |
| `vustomize-match` | 自定义参数匹配（已跳过） |
| `regex-return-regex` | 回馈式正则（已跳过） |
| `only-keyword` | 纯关键字匹配（已跳过） |

> 以下为旧引擎（LEGACY）的匹配模式说明，保留仅供参考。v3.0 图引擎模式下不经过此路径。

### 3.10 [LEGACY] `function-param-regex` 模式的 grep 策略

对于传统 PHP/JS 规则，`match` 字段是敏感函数名（如 `system`），需要包装成正则：

```python
# 单函数: fpc_single = '[f]\s*\((.*)(?:\))'  → system\s*\((.*)(?:\))
# 多函数: fpc_multi  = '(?:[f])\s*\((.*)(?:\))' → (?:eval|system)\s*\((.*)(?:\))
# JS宽松:  fpc_loose  = r'(?:(\A|\s|\b)[f])({fpc})?\b'
```

对于 Java/Go/C 的新规则，`match` 字段直接作为完整正则使用，支持 `|` 多选。

### 3.2 rule.main() 二次筛选

Java 和 C 语言规则支持可选的 `main()` 函数做二次筛选：

```python
# 在 _scan_java() 和 _scan_c() 中:
main_input = source_lines[idx].strip()  # 读取源码行
main_result = self.single_rule.main(main_input)
if main_result is False:
    return False, 'Filtered by rule.main()'  # 跳过此 sink
# main_result is None → 不做筛选，继续 AST 分析
# main_result is not False → 通过筛选，继续
```

这允许规则在不修改扫描引擎的情况下，对 grep 结果做精细过滤（例如只匹配特定调用模式的函数）。

## 4. AST 回溯分析统一接口

### 4.1 scan_parser 统一签名

所有语言引擎的入口函数签名一致：

```python
def scan_parser(
    sensitive_func,    # [str] 敏感函数名列表 (sink 函数)
    vul_lineno,        # int  漏洞所在行号
    file_path,        # str  当前分析文件路径
    repair_functions=[],   # [str] 修复函数列表
    controlled_params=[],  # [str] 已知可控参数列表
    svid=0             # int  漏洞编号
) -> list:  # 返回 [{'code': int, 'source': [...], 'source_lineno': int, ...}, ...]
```

### 4.2 结果码 (code) 语义

| code | 含义 | 处理 |
|---|---|---|
| **1** | 参数可控，漏洞确认 | `is_vulnerability=True` |
| **2** | 参数可控但已修复 | `is_vulnerability=False` |
| **3** | 疑似可控（无法确定） | 根据 `is_unconfirm` 标志决定 |
| **4** | 新危险函数（code 4 且 chain>1 = 配置型漏洞） | 触发 NewCore |
| **-1** | 分支约束阻断 | 仅在无其他结果时保留 |

### 4.3 结果解析流程

```python
def _parse_ast_result(self, result):
    # 优先级: code=1 > code=4 > code=3 > code=2 > 其他
    # code=1: 直接确认漏洞
    # code=4+chain: 配置型漏洞确认
    # code=4-chain: 新规则生成信号
    # code=3: 疑似（取决于 is_unconfirm）
    # code=2: 已修复
    # 其他: 不可控
```

## 5. CAST — 跨语言参数可控性分析

`cast.py` 中的 `CAST` 类实现了**跨语言参数可控性检查**（用于 `vustomize-match` 模式）。

### 5.1 工作流程

```
CAST.is_controllable_param()
    │
    ├─ 1. 用规则正则从 code 中提取参数名
    ├─ 2. 调用 rule.main() 获取筛选后的参数列表
    ├─ 3. 对每个参数:
    │     a. 判断是否包含变量（正则提取）
    │     b. 按语言分派到对应的 anlysis_params() 函数
    │        - php_anlysis_params()
    │        - js_analysis_params()
    │        - python_analysis_params()
    │        - go_analysis_params()
    │        - c_analysis_params()
    │     c. 返回 (is_co, cp, expr_lineno, chain)
    └─ 4. 汇总结果
```

### 5.2 块代码分析

`CAST.block_code(block_position)` 提供了多种代码块提取模式：

| position | 含义 | 用途 |
|---|---|---|
| 0 (in-function-up) | 函数体内 sink 上方代码 | 回溯变量定义 |
| 1 (in-function-down) | 函数体内 sink 下方代码 | 前瞻检查 |
| 2 (in-current-line) | 当前行 | 行级分析 |
| 3 (in-function) | 整个函数体 | 完整函数分析 |

## 6. 各语言 AST 解析器选型

| 语言 | 解析器 | 包名 | 特点 |
|---|---|---|---|
| PHP | lphply (自维护) | `phply` | PLY 手写 parser，支持 PHP 5.6-8.5 |
| JavaScript | esprima (自维护 lesprima) | `esprima` | 修正 22 个 bug，兼容 JS 全语法 |
| Python | 内置 `ast` 模块 | `ast` | 无额外依赖，最简洁 |
| Java | javalang (自维护 ljavalang) | `javalang` | 修正后支持 Java 全语法 |
| Go | `go/ast` (标准库) | `go` | 通过 `_ast_trace.py` 桥接 |
| C/C++ | tree-sitter / 文本分析 | - | 混合策略：AST + 文本行级追踪 |

## 7. 预处理模块 (pretreatment.py)

### 7.1 职责

`Pretreatment` 类负责扫描前的文件收集和 AST 预解析，是整个流水线的准备阶段。

### 7.2 核心流程

```python
class Pretreatment:
    def pre_ast_all(self, lan=None, is_unprecom=False):
        # 1. 将文件列表放入队列
        # 2. 启动 10 个并发协程
        # 3. 每个协程调用 pre_ast() 处理队列中的文件
        # 4. 预解析结果存入 self.pre_result
```

预解析为各语言引擎缓存 AST 节点，避免每个规则扫描时重复解析同一文件。PHP 引擎的 `ast_object.get_nodes(file_path)` 即从此缓存读取。

## 8. 规则系统 (rule.py + rules/)

### 8.1 规则加载

```python
class Rule:
    def __init__(self, lans=None):
        # 1. 加载 base/ 目录的通用规则
        # 2. 加载各语言目录 rules/{language}/ 下的规则
        # 3. javascript 同时扫描 rules/nodejs/ (别名映射)
        # 4. 动态 import 每个规则文件
```

### 8.2 规则文件结构

每条规则是一个 Python 类，典型结构：

```python
class system:
    vulnerability = 'Command Injection'
    language = 'php'
    match_mode = 'function-param-regex'
    match = 'system'
    vul_function = ['system']
    svid = 1001
    author = 'LoRexxar'
    status = True  # False 则跳过

    def main(self, match_text):
        """可选的二次筛选"""
        return match_text  # 或 None 或 False

    repair = {
        'htmlspecialchars': [1001],
        'addslashes': [1001],
    }
```

### 8.3 Tamper 系统

`rules/tamper/` 目录定义了修复函数和可控输入函数：

- `demo.py` → PHP 的 `PHP_IS_REPAIR_DEFAULT` 和 `PHP_IS_CONTROLLED_DEFAULT`
- `demo_java.py` → Java 的修复/可控列表
- `demo_python.py` → Python 的修复/可控列表
- `demo_go.py` → Go 的修复/可控列表

修复函数用于 `code=2` 判定（参数可控但经过安全过滤），可控参数列表预定义了已知可控的输入源。

## 9. 数据流完整示例

以 PHP 命令注入扫描为例：

```
1. scan() 加载规则 system (CVI-1001, match_mode=function-param-regex)
2. SingleRule.origin_results():
   - match = 'system\s*\((.*)(?:\))'
   - grep 结果: [('target.php', 42, 'system($cmd)')]
3. VulnerabilityMatcher._scan_php():
   - init_php_repair(): 加载修复函数列表
   - match_mode == function-param-controllable:
     - rule_match = ['system']
     - php_scan_parser(['system'], 42, 'target.php', ...)
4. PHP scan_parser():
   - ast_object.get_nodes('target.php') → 获取预解析的 AST 节点
   - analysis(nodes, 'system', back_node=[], vul_lineno=42, ...)
   - 找到 FunctionCall(name='system', lineno=42)
   - anlysis_function() → 提取参数 $cmd
   - analysis_variable_node() → anlysis_params('$cmd', file_path, lineno=42)
   - anlysis_params() 内部回溯:
     - 在 back_node 中查找 $cmd 的赋值
     - 找到 $cmd = $_GET['cmd']
     - is_controllable('$_GET') → (1, [source_info])
   - set_scan_results(code=1, cp=[source_info], ...)
5. _parse_ast_result([{'code': 1, ...}])
   - return (True, 'Function-param-controllable', chain)
6. 构建 VulnerabilityResult → 存入数据库
```

## 10. 并发模型

- **规则级并发**：`scanner.py` 使用 `asyncio.gather()` 并发执行所有规则的扫描任务
- **预处理并发**：`pretreatment.py` 使用 10 个协程并发解析文件
- **单规则内串行**：每条规则内部，对 grep 到的多个 sink 点逐个处理（保证全局状态一致性）

## 11. 核心文件索引

| 文件 | 行数 | 职责 |
|---|---|---|
| `core/scanner.py` | ~624 | 扫描调度与任务管理，scan() 入口 |
| `core/matcher.py` | ~700+ | 漏洞判定引擎，语言分派与结果解析 |
| `core/cast.py` | ~433 | 跨语言参数可控性分析 (CAST) |
| `core/rule.py` | ~500+ | 规则加载与管理 |
| `core/pretreatment.py` | ~800+ | 文件收集与 AST 预解析 |
| `core/filters.py` | - | 白名单/特殊文件/注释过滤 |
| `core/rule_generator.py` | - | 新规则生成 (NewCore) |
| `Kunlun_M/const.py` | ~100 | 全局常量定义 |
| `core/core_engine/php/parser.py` | 3241 | PHP AST 回溯分析引擎 |
| `core/core_engine/javascript/parser.py` | 2543 | JavaScript AST 回溯分析引擎 |
| `core/core_engine/python/parser.py` | 2050 | Python AST 回溯分析引擎 |
| `core/core_engine/java/parser.py` | ~1962 | Java AST 回溯分析引擎 |
| `core/core_engine/go/parser.py` | ~1800 | Go AST 回溯分析引擎 |
| `core/core_engine/c/parser.py` | ~2323 | C/C++ AST 回溯分析引擎 |
| `core/core_engine/function_summary.py` | - | 函数摘要共享模块 |
| `core/core_engine/branch_constraint.py` | - | 分支约束共享数据结构 |
| `core/core_engine/trace_cache.py` | - | 追踪缓存（含内置知识库） |
| `core/core_engine/builtin_knowledge.py` | - | 内置函数可控性知识库 |
