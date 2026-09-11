# Kunlun-M 项目架构文档

## 1. 项目定位与总体说明

Kunlun-M 是基于 **Python + Django** 的静态代码安全分析平台，支持：

- 命令行扫描（CLI）
- 交互式控制台（Console，含图遍历 REPL）
- Web 管理与 API 查询
- 规则库驱动的漏洞检测
- **AST 图引擎**：构建完整程序图（AST 结构 + 调用图 + 数据流），污点回溯判定可控性
- 第三方依赖漏洞（SCA）检测

当前代码同时承载了“扫描引擎 + 数据持久化 + Web 展示”三类职责，属于单仓一体化架构。

---

## 2. 顶层目录职责划分

```text
Kunlun-M/
├── kunlun.py                 # 统一入口（初始化 Django 环境，转发到 core.main）
├── Kunlun_M/                 # Django 项目配置层（settings/urls/middleware）
├── core/                     # 扫描核心（参数编排、图引擎、规则执行、结果落库）
│   ├── scanner.py            # 图引擎扫描管线（构建图 → 污点分析 → 结果写入）
│   ├── graph/                # AST 图引擎（schema/构建/推导边/分析器/持久化）
│   ├── core_engine/          # 各语言 AST 解析适配（php/js/java/python/go/c/…）
│   ├── engine.py             # 薄导出层（仅 re-export scanner.scan / Running）
│   ├── cli.py                # 扫描任务编排（文件收集、语言识别、AST 预处理）
│   ├── rule.py               # 规则动态加载（rules/<language>/CVI_xxxx.py）
│   ├── rule_generator.py     # auto rule 机制（NewCore）
│   ├── console.py            # 交互式控制台 + 图遍历 REPL
│   ├── import_export.py      # 项目归档导入导出
│   └── neo4j_export.py       # AST 图导出 Neo4j
├── web/                      # Web 层（index/dashboard/backend/api 四个 Django app）
├── rules/                    # 漏洞规则、语言定义、框架识别、tamper 配置
├── utils/                    # 通用工具（日志、文件处理、导出、igraph 兼容层）
├── templates/ + static/      # 前端模板与静态资源
├── tests/                    # 测试样本与 AST/漏洞用例
└── docs/                     # 文档与变更记录
```

---

## 3. 架构分层（逻辑视图）

## 3.1 接入层（Entry Layer）

- `kunlun.py`
  - 设置 `DJANGO_SETTINGS_MODULE`
  - 调用 `django.setup()`
  - 转入 `core.main()`

这一层统一了 CLI 与 Web 运行时环境，确保扫描逻辑可直接复用 Django ORM 与配置。

## 3.2 编排层（Orchestration Layer）

- `core/__init__.py`（主控）
  - 定义子命令：`init/config/scan/show/search/console/plugin/web/analyze/export-project/import-project/export-neo4j/reset`
  - 负责日志初始化、规则装载、任务初始化、运行状态更新

这层是系统“总调度器”，负责把用户命令映射到具体的执行路径。

## 3.3 扫描应用层（Scan Application Layer）

- `core/cli.py`
  - 创建/复用扫描任务（`ScanTask`）
  - 目标目录与参数解析（`ParseArgs`）
  - 文件收集（`Directory.collect_files()`）
  - 语言/框架识别（`Detection`）
  - 调用引擎扫描（`core.engine.scan`）
  - 结果展示与导出

这一层承接“扫描前后流程”，是业务编排核心。

## 3.4 图引擎层（Graph Engine Layer）

3.0 起，所有语言的扫描链路 100% 基于图引擎，`core/scanner.py` 是唯一扫描管线：

**图构建（一次性，支持 .graphmlz 缓存复用）：**

1. `build_ast_graph()`（`core/graph/graph_pipeline.py`）：遍历文件 → 各语言 Normalizer 遍历 AST 生成结构边 → `AstGraphBuilder` 组装为 igraph Graph → 可选落盘 `.graphmlz` + SQLite 节点索引
2. `enrich_taint()`（`core/graph/knowledge_bridge.py`）：跨函数污点标注，builtin source registry（`document.cookie`、`process.env` 等）
3. `build_function_summaries()`（`core/graph/function_summary.py`）：DFG 反向追踪 return → parameter，产出 passthrough/source/safe/literal 摘要
4. safe 函数 DFG passthrough 边清理

**扫描（按规则并发）：**

5. 规则匹配（`rule.main()` 二次筛选 + vendor/test 过滤）
6. `analyzer.find_sinks()` 定位 sink 点
7. 对 sink 每个参数执行 `analyzer.parameters_back()` 污点回溯 → `AnalysisResult`
8. 结果写入 `ScanResultTask` / `TaintChain`

**`core/graph/` 模块分工：**

| 模块 | 职责 |
|---|---|
| `node_edge_schema.py` | 12 种节点标签、9 种边标签及属性枚举 |
| `normalizers/<lang>/` | 各语言 AST → 结构边（own/ast/use/member/frg） |
| `edge_builders/` | 推导边：dfg（数据流）、cg（调用图）、alias（间接调用）、crg |
| `graph_analyzer.py` | `GraphAnalyzer`：find_sinks、parameters_back 污点回溯、守卫体系 |
| `function_summary.py` | 跨函数 DFG 摘要（return → parameter 反向追踪） |
| `knowledge_bridge.py` | enrich_taint + builtin_knowledge 桥接 |
| `graph_io.py` / `workspace.py` | .graphmlz 持久化与工作区管理 |

**守卫体系（3.0.0 后新增，详见 [ast-graph-structure.md](./ast-graph-structure.md) 第 5 节）：**

`parameters_back` 公共入口在 BFS 实现外层按序执行后置守卫，命中即返回 `code=-1`（不可控）。设计原则：**守卫只识别“到达 sink 即证明约束成立”的路径敏感形态**，与分支约束分析（Rule 6）互补，均不使用白名单豁免。

## 3.5 语义解析层（Language Adapter Layer）

- `core/core_engine/<language>/*`
  - 各语言 parser 适配（phply/lphply、esprima、javalang、python ast、go/ast 等）
  - 为图构建提供统一 AST 节点流
- `core/pretreatment.py`（AST 预处理入口）、`core/cast.py`

## 3.6 数据与模型层（Persistence Layer）

- `web/index/models.py`
  - 核心模型：`Project`、`ScanTask`、`ScanResultTask`
  - 规则与扩展：`Rules`、`Tampers`
  - 传播链：`TaintChain`
  - 供应链：`ProjectVendors`、`VendorVulns`
  - 提供若干“更新或新建”逻辑函数，封装扫描写库行为

## 3.7 展示与服务层（Presentation Layer）

- `web/dashboard/*`：任务管理、项目总览、图可视化（Cytoscape.js）
- `web/api/*`：token 鉴权 REST API
- `web/backend/*`：日志与调试
- CLI 输出：csv/json/xml/md/html 五种格式

## 3.8 规则与知识库层（Rule/Knowledge Layer）

- `rules/<language>/CVI_<id>.py`：漏洞规则
- `rules/tamper/`：框架 tamper（source/repair/sink 扩展）
- `core/graph/knowledge_bridge.py` + 各语言 `builtin_knowledge`：内置安全函数知识库（safe=True 的返回值净化判定唯一入口）

---

## 4. 关键运行流程（Scan 主链路）

1. 用户执行 `python kunlun.py scan -t <target>`
2. `core.main()` 解析参数，创建扫描任务并写入运行状态文件
3. `core.cli.start()` 收集文件、识别语言框架
4. `core.scanner.scan()` 构建图（或复用缓存）→ enrich_taint → function summaries
5. 规则匹配定位 sink → `parameters_back` 污点回溯（含守卫体系）→ `AnalysisResult`
6. 结果写入 `ScanResultTask` / `TaintChain`
7. CLI 展示结果，Web/API 侧可查询同一批任务数据

---

## 5. 架构要点

- **统一运行时**：CLI/Web 共用 Django 配置与模型，数据一致性好。
- **单管线多语言**：所有语言共享 scanner 管线与图 schema，语言差异收敛在 Normalizer 与 edge_builders 内。
- **图缓存**：同 target 二次扫描自动复用 .graphmlz，`--no-cache` 强制重建。
- **守卫可组合**：每个守卫独立成函数、按序短路，均有独立探针验证与全量回归，扩展新守卫不影响既有判定。
- **知识库唯一入口**：函数安全判定统一走 builtin_knowledge（safe=True），避免各处散落白名单。

---

## 6. 模块索引

- 图结构 Schema、守卫体系详解：[ast-graph-structure.md](./ast-graph-structure.md)
- 各语言 AST → 图映射：[ast-graph-\<lang\>-mapping.md](./README.md) 系列
- 扫描管线与各语言回溯设计细节：[design/](./design/) 目录
- 规则开发：[rules.md](./rules.md)；tamper：[tamper.md](./tamper.md)
- CLI 用法：[cli.md](./cli.md)；Web：[web.md](./web.md)；CI：[ci.md](./ci.md)
