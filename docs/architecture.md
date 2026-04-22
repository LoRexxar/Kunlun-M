# Kunlun-M 项目架构文档（重梳理版）

## 1. 项目定位与总体说明

Kunlun-M 是基于 **Python + Django** 的静态代码审计平台，支持：

- 命令行扫描（CLI）
- 交互式控制台（Console）
- Web 管理与 API 查询
- 规则库驱动的漏洞检测
- AST 语义分析（以 PHP / JavaScript 为核心）
- 第三方依赖漏洞（SCA）检测

当前代码同时承载了“扫描引擎 + 数据持久化 + Web 展示”三类职责，属于单仓一体化架构。

---

## 2. 顶层目录职责划分

```text
Kunlun-M/
├── kunlun.py                 # 统一入口（初始化 Django 环境，转发到 core.main）
├── Kunlun_M/                 # Django 项目配置层（settings/urls/middleware）
├── core/                     # 扫描核心（参数编排、扫描调度、规则执行、AST 引擎）
├── web/                      # Web 层（index/dashboard/backend/api 四个 Django app）
├── rules/                    # 漏洞规则、语言定义、框架识别、tamper 配置
├── utils/                    # 通用工具（日志、文件处理、导出、状态）
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
  - 定义子命令：`init/config/scan/show/search/console/plugin/web`
  - 负责日志初始化、规则装载、任务初始化、运行状态更新
  - 在 `scan` 分支中调用 `core.cli.start(...)`

这层是系统“总调度器”，负责把用户命令映射到具体的执行路径。

## 3.3 扫描应用层（Scan Application Layer）

- `core/cli.py`
  - 创建/复用扫描任务（`ScanTask`）
  - 目标目录与参数解析（`ParseArgs`）
  - 文件收集（`Directory.collect_files()`）
  - 语言/框架识别（`Detection`）
  - AST 预处理（`ast_object.pre_ast_all`）
  - 调用引擎扫描（`core.engine.scan`）
  - 结果展示与导出

这一层承接“扫描前后流程”，是业务编排核心。

## 3.4 引擎层（Engine Layer）

- `core/engine.py`
  - `Rule(language).rules(...)` 加载规则
  - 以规则为粒度并发执行（`asyncio.gather`）
  - 对单规则调用 `scan_single -> SingleRule.process`
  - 聚合漏洞、写入数据库、写入结果流（ResultFlow）

特点：

- 规则级并发，扩展规则时无需改主流程
- 结果入库与扫描逻辑耦合较深（后续可解耦）

## 3.5 语义分析层（AST/Semantic Layer）

- `core/core_engine/php/*`
- `core/core_engine/javascript/*`
- `core/cast.py`、`core/pretreatment.py`

职责：

- 按语言构建 AST
- 对规则命中的敏感点做参数/数据流回溯
- 形成漏洞证据链（source、line、node flow）

## 3.6 数据与模型层（Persistence Layer）

- `web/index/models.py`
  - 核心模型：`Project`、`ScanTask`、`ScanResultTask`
  - 规则与扩展：`Rules`、`Tampers`、`NewEvilFunc`
  - 供应链：`ProjectVendors`、`VendorVulns`
  - 提供若干“更新或新建”逻辑函数，封装扫描写库行为

说明：当前模型层同时承担了部分业务逻辑（如 dedup/hash/upsert）。

## 3.7 展示与服务层（Presentation Layer）

- `web/index`：首页与基础入口
- `web/dashboard`：任务、规则、tamper、供应链信息展示
- `web/backend`：后台管理能力
- `web/api`：对外数据接口
- `Kunlun_M/urls.py`：统一路由分发

## 3.8 规则与知识库层（Rule/Knowledge Layer）

- `rules/<language>/CVI_xxxx.py`：漏洞规则实现
- `rules/frameworks.xml`：框架识别规则
- `rules/languages.xml`：语言后缀映射
- `rules/tamper/*`：污点/修复策略

规则是该系统的核心“知识资产”，扫描能力主要由此驱动。

---

## 4. 关键运行流程（Scan 主链路）

1. 用户执行 `python kunlun.py scan -t <target>`
2. `core.main()` 解析参数，创建扫描任务并写入运行状态文件
3. `core.cli.start()` 收集文件、识别语言框架、执行 AST 预处理
4. `core.engine.scan()` 按规则并发扫描
5. 语言引擎（PHP/JS）完成语义分析与证据链构建
6. 结果写入 `ScanResultTask` / `ResultFlow` 等模型
7. CLI 展示结果，Web/API 侧可查询同一批任务数据

---

## 5. 当前架构优势

- **统一运行时**：CLI/Web 共用 Django 配置与模型，数据一致性好。
- **规则驱动**：通过新增 `rules` 文件可扩展检测能力。
- **多入口协同**：CLI 适合批量扫描，Web 适合结果管理。
- **语义分析能力**：相对纯正则方案，误报控制更好。

---

## 6. 当前架构问题（重梳理后的结论）

1. **分层边界不清**
   - `core` 中直接依赖 Django 模型，扫描引擎与持久化耦合。
2. **配置治理不足**
   - `settings.py.public` 中包含较多环境默认值；配置分环境能力偏弱。
3. **领域对象分散**
   - 同类业务在 `core/*` 与 `web/index/models.py` 间交叉实现。
4. **插件化不彻底**
   - 存在插件目录，但主流程仍以内建语言引擎为中心。
5. **异步模型较浅**
   - 当前主要是规则并发，任务队列、分布式执行、资源隔离能力有限。

---

## 7. 建议的目标架构（演进版）

建议采用“六层 + 插件总线”模式：

- **interface**：CLI / Web / API
- **application**：任务编排、扫描作业管理
- **domain**：规则实体、漏洞实体、证据链实体
- **engine**：语言扫描器接口 + PHP/JS 实现
- **infrastructure**：ORM 仓储、文件系统、日志、外部漏洞源
- **plugin bus**：规则包、语言包、供应链适配器

并按以下原则推进：

1. 引擎返回统一 DTO，应用层决定是否落库。
2. 规则引擎接口化（RuleProvider/RuleExecutor），降低对目录命名约束。
3. 扫描任务异步化（可接入队列），支持并行 worker。
4. 配置分层：`base/dev/prod` + 环境变量注入。
5. Web 与扫描核心通过 service/repository 解耦。

---

## 8. 模块映射（现状 -> 目标）

- `core/__init__.py` -> `interface.cli + application.command_handlers`
- `core/cli.py` -> `application.scan_service`
- `core/engine.py` -> `engine.rule_runtime`
- `core/core_engine/*` -> `engine.languages.*`
- `web/index/models.py` -> `infrastructure.persistence.models + repositories`
- `web/dashboard/*` -> `interface.web.dashboard`
- `rules/*` -> `plugins.rules`

---

## 9. 文档结论

Kunlun-M 当前是一个“可用、成熟、但耦合偏高”的扫描平台：

- 在规则能力和语义分析方面有明显积累；
- 在工程结构上需要进一步解耦“扫描核心”和“平台能力”；
- 若要支持下一阶段（更高并发、更强插件生态、更低维护成本），建议围绕“分层重构 + 插件总线 + 异步任务化”持续演进。

