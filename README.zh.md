中文 | [English](README.md)

# KunLun-M

[![GitHub release](https://img.shields.io/github/release/LoRexxar/Kunlun-M/all.svg)](https://github.com/LoRexxar/Kunlun-M/releases)
[![license](https://img.shields.io/github/license/LoRexxar/Kunlun-M.svg)](./LICENSE)
![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)

**KunLun-M（昆仑镜）** 是一款开源静态代码安全分析系统。通过构建 AST 图进行污点分析，检测源代码中的安全漏洞。

- **14 种语言**：PHP / JavaScript / TypeScript / Python / Java / Go / Ruby / Rust / C / C++ / C# / Kotlin / Lua / Solidity
- **AST 图引擎**：构建完整程序图（调用图、数据流、AST 结构），支持污点追踪
- **CLI / Console / Web** 三种模式
- **内置 AI Agent Skill**：支持 Codex / Claude Code / Hermes 等一键接入

## 快速开始

```bash
# 安装
git clone https://github.com/LoRexxar/Kunlun-M.git && cd Kunlun-M
pip install -r requirements.txt
cp Kunlun_M/settings.py.bak Kunlun_M/settings.py

# 初始化数据库
python kunlun.py init

# 扫描
python kunlun.py scan -t /path/to/project

# 指定语言扫描
python kunlun.py scan -t /path/to/project -lan php

# 导出 HTML 报告
python kunlun.py scan -t /path/to/project -f html -o report.html

# Web 模式
python kunlun.py web -p 9999
```

## CLI 命令

```
python kunlun.py <命令> [参数]
```

### 核心命令

| 命令 | 说明 |
|------|------|
| `init` | 初始化 / 迁移数据库 |
| `reset` | 重置数据库（清除扫描数据、TaintChain、旧 ResultFlow、workspace） |
| `scan -t <目标>` | 扫描目标（文件、目录或压缩包） |
| `console` | 交互式控制台（含图遍历 REPL） |
| `web [-p 9999]` | Web Dashboard + API |
| `analyze` | AST 图二次分析 |
| `export-project -p <项目>` | 导出项目归档 |
| `import-project -f <归档>` | 导入项目归档 |
| `export-neo4j -p <项目>` | 导出 AST 图到 Neo4j |

### 扫描参数

| 参数 | 说明 |
|------|------|
| `-t/--target` | 目标文件/目录（必填） |
| `-lan/--language` | 语言（php/javascript/python/java/go/ruby/rust/c/cpp/csharp/kotlin/lua/solidity） |
| `-r/--rule` | 指定规则（逗号分隔 CVI 编号，如 `1000,1001`） |
| `-f/--format` | 输出格式：`csv`（默认）/ `json` / `md` / `html` / `xml` |
| `-o/--output` | 输出文件路径 |
| `-tp/--tamper` | 应用 tamper（如 wordpress） |
| `-b/--blackpath` | 排除路径（如 `vendor,node_modules`） |
| `--without-vendor` | 跳过 SCA（组件漏洞）扫描 |
| `--no-cache` | 强制重建图（不使用缓存） |
| `-d/--debug` | 调试模式 |

### 其他命令

| 命令 | 说明 |
|------|------|
| `export` | 导出规则和 tamper 到文件 |
| `generate rule` | 生成规则模板文件 |
| `generate tamper` | 生成 tamper 模板文件 |
| `show rule [-k <key>]` | 查看规则（按语言/关键字过滤） |
| `show tamper` | 查看 tamper |
| `search vendor <名称> <版本>` | 搜索组件漏洞 |
| `plugin <名称>` | 运行插件（`entrance_finder` / `php_unserialize_chain_tools`） |

## Console 模式

Console 模式提供交互式 REPL，支持图遍历：

```bash
python kunlun.py console

KunLun-M> scan
KunLun-M(scan)> set target /path/to/project
KunLun-M(scan)> run

KunLun-M> load 42
KunLun-M(result)> show vuls
KunLun-M(result)> graph           # 进入图遍历 REPL
>>> g.function.main.ownout.count
14
```

### 图遍历 REPL

在图遍历 REPL 中，使用 `g` 作为入口进行 Joern 风格的图查询：

```python
>>> g.function                          # 所有函数节点
>>> g.file.index                        # 名为 'index' 的文件
>>> g.identifier.session.dfg            # 从 'session' 出发的数据流
>>> g.function.main.ownout              # main 函数的 AST 子节点
>>> g.identifier.input.uses             # 使用了 'input' 的函数
>>> g.function.exec.shortest_path      # 到 'exec' 的最短路径
```

完整 API 参考：[docs/graph-traversal.md](./docs/graph-traversal.md)

## Web Dashboard

```
python kunlun.py web -p 9999
```

Web 模式包含：
- **Dashboard**：任务管理、项目概览、扫描结果
- **图分析**：Cytoscape.js 交互式图可视化（4 种布局）
- **API**：Token 认证的 REST API，支持自动化

### 主要 API

```
POST   /api/task/create                   创建扫描任务
POST   /api/task/create/start             创建并自动启动扫描
GET    /api/task/<task_id>/status         任务状态
GET    /api/task/list                     任务列表
GET    /api/task/<task_id>/result         扫描结果
GET    /api/task/<task_id>/taintchain     污点链路数据
GET    /api/rule/list                     规则列表
GET    /api/graph/query                   AST 图查询
GET    /api/graph/subgraph                子图提取（用于可视化）
GET    /api/graph/chain_subgraph          污点链路子图
GET    /api/graph/node_vulns              节点关联漏洞
```

在 `Kunlun_M/settings.py` 中配置 `API_TOKEN` 进行 API 认证。

## 数据导入导出

### 项目归档

将完整项目（数据库记录 + 图文件）导出为可移植的 `.tar.gz`：

```bash
python kunlun.py export-project -p nodejs
python kunlun.py import-project -f kunlun-export-nodejs-*.tar.gz [--force]
```

### Neo4j 图导出

将 AST 图导出到 Neo4j，支持 Cypher 高级查询：

```bash
python kunlun.py export-neo4j -p nodejs --clean
python kunlun.py export-neo4j -s 42 --neo4j-uri bolt://host:7687
```

详细文档：[docs/data-export.md](./docs/data-export.md)

## AI Agent 接入

如果你使用 AI Agent（Codex / Claude Code / Hermes 等），发送：

> 下载 `https://github.com/LoRexxar/Kunlun-M.git`，并加载其 skill（kunlun-m-general）。

Agent 会自动识别 `skills/kunlun-m-general/` 目录并按文档完成初始化和扫描。

脚本化工作流见 [docs/skill_kunlunm_general.md](./docs/skill_kunlunm_general.md)。

## 支持语言

| 语言 | 语义分析 | 图引擎 |
|------|:-:|:-:|
| PHP | ✅ | ✅ |
| JavaScript | ✅ | ✅ |
| TypeScript | ✅ | ✅ |
| Python | ✅ | ✅ |
| Java | ✅ | ✅ |
| Go | ✅ | ✅ |
| Ruby | ✅ | ✅ |
| Rust | ✅ | ✅ |
| C | ✅ | ✅ |
| C++ | ✅ | ✅ |
| C# | ✅ | ✅ |
| Kotlin | ✅ | ✅ |
| Lua | ✅ | ✅ |
| Solidity | 基础 | — |

## 插件

### PHP 反序列化链挖掘

自动发现 PHP 反序列化链并生成 PoC 文件：

```bash
python kunlun.py plugin php_unserialize_chain_tools -t /path/to/php/project
```

### 入口点发现

快速发现大型 PHP 项目中潜在的入口页面：

```bash
python kunlun.py plugin entrance_finder -t /path/to/php/project -l 3
```

## 开发

### 规则开发

规则命名遵循 `rules/{语言}/CVI_{编号}.py`，模板参见 `rules/rule.template`。

### 架构概览

```
core/
├── __init__.py          CLI 入口、子命令分发
├── scanner.py           图引擎扫描（构建图 → 污点分析）
├── graph/
│   ├── graph_pipeline.py    AST → igraph 图构建
│   ├── graph_query_builder.py  6 种查询方法（概览/文件/函数/追踪/搜索/子图）
│   ├── graph_io.py          图持久化（GraphMLZ）
│   ├── node_edge_schema.py  12 种节点类型、9 种边类型
│   └── workspace.py         扫描工作空间管理
├── import_export.py     项目归档导入导出
├── neo4j_export.py      igraph → Neo4j 导出
├── console.py           交互式控制台 + 图遍历 REPL
└── engine.py            薄导出层

web/
├── index/               模型、页面
├── api/                 REST API（Session + Token 认证）
└── dashboard/           Web UI（模板 + 控制器）
```

### 文档

- [docs/README.md](./docs/README.md) — 文档索引
- [docs/cli.md](./docs/cli.md) — CLI 详细参考
- [docs/architecture.md](./docs/architecture.md) — 架构概览
- [docs/data-export.md](./docs/data-export.md) — 导入导出与 Neo4j
- [docs/graph-traversal.md](./docs/graph-traversal.md) — 图遍历 REPL
- [docs/changelog.md](./docs/changelog.md) — 更新日志

## 更新日志

[docs/changelog.md](./docs/changelog.md)

## Stargazers

<div align=center><a href="https://github.com/LoRexxar/Kunlun-M"><img src="https://api.star-history.com/svg?repos=LoRexxar/Kunlun-M&type=Timeline"></a></div>

## 404StarLink 项目

![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

KunLun-M 是 404Team [星链计划](https://github.com/knownsec/404StarLink-Project)中的一环。

## 贡献者

**核心开发者：**
- [LoRexxar](https://github.com/LoRexxar)

**重要贡献者：**
- Vidar-Team [LuckC4t](https://github.com/LuckyC4t)
- Dubhe [Sissel](https://github.com/boke1208)

**贡献者：**
- Dubhe [Sndav](https://github.com/Sndav)、[#jax777](https://github.com/jax777)、[lavon321](https://github.com/lavon321)、[Raul1718](https://github.com/Raul1718)、[akkuman](https://github.com/akkuman)

## 许可证

[MIT License](./LICENSE)
