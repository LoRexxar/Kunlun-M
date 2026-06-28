[中文](README.zh.md) | English

# KunLun-M

[![GitHub release](https://img.shields.io/github/release/LoRexxar/Kunlun-M/all.svg)](https://github.com/LoRexxar/Kunlun-M/releases)
[![license](https://img.shields.io/github/license/LoRexxar/Kunlun-M.svg)](./LICENSE)
![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)

**KunLun-M（昆仑镜）** is an open-source static code security analysis system. It builds an AST graph from source code and performs taint analysis to detect vulnerabilities.

- **14 languages**: PHP / JavaScript / TypeScript / Python / Java / Go / Ruby / Rust / C / C++ / C# / Kotlin / Lua / Solidity
- **AST graph engine**: Builds a full program graph (call graph, data flow, AST structure) for taint tracking
- **CLI / Console / Web** three modes
- **Built-in AI Agent skill**: One-click integration with Codex / Claude Code / Hermes etc.

## Quick Start

```bash
# Install
git clone https://github.com/LoRexxar/Kunlun-M.git && cd Kunlun-M
pip install -r requirements.txt
cp Kunlun_M/settings.py.bak Kunlun_M/settings.py

# Init database
python kunlun.py init

# Scan
python kunlun.py scan -t /path/to/project

# Scan with specific language
python kunlun.py scan -t /path/to/project -lan php

# Export HTML report
python kunlun.py scan -t /path/to/project -f html -o report.html

# Web dashboard
python kunlun.py web -p 9999
```

## CLI Commands

```
python kunlun.py <command> [args]
```

### Core Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize / migrate database |
| `reset` | Reset database (clear scan data, TaintChain, legacy ResultFlow, workspace) |
| `scan -t <target>` | Scan target (file, directory, or archive) |
| `console` | Interactive console with graph REPL |
| `web [-p 9999]` | Web dashboard with API |
| `analyze` | AST graph secondary analysis |
| `export-project -p <project>` | Export project to portable archive |
| `import-project -f <archive>` | Import project from archive |
| `export-neo4j -p <project>` | Export AST graph to Neo4j |

### Scan Parameters

| Parameter | Description |
|-----------|-------------|
| `-t/--target` | Target file/directory (required) |
| `-lan/--language` | Language (php/javascript/python/java/go/ruby/rust/c/cpp/csharp/kotlin/lua/solidity) |
| `-r/--rule` | Specific rules (comma-separated CVI IDs, e.g. `1000,1001`) |
| `-f/--format` | Output format: `csv` (default) / `json` / `md` / `html` / `xml` |
| `-o/--output` | Output file path |
| `-tp/--tamper` | Apply tamper (e.g. wordpress) |
| `-b/--blackpath` | Exclude paths (e.g. `vendor,node_modules`) |
| `--without-vendor` | Skip SCA (vendor vulnerability) scan |
| `--no-cache` | Force rebuild graph (no cache) |
| `-d/--debug` | Debug mode |

### Other Commands

| Command | Description |
|---------|-------------|
| `export` | Export rules & tampers from database to files |
| `generate rule` | Generate rule template file |
| `generate tamper` | Generate tamper template file |
| `show rule [-k <key>]` | Show rules (filter by language/key) |
| `show tamper` | Show tampers |
| `search vendor <name> <version>` | Search vendor vulnerabilities |
| `plugin <name>` | Run plugin (`entrance_finder` / `php_unserialize_chain_tools`) |

## Console Mode

Console mode provides an interactive REPL with graph traversal support:

```bash
python kunlun.py console

KunLun-M> scan
KunLun-M(scan)> set target /path/to/project
KunLun-M(scan)> run

KunLun-M> load 42
KunLun-M(result)> show vuls
KunLun-M(result)> graph           # Enter graph traversal REPL
>>> g.function.main.ownout.count
14
```

### Graph Traversal REPL

Inside the graph REPL, use `g` as the entry point for Joern-style graph queries:

```python
>>> g.function                          # All function nodes
>>> g.file.index                        # File named 'index'
>>> g.identifier.session.dfg            # Data flow from 'session'
>>> g.function.main.ownout              # AST children of main
>>> g.identifier.input.uses             # Functions using 'input'
>>> g.function.exec.shortest_path      # Shortest path to 'exec'
```

See [docs/graph-traversal.md](./docs/graph-traversal.md) for the full API reference.

## Web Dashboard

```
python kunlun.py web -p 9999
```

Web mode includes:
- **Dashboard**: Task management, project overview, scan results
- **Graph Analysis**: Interactive Cytoscape.js graph visualization (4 layouts)
- **API**: Token-authenticated REST API for automation

### Main API Endpoints

```
POST   /api/task/create                   Create scan task
POST   /api/task/create/start             Create + auto-start scan
GET    /api/task/<task_id>/status         Task status
GET    /api/task/list                     Task list
GET    /api/task/<task_id>/result         Scan results
GET    /api/task/<task_id>/taintchain     Taint chain data
GET    /api/rule/list                     Rule list
GET    /api/graph/query                   AST graph query
GET    /api/graph/subgraph                Subgraph extraction (for visualization)
GET    /api/graph/chain_subgraph          Taint chain subgraph
GET    /api/graph/node_vulns             Node-associated vulnerabilities
```

Configure `API_TOKEN` in `Kunlun_M/settings.py` for API authentication.

## Data Export & Import

### Project Archive

Export a complete project (database records + graph files) as a portable `.tar.gz`:

```bash
python kunlun.py export-project -p nodejs
python kunlun.py import-project -f kunlun-export-nodejs-*.tar.gz [--force]
```

### Neo4j Graph Export

Export AST graphs to Neo4j for advanced Cypher queries:

```bash
python kunlun.py export-neo4j -p nodejs --clean
python kunlun.py export-neo4j -s 42 --neo4j-uri bolt://host:7687
```

See [docs/data-export.md](./docs/data-export.md) for full documentation.

## AI Agent Integration

If you're using an AI Agent (Codex / Claude Code / Hermes etc.), send:

> Download `https://github.com/LoRexxar/Kunlun-M.git` and load its skill (kunlun-m-general).

The agent will auto-detect `skills/kunlun-m-general/` and follow the docs to initialize and scan.

See [docs/skill_kunlunm_general.md](./docs/skill_kunlunm_general.md) for scripted workflows.

## Supported Languages

| Language | Semantic Analysis | Graph Engine |
|----------|:-:|:-:|
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
| Solidity | Basic | — |

## Plugins

### PHP Deserialization Chain Finder

Automatically discovers PHP deserialization chains and generates PoC files:

```bash
python kunlun.py plugin php_unserialize_chain_tools -t /path/to/php/project
```

### Entrance Finder

Quickly finds potential PHP entry pages in large codebases:

```bash
python kunlun.py plugin entrance_finder -t /path/to/php/project -l 3
```

## Development

### Rule Development

Rules follow the convention `rules/{language}/CVI_{id}.py`. See `rules/rule.template` for a template.

### Architecture

```
core/
├── __init__.py          CLI entry, subcommand dispatch
├── scanner.py           Graph-based scan engine (build graph → taint analysis)
├── graph/
│   ├── graph_pipeline.py    AST → igraph graph builder
│   ├── graph_query_builder.py  6 query methods (overview/file/function/trace/search/subgraph)
│   ├── graph_io.py          Graph persistence (GraphMLZ)
│   ├── node_edge_schema.py  12 node types, 9 edge types
│   └── workspace.py         Scan workspace management
├── import_export.py     Project archive export/import
├── neo4j_export.py      igraph → Neo4j export
├── console.py           Interactive console + graph REPL
└── engine.py            Thin re-export layer

web/
├── index/               Models, dashboard pages
├── api/                 REST API (session + token auth)
└── dashboard/           Web UI (templates + controllers)
```

### Documentation

- [docs/README.md](./docs/README.md) — Documentation index
- [docs/cli.md](./docs/cli.md) — CLI detailed reference
- [docs/architecture.md](./docs/architecture.md) — Architecture overview
- [docs/data-export.md](./docs/data-export.md) — Export/import & Neo4j
- [docs/graph-traversal.md](./docs/graph-traversal.md) — Graph traversal REPL
- [docs/changelog.md](./docs/changelog.md) — Changelog

## Changelog

[docs/changelog.md](./docs/changelog.md)

## Stargazers

<div align=center><a href="https://github.com/LoRexxar/Kunlun-M"><img src="https://api.star-history.com/svg?repos=LoRexxar/Kunlun-M&type=Timeline"></a></div>

## 404StarLink Project

![](https://github.com/knownsec/404StarLink-Project/raw/master/logo.png)

KunLun-M is part of the [404Team StarLink Project](https://github.com/knownsec/404StarLink-Project).

## Contributors

**Core Developer:**
- [LoRexxar](https://github.com/LoRexxar)

**Important Contributors:**
- Vidar-Team [LuckC4t](https://github.com/LuckyC4t)
- Dubhe [Sissel](https://github.com/boke1208)

**Contributors:**
- Dubhe [Sndav](https://github.com/Sndav), [#jax777](https://github.com/jax777), [lavon321](https://github.com/lavon321), [Raul1718](https://github.com/Raul1718), [akkuman](https://github.com/akkuman)

## License

[MIT License](./LICENSE)
