# 数据导入导出

> KunLun-M 提供两种数据导出能力：**项目归档**（数据库 + 图文件打包迁移）和 **图导出到 Neo4j**（AST 图写入图数据库）。

---

## 1. 项目归档导出 / 导入

将一个项目的完整数据（扫描任务、漏洞结果、危险函数、组件信息、TaintChain 污点链路、workspace 图文件）打包为可移植的 `.tar.gz` 归档，支持跨实例迁移。

### 1.1 导出

```bash
# 通过项目 ID 或名称导出
python kunlun.py export-project -p <project_id_or_name> [-o <output_dir>]
```

**参数说明：**

| 参数 | 说明 |
|------|------|
| `-p/--project` | 项目 ID（数字）或项目名称（必填） |
| `-o/--output` | 输出目录，默认当前目录 |

**导出内容：**

```
kunlun-export-{name}-{timestamp}.tar.gz
├── manifest.json          # 元信息（版本、项目信息、统计、校验）
├── db/
│   ├── project.json        # 项目主表
│   ├── scantasks.json      # 扫描任务列表
│   ├── results.json        # 漏洞结果列表
│   ├── newevilfuncs.json   # 危险函数列表
│   ├── vendors.json        # 组件信息列表
│   └── taint_chains.json   # 污点链路数据（TaintChain 表）
└── workspace/
    └── {scan_id}/          # 每个扫描的图文件
        ├── graph.graphmlz  # igraph 压缩图数据
        └── meta.json        # 图元信息
```

**manifest.json 示例：**

```json
{
  "version": "1.0",
  "exported_at": "2026-06-26T08:03:50.123456",
  "project_id": 1,
  "project_name": "nodejs",
  "project_hash": "abc123...",
  "scan_ids": [1, 1507, 1513],
  "scan_count": 3,
  "result_count": 47,
  "newevilfunc_count": 12,
  "vendor_count": 5,
  "taint_chain_rows": 168,
  "graph_files": 6
}
```

**Console 模式：**

```
KunLun-M> export nodejs
[EXPORT] Exporting project 'nodejs' (id=1) ...
[EXPORT]   scans=3, results=47, newevilfuncs=12, vendors=5, taint_chains=168, graphs=6
[EXPORT] Archive saved: kunlun-export-nodejs-20260626_080350.tar.gz (0.15 MB)
```

### 1.2 导入

```bash
python kunlun.py import-project -f <archive_path> [--force]
```

**参数说明：**

| 参数 | 说明 |
|------|------|
| `-f/--file` | 归档文件路径（必填） |
| `--force` | 同名项目（相同 project_hash）存在时强制覆盖，不传则拒绝 |

**导入行为：**

1. 解压到临时目录，读取 `manifest.json` 校验格式
2. 根据 `project_hash` 查找是否已存在同名项目
   - 已存在且无 `--force`：报错退出
   - 已存在且有 `--force`：复用已有 project 记录
   - 不存在：创建新 project 记录
3. ID 全量重映射：scantask、result、newevilfunc 全部新建 ID
4. TaintChain 的 `vul_result` 字段自动映射到新 result ID
5. workspace 图文件复制到 `workspace/{new_scan_id}/`

**Console 模式：**

```
KunLun-M> import kunlun-export-nodejs-20260626_080350.tar.gz
[IMPORT] Importing from kunlun-export-nodejs-20260626_080350.tar.gz ...
[IMPORT]   Created project 'nodejs' (new id=2)
[IMPORT]   Imported 3 scantasks, 47 results, 12 newevilfuncs, 5 vendors
[IMPORT]   Imported 168 TaintChain rows
[IMPORT]   Copied 6 graph files
[IMPORT] Import complete.
```

### 1.3 注意事项

- TaintChain 使用 Django ORM 直接操作
- 同名项目判定基于 `project_hash`，不是项目名称
- 导入后旧项目的 scan ID 和新项目的 scan ID 不同，workspace 目录按新 scan ID 组织

---

## 2. AST 图导出到 Neo4j

将 KunLun-M 的 igraph AST 图批量导出到 Neo4j 图数据库，支持通过 Cypher 进行高级图查询。

### 2.1 前置条件

- Neo4j 数据库运行中（测试兼容 Neo4j 4.x）
- Python neo4j driver 已安装：`pip install neo4j`

### 2.2 连接配置

在 `Kunlun_M/settings.py` 中配置（或通过环境变量 / CLI 参数覆盖）：

```python
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
```

**优先级：CLI 参数 > 环境变量 > settings.py**

### 2.3 导出命令

```bash
# 导出整个项目（所有已完成且有图文件的 scan）
python kunlun.py export-neo4j -p <project_id_or_name> [--clean] [连接参数]

# 导出单个 scan
python kunlun.py export-neo4j -s <scan_id> [--clean] [连接参数]

# 查看可用项目列表
python kunlun.py export-neo4j
```

**完整参数：**

| 参数 | 说明 |
|------|------|
| `-p/--project` | 项目 ID 或名称 |
| `-s/--scan` | 单个 scan ID |
| `--neo4j-uri` | Neo4j URI（默认 `bolt://localhost:7687`） |
| `--neo4j-user` | Neo4j 用户名（默认 `neo4j`） |
| `--neo4j-password` | Neo4j 密码（默认空） |
| `--clean` | 导出前清空已有的 KunlunM 节点和关系 |
| `--batch-size` | UNWIND 批量写入大小，默认 500 |

**Console 模式：**

```
KunLun-M> neo4j nodejs --clean
[Neo4j] Exporting project 'nodejs' (id=1), 3 scans: [1, 1507, 1513]
[NEO4J] Connecting to neo4j@bolt://localhost:7687 ...
[NEO4J] Creating indexes ...
[NEO4J] scan_id=1: 778 nodes, 1161 edges
[NEO4J] scan_id=1507: 2100 nodes, 4120 edges
[NEO4J] scan_id=1513: 1820 nodes, 2414 edges
[NEO4J] Export complete: 3 scans, 4698 nodes, 7695 edges
```

### 2.4 数据映射

#### 节点映射

igraph 的 `vertex.label` 属性映射为 Neo4j 的 Label，所有节点额外带有 `vid`（igraph 内部 ID）和 `scan_id` 属性：

| igraph label | Neo4j Label | 说明 |
|--------------|-------------|------|
| `file` | `KunlunFile` | 源文件 |
| `class` | `KunlunClass` | 类定义 |
| `function` | `KunlunFunction` | 函数/方法 |
| `parameter` | `KunlunParameter` | 函数参数 |
| `return` | `KunlunReturn` | 返回语句 |
| `identifier` | `KunlunIdentifier` | 变量/标识符 |
| `const` | `KunlunConst` | 常量/字面量 |
| `operator` | `KunlunOperator` | 操作符/调用 |
| `branch` | `KunlunBranch` | 分支/循环 |
| `import` | `KunlunImport` | 导入语句 |
| `annotation` | `KunlunAnnotation` | 注解/装饰器 |
| `dependency` | `KunlunDependency` | 依赖项 |

#### 关系映射

igraph 的 `edge.label` 属性映射为 Neo4j 的 Relationship Type：

| igraph label | Neo4j Type | 说明 |
|--------------|------------|------|
| `own` | `CONTAINS` | 文件→函数/类（包含关系） |
| `cg` | `CALLS` | 函数→函数（调用关系） |
| `dfg` | `DATA_FLOW` | 数据流（变量传播） |
| `ast` | `AST_CHILD` | AST 父子关系 |
| `use` | `USES` | 标识符引用函数/类 |
| `frg` | `FILE_REF` | 文件间引用（import/include） |
| `member` | `MEMBER_ACCESS` | 成员访问（属性/数组） |
| `crg` | `CLASS_RELATION` | 类关系（继承/实现） |
| `alias` | `ALIAS` | 别名关系 |

#### 属性映射

节点和边的属性（除 `label`/`source`/`target`）原样保留为 Neo4j 属性：

**节点常见属性：**

| 属性 | 适用类型 | 说明 |
|------|----------|------|
| `name` | 全部 | 显示名称 |
| `language` | 全部 | 编程语言 |
| `lineno` | 多数 | 起始行号（整数） |
| `end_lineno` | 部分函数/类 | 结束行号 |
| `fullname` | function/class | 完整限定名 |
| `signature` | function | 函数签名 |
| `file_path` / `path` | file | 文件路径 |
| `raw_type` | 多数 AST 节点 | 原始 AST 节点类型 |
| `type` | 多数 | 子类型（import/direct/method 等） |
| `content_hash` | file | 文件内容哈希 |
| `operator` | operator | 运算符 |
| `condition` | branch | 条件表达式 |

**关系常见属性：**

| 属性 | 适用类型 | 说明 |
|------|----------|------|
| `role` | AST_CHILD | AST 角色（param/lhs/rhs/arg/callee/body 等） |
| `type` | 多种 | 子类型（import/direct/method/forward_slice 等） |
| `call_type` | CALLS | 调用类型（direct/method/static 等） |
| `access_type` | MEMBER_ACCESS | 访问类型（property/array_offset 等） |

### 2.5 Neo4j 查询示例

导出完成后，可以在 Neo4j Browser 或 Cypher Shell 中进行图查询：

```cypher
-- 查看各类型节点统计
MATCH (n) RETURN labels(n)[0] AS type, count(*) AS cnt ORDER BY cnt DESC

-- 查看各类型关系统计
MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS cnt ORDER BY cnt DESC

-- 查找指定 scan 的所有文件
MATCH (f:KunlunFile {scan_id: 1}) RETURN f.name, f.file_path

-- 查找某函数的所有调用
MATCH (caller:KunlunFunction)-[r:CALLS]->(callee:KunlunFunction)
WHERE caller.name = 'ExecuteCommand'
RETURN caller.name, callee.name, r.call_type

-- 追踪数据流：从参数到 sink
MATCH path = (source:KunlunParameter {name: 'cmd'})-[:DATA_FLOW*1..5]->(sink)
RETURN path

-- 查找跨文件调用关系
MATCH (f1:KunlunFile)-[:CONTAINS]->(fn1:KunlunFunction)-[c:CALLS]->(fn2:KunlunFunction)<-[:CONTAINS]-(f2:KunlunFile)
WHERE f1 <> f2
RETURN f1.name, fn1.name, fn2.name, f2.name

-- 查找某文件的 AST 结构（前 20 层）
MATCH (f:KunlunFile {name: 'main.go'})-[:CONTAINS*1..20]->(n)
RETURN labels(n)[0] AS type, n.name, n.lineno ORDER BY n.lineno LIMIT 50
```

### 2.6 索引

导出时会自动创建以下索引（已存在则跳过）：

- `KunlunFile(vid)` / `KunlunFile(file_path)` / `KunlunFile(scan_id)`
- `KunlunFunction(vid)` / `KunlunFunction(fullname)`
- `KunlunIdentifier(vid)` / `KunlunIdentifier(name)`
- 其余 9 种节点类型的 `vid` 索引

### 2.7 性能

| 场景 | 节点数 | 边数 | 耗时 |
|------|--------|------|------|
| 单 scan（Go 项目） | 778 | 1,161 | ~3 秒 |
| 多 scan（nodejs，3 scans） | 4,698 | 7,695 | ~29 秒 |

写入性能依赖 Neo4j 的硬件配置和现有数据量。大项目（数百 scan）建议分批导出或使用 `--batch-size` 调参。

### 2.8 注意事项

- `--clean` 会删除所有 KunlunM 标签的节点和关系，慎用
- 不带 `-p` 和 `-s` 时仅列出有图文件的项目，不连接 Neo4j
- 多次导出同一 scan 会产生重复节点（相同 vid），建议先 `--clean` 或按需导出
- vid 为字符串类型，跨 scan 的 vid 可能重复，多 scan 导出时查询需结合 `scan_id` 过滤
