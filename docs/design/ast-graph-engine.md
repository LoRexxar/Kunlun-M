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
                                    igraph 图构建
                                            ↓
                              ┌──────────────┴──────────────┐
                              ↓                              ↓
                       GraphAnalyzer                 AstGraphIO.save()
                       (图上回溯/判定)                 (.graphmlz 持久化)
                              ↓                              ↓
                       分析决策标记                     SQLite 索引更新
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

| 统一标签 | 语义 | 映射来源 |
|---------|------|---------|
| **File** | 源代码文件 | 新建，非 AST 节点 |
| **Function** | 函数/方法定义 | PHP: Function/Method, JS: FunctionDeclaration/FunctionExpression, Java: MethodDeclaration/ConstructorDeclaration, Python: FunctionDef/AsyncFunctionDef, Go: function_declaration, C: function_definition |
| **Class** | 类/结构体定义 | PHP: Class, JS: ClassDeclaration/ClassExpression, Java: ClassDeclaration, Python: ClassDef, Go: type_declaration(struct), C: structSpecifier |
| **Interface** | 接口定义 | Java: InterfaceDeclaration, PHP: Interface (如有), Go: interface |
| **Variable** | 变量/标识符 | PHP: Variable, JS: Identifier, Java: MemberReference/LocalVariableDeclaration, Python: Name, Go: identifier, C: identifier |
| **Literal** | 字面量 | PHP: String/Number/Boolean/Constant, JS: Literal, Java: Literal, Python: Constant/Num/Str, Go: literal, C: number_literal/string_literal |
| **FunctionCall** | 函数调用 | PHP: FunctionCall, JS: CallExpression, Java: MethodInvocation/MethodInvocation, Python: Call, Go: call_expression, C: call_expression |
| **Assignment** | 赋值语句 | PHP: Assignment, JS: AssignmentExpression, Java: Assignment, Python: Assign/AugAssign, Go: assignment_statement, C: assignment_expression |
| **Return** | 返回语句 | PHP: Return, JS: ReturnStatement, Java: ReturnStatement, Python: Return, Go: return_statement, C: return_statement |
| **Conditional** | 条件语句 | PHP: If/TernaryOp, JS: IfStatement/ConditionalExpression, Java: IfStatement/TernaryExpression, Python: If/IfExp, Go: if_statement, C: if_statement |
| **Loop** | 循环语句 | PHP: For/While/Foreach, JS: ForStatement/WhileStatement/ForInStatement, Java: ForStatement/WhileStatement/EnhancedForStatement, Python: For/While, Go: for_statement, C: for_statement/while_statement |
| **Branch** | 分支体 (if/else/elif/switch-case) | 从 Conditional/Loop 展开得到 |
| **TryCatch** | 异常处理 | PHP: Try, JS: TryStatement, Java: TryStatement, Python: Try/ExceptHandler, Go: defer (语义等价), C: — |
| **Import** | 导入/包含 | PHP: Include/Require/UseDeclaration, JS: ImportDeclaration/Require, Java: Import, Python: Import/ImportFrom, Go: import_declaration, C: #include |
| **Parameter** | 函数参数定义 | PHP: FormalParameter, JS: param (FunctionDeclaration.params), Java: FormalParameter, Python: arguments, Go: parameter_list, C: parameter_declaration |
| **BinaryOp** | 二元操作 | PHP: BinaryOp, JS: BinaryExpression, Java: BinaryOperator, Python: BinOp, Go: binary_expression, C: binary_expression |
| **UnaryOp** | 一元操作 | PHP: UnaryOp, JS: UnaryExpression/UpdateExpression, Java: UnaryOperator, Python: UnaryOp/UAdd/USub, Go: unary_expression, C: unary_expression |
| **MemberAccess** | 成员/属性访问 | PHP: ObjectProperty/ArrayOffset, JS: MemberExpression, Java: FieldAccess/ArrayAccess, Python: Attribute/Subscript, Go: selector_expression/index_expression, C: member_access/array_subscript |
| **New** | 对象实例化 | PHP: New, JS: NewExpression, Java: ClassCreator, Python: Call (class 构造), Go: —, C: — |
| **Throw** | 抛出异常 | PHP: Throw, JS: ThrowStatement, Java: ThrowStatement, Python: Raise, Go: —, C: — |
| **TypeCast** | 类型转换 | PHP: Cast, JS: —, Java: CastExpression, Python: — (隐式), Go: call_expression(type), C: cast_expression |
| **Lambda** | 匿名函数 | PHP: Closure, JS: ArrowFunctionExpression/FunctionExpression, Java: LambdaExpression, Python: Lambda, Go: func_literal, C: — |
| **Property** | 类属性/字段 | PHP: ClassVariable, JS: PropertyDefinition, Java: FieldDeclaration, Python: Assign(ClassDef body), Go: var_declaration, C: struct member |
| **Decorator** | 装饰器/注解 | PHP: —, JS: —, Java: Annotation, Python: decorator, Go: —, C: — |

### 3.3 统一边类型 (EdgeLabel)

| 统一边标签 | 语义 | 方向 | 典型场景 |
|-----------|------|------|---------|
| **CONTAINS** | 文件/类/函数包含子节点 | parent → child | File→Function, File→Class, Function→Statement, Class→Property, Class→Method |
| **DEFINES** | 定义变量/参数 | parent → child | Function→Parameter, Class→Property, Block→Variable |
| **ASSIGNS_TO** | 赋值目标 (LHS) | Statement → Variable | `$x = 1`, `x = 1` |
| **ASSIGNS_FROM** | 赋值来源 (RHS) | Statement → Expression | `$x = $y`, `x = func()` |
| **CALLS** | 函数调用 | FunctionCall → 被调用目标 | `system($cmd)`, `$obj->method()` |
| **CALLER_ARG** | 调用参数 | FunctionCall → Argument | 第 0,1,2... 个参数 |
| **RETURNS** | 返回值 | Return → Expression | `return $x`, `return func()` |
| **CONDITION_OF** | 条件属于哪个控制结构 | Expression → Conditional | if 条件表达式 |
| **TRUE_BRANCH** | if 真分支体 | Conditional → Block | if (...) { ... } |
| **FALSE_BRANCH** | if 假分支体 | Conditional → Block | if (...) { } else { ... } |
| **LOOP_BODY** | 循环体 | Loop → Block | for (...) { ... } |
| **CATCHES** | catch 块 | TryCatch → Block | try { } catch (e) { } |
| **THROWS** | try 保护的代码 | TryCatch → Block | try { ... } |
| **IMPORTS** | 导入关系 | File → File (跨文件) | `include 'a.php'`, `import b` |
| **CLASS_EXTENDS** | 类继承 | Class → Class | `class B extends A` |
| **CLASS_IMPLEMENTS** | 接口实现 | Class → Interface | `class B implements I` |
| **HAS_METHOD** | 类方法 | Class → Function | class 内的方法定义 |
| **HAS_PROPERTY** | 类属性 | Class → Property | class 内的属性定义 |
| **MEMBER_OF** | 属性/方法属于类 | MemberAccess → Class | `$this->prop`, `self::method` |
| **FLOWS_TO** | 数据流（分析时生成） | Variable → Variable | `$input → $cmd → system()` |

### 3.4 节点通用属性

```python
# 所有节点的通用属性
{
    'language': str,        # php / javascript / java / python / go / c
    'raw_type': str,        # 原始 AST 节点类型名 (如 'FunctionCall', 'MethodInvocation')
    'lineno': int,          # 起始行号
    'end_lineno': int,      # 结束行号 (可选)
    'file_path': str,       # 所属文件绝对路径
    'code_snippet': str,    # 对应源码片段 (可选, 用于展示)
}
```

**各节点类型特有属性：**

| 节点类型 | 特有属性 | 说明 |
|---------|---------|------|
| File | path, language, content_hash | 文件路径、语言、内容 MD5 |
| Function | name, fqn, is_method, class_name, modifiers | 函数全限定名、是否方法、所属类 |
| Class | name, fqn, parent_class, interfaces | 类全限定名、父类、接口列表 |
| Variable | name, scope | 变量名、作用域 |
| FunctionCall | name, callee_type | 调用名称 (function/method/static_method) |
| Assignment | operator | 赋值运算符 (=, +=, .=) |
| Import | import_path, import_type | 导入路径、类型 (include/require/import/from) |
| Parameter | name, default_value, type_hint | 参数名、默认值、类型提示 |
| Literal | value, value_type | 字面量值和类型 |
| Branch | branch_type | true / false / elif / case |
| BinaryOp | operator | +, -, *, /, ., ==, !=, &&, \|\| |

### 3.5 图存储结构示意

```cypher
# 示例: <?php function test($input) { $cmd = $input; system($cmd); }

(File:app.php)-[:CONTAINS]->(Function:test {fqn:'test', lineno:2})
(Function:test)-[:DEFINES]->(Parameter:$input {lineno:2})
(Function:test)-[:CONTAINS]->(Assignment:$cmd=$input {lineno:3})
  (Assignment)-[:ASSIGNS_TO]->(Variable:$cmd {lineno:3})
  (Assignment)-[:ASSIGNS_FROM]->(Variable:$input {lineno:3})
(Function:test)-[:CONTAINS]->(FunctionCall:system {lineno:4})
  (FunctionCall:system)-[:CALLS]->(Function:system {name:'system', builtin:true})
  (FunctionCall:system)-[:CALLER_ARG {index:0}]->(Variable:$cmd {lineno:4})
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

在现有 Django DB 中新增两张表，用于**不加载图时的快速查询**：

```python
# 新增模型 (web/index/models.py)

class AstNodeIndex(models.Model):
    """AST 节点快速索引 — 轻量级，不含图结构"""
    file_path = models.CharField(max_length=500)
    node_label = models.CharField(max_length=50)    # Function, Class, Variable...
    node_name = models.CharField(max_length=200, null=True)
    lineno = models.IntegerField()
    language = models.CharField(max_length=20)
    fqn = models.CharField(max_length=500, null=True)  # Function.fqn

    class Meta:
        indexes = [
            models.Index(fields=['file_path', 'node_label']),
            models.Index(fields=['node_label', 'node_name']),
            models.Index(fields=['fqn']),
        ]


class FileHash(models.Model):
    """文件内容哈希 — 用于增量更新判断"""
    file_path = models.CharField(max_length=500, primary_key=True)
    content_hash = models.CharField(max_length=32)   # MD5
    language = models.CharField(max_length=20)
    scan_time = models.DateTimeField(auto_now=True)
```

**用途示例：**

```sql
-- Web 列表页：不加载图就能查到某文件有哪些函数
SELECT node_name, lineno FROM ast_node_index
WHERE file_path = '/app/routes.php' AND node_label = 'Function';

-- 增量更新：快速判断哪些文件变了
SELECT file_path FROM file_hashes
WHERE project_id = 1 AND content_hash != '<new_hash>';

-- 全局搜索：某函数在哪些文件中定义
SELECT DISTINCT file_path, lineno FROM ast_node_index
WHERE node_name = 'run' AND node_label = 'Function';
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
python kunlun.py analyze <graph_dir>

# 子命令:
  analyze functions   [-n name] [-l language] [-c class]   # 查询函数
  analyze classes     [-n name]                             # 查询类
  analyze calls       [-n callee_name] [-f file]             # 查询调用
  analyze taint       --source $_GET --sink system          # 查询污点路径
  analyze context     --vul-id 42                           # 查询漏洞分析上下文
  analyze rejected    [-n sink_name]                        # 查询被过滤的sink
  analyze subgraph    [-f file] [--function fqn]            # 提取子图
  analyze visualize    [-f file] [-o output.png]             # 可视化
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

### Phase 1: 基础图构建（PHP 单语言验证）

**目标**: 验证 PHP AST → igraph 的完整流程

- [ ] `core/graph/base.py` — UnifiedNode / UnifiedEdge 数据类
- [ ] `core/graph/php_normalizer.py` — PHP AST 归一化
- [ ] `core/graph/builder.py` — AstGraphBuilder
- [ ] `core/graph/io.py` — AstGraphIO (save/load)
- [ ] Django migration — AstNodeIndex + FileHash 表
- [ ] 集成到 Pretreatment — parse 后同步构建图
- [ ] 测试: 与现有引擎结果对比

### Phase 2: 图上分析验证

**目标**: 在图上实现 parameters_back，对比结果

- [ ] `core/graph/analyzer.py` — GraphAnalyzer 基础版
- [ ] `core/graph/analyzer.py` — parameters_back 图版本
- [ ] `core/graph/analyzer.py` — function_back 图版本
- [ ] 双模运行: 现有引擎 + 图引擎，对比结果
- [ ] 测试: 对 5 个 PHP 漏洞靶场验证一致性

### Phase 3: 二次分析 API

**目标**: 扫描完成后可加载图查询

- [ ] `core/graph/session.py` — AstGraphSession
- [ ] `core/graph/query.py` — GraphQueryBuilder
- [ ] CLI `analyze` 子命令
- [ ] Web 页签原型

### Phase 4: 多语言扩展

- [ ] JS Normalizer (esprima)
- [ ] Python Normalizer (ast)
- [ ] Java Normalizer (javalang)
- [ ] Go Normalizer (tree-sitter)
- [ ] C Normalizer (tree-sitter)
- [ ] 每种语言的双模验证

### Phase 5: 切换图模式

- [ ] 分析引擎完全切换到图
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

## 附录 C: TraceCache 知识库覆盖

| 语言 | 内置条目数 | 覆盖范围 |
|------|----------|---------|
| PHP | ~500+ | 最完善，覆盖常见 Web 函数 |
| Java | ~300+ | 框架方法覆盖好 |
| JavaScript | ~200+ | Node.js 浏览器 API |
| Python | ~200+ | 标准库 + Web 框架 |
| Go | ~150+ | 标准库为主 |
| C | ~120+ | libc + 常见函数 |

## 附录 D: Source Discovery 框架覆盖

| 语言 | 支持的框架 |
|------|-----------|
| PHP | Laravel, ThinkPHP, CodeIgniter, Symfony |
| Python | Flask, Django, FastAPI |
| JavaScript | Express, Koa, Hapi, Fastify |
| Go | Gin, Echo, Fiber, Chi, Beego, GORM |
| C | CGI, libcurl, OpenSSL |
