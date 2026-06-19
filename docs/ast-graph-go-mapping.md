# Go AST → Unified Graph Mapping

## Parser: tree-sitter-go

Go 使用 `tree-sitter-go` 作为 AST 解析器（通过 `tree-sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"function_declaration"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"{"`、`"+"` |

---

## Node Type Mapping

### Class (2 types)

| Go AST Node | Unified Label | ClassType | 备注 |
|-------------|---------------|-----------|------|
| `package_clause` | CLASS | class | 包名作为 class 节点 |
| `type_spec` (含 `struct_type`) | CLASS | class | struct 定义 |
| `type_spec` (含 `interface_type`) | CLASS | interface | 接口定义 |

### Import (1 type)

| Go AST Node | Unified Label | ImportType | 备注 |
|-------------|---------------|------------|------|
| `import_declaration` | IMPORT | import | 单个/分组 import 均支持 |

Grouped import `import ("a" "b")` 展开为多个 IMPORT 节点（每个 `import_spec` 一个）。

### Function (3 types)

| Go AST Node | Unified Label | FunctionType | 备注 |
|-------------|---------------|-------------|------|
| `function_declaration` | FUNCTION | function | 普通函数 |
| `method_declaration` | FUNCTION | method | 方法（name 在 `field_identifier`） |
| `func_literal` | FUNCTION | function | 匿名函数/lambda |

**方法声明特殊处理：**
- 方法名在 `field_identifier` 子节点（非 `identifier`）
- 第一个 `parameter_list` 是 receiver（如 `(u *User)`），不作为参数
- 返回值检测：simple return 在 param_list 和 block 之间的 `type_identifier`；named return 使用第二个/第三个 `parameter_list`

### Branch (7 types)

| Go AST Node | Unified Label | BranchType | 备注 |
|-------------|---------------|------------|------|
| `if_statement` | BRANCH | if | 条件为二元表达式 |
| `else_clause` (含 `block`) | BRANCH | else | else 分支 |
| `else_clause` (含 `if_statement`) | BRANCH | if (递归) | else if 嵌套 |
| `for_statement` (含 `for_clause`) | BRANCH | for | C 风格 for |
| `for_statement` (含 `range` 关键字) | BRANCH | foreach | range for |
| `expression_switch_statement` | BRANCH | switch | switch 语句 |
| `expression_case` | BRANCH | case | case 子句 |
| `default_case` | BRANCH | default | default 子句 |
| `select_statement` | BRANCH | switch | select 语句（映射为 switch） |
| `communication_case` | BRANCH | case | select case 子句 |

### Operator (14+ types)

| Go AST Node | Unified Label | OperatorType | 备注 |
|-------------|---------------|-------------|------|
| `call_expression` (identifier callee) | OPERATOR | call | 普通函数调用 |
| `call_expression` (selector callee) | OPERATOR | method_call | 方法调用 |
| `call_expression` (func_literal callee) | OPERATOR | call | lambda 调用 |
| `type_conversion` | OPERATOR | call | 类型转换 |
| `binary_expression` | OPERATOR | binary_op | 二元运算 |
| `unary_expression` | OPERATOR | unary_op | 一元运算（!/-/*/&) |
| `unary_expression` (<-) | OPERATOR | binary_op | receive 操作 |
| `short_var_declaration` | OPERATOR | assign | := 短变量声明 |
| `assignment_statement` | OPERATOR | assign | 赋值 |
| `inc_statement` | OPERATOR | unary_op | ++ |
| `dec_statement` | OPERATOR | unary_op | -- |
| `go_statement` | OPERATOR | call | go 协程启动 |
| `defer_statement` | OPERATOR | call | defer 延迟执行 |
| `break_statement` | OPERATOR | break | break |
| `continue_statement` | OPERATOR | continue | continue |
| `selector_expression` | OPERATOR | method_call | 属性访问 a.b |
| `index_expression` | OPERATOR | binary_op | 索引 a[i] |

### Identifier (2 types)

| Go AST Node | Unified Label | IdentifierType | 备注 |
|-------------|---------------|---------------|------|
| `identifier` | IDENTIFIER | variable | 普通标识符 |
| `field_identifier` | IDENTIFIER | property | 字段名（struct member） |
| `type_identifier` | IDENTIFIER | static | 类型名 |

`nil`/`true`/`false` 被映射为 CONST 节点。

### Const (4 types)

| Go AST Node | Unified Label | ConstType | 备注 |
|-------------|---------------|-----------|------|
| `int_literal` | CONST | number | 整数 |
| `float_literal` | CONST | number | 浮点数 |
| `imaginary_literal` | CONST | number | 虚数 |
| `interpreted_string_literal` | CONST | string | 双引号字符串 |
| `raw_string_literal` | CONST | string | 反引号字符串 |
| `rune_literal` | CONST | string | 字符 |

### Parameter

| Go AST Node | Unified Label | 备注 |
|-------------|---------------|------|
| `parameter_declaration` | PARAMETER | 仅普通参数（不含 receiver） |

### Return

| Go AST Node | Unified Label | 备注 |
|-------------|---------------|------|
| `return_statement` | RETURN | return 语句 |

---

## Edge Type Mapping

| 边类型 | Go 中的使用场景 |
|--------|-----------------|
| OWN | file→class, file→import, class→field, function→param, branch→statement |
| AST | branch→condition, call→callee, call→arg, binary→left/right, return→value, assign→lhs/rhs |
| MEMBER | identifier→selector_expression (属性访问) |
| FRG | import→dependency (外部依赖) |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression |
| CALLEE | call→callee node |
| ARG | call→argument (with arg_index) |
| LEFT | binary→left operand |
| RIGHT | binary→right operand / selector→field |
| VALUE | return→expression, unary→operand |
| LHS | assignment→left side |
| RHS | assignment→right side |
| IFTRUE | (reserved for future use) |
| IFFALSE | if→else |
| DECL | var decl→identifier |

---

## tree-sitter Go 关键陷阱

1. **method_declaration 的名字在 field_identifier** — 不是 `identifier` 子节点
2. **grouped import 使用 import_spec_list** — 一个 `import_declaration` 包含多个 `import_spec`
3. **for-range 没有专门的 for_range_clause 节点** — range 关键字出现在普通 `for_statement` 的子节点文本中
4. **Literal 的值是源码文本** — 如 `"10"` 不是 `10`，与 javalang 类似
5. **关键字/标点是叶节点** — `"if"`、`"{"`、`"+"` 都是独立节点，需过滤跳过
6. **nil/true/false 是叶节点** — 不是 identifier，需要特殊处理映射到 CONST
