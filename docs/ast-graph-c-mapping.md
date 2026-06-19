# C/C++ AST → Unified Graph Mapping

## Parser: tree-sitter-c

C/C++ 使用 `tree-sitter-c` 作为 AST 解析器（通过 `tree_sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter C 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型 |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node] |
| `node.start_point` | (row, col) |

---

## Node Type Mapping

### Class (3 types)

| C AST Node | Unified Label | ClassType | 备注 |
|-----------|---------------|-----------|------|
| `type_definition` + `struct_specifier` | CLASS | struct | typedef struct |
| `struct_specifier` (standalone) | CLASS | struct | struct 定义 |
| `type_definition` + `enum_specifier` | CLASS | enum | typedef enum |

### Import (1 type)

| C AST Node | Unified Label | ImportType | 备注 |
|-----------|---------------|------------|------|
| `preproc_include` + `system_lib_string` | IMPORT | include | `#include <header>` |
| `preproc_include` + `string_literal` | IMPORT | include | `#include "file"` |

### Function (1 type)

| C AST Node | Unified Label | FunctionType | 备注 |
|-----------|---------------|-------------|------|
| `function_definition` | FUNCTION | function | 完整函数定义 |
| `declaration` + `function_declarator` | FUNCTION | function | 前向声明 |

函数名在 `function_declarator > identifier`。返回类型是 `function_definition` 的第一个 `primitive_type`/`type_identifier` 子节点。

### Branch (7 types)

| C AST Node | Unified Label | BranchType | 备注 |
|-----------|---------------|------------|------|
| `if_statement` | BRANCH | if | 条件在 parenthesized_expression |
| `else_clause` + `compound_statement` | BRANCH | else | else 分支 |
| `else_clause` + `if_statement` | BRANCH | if (递归) | else if |
| `for_statement` | BRANCH | for | C 风格 for |
| `while_statement` | BRANCH | while | while 循环 |
| `do_statement` | BRANCH | while | do-while |
| `switch_statement` | BRANCH | switch | switch 语句 |
| `case_statement` | BRANCH | case / default | case/default |
| `conditional_expression` | BRANCH | ternary | 三元运算 `?:` |

### Operator (10+ types)

| C AST Node | Unified Label | OperatorType | 备注 |
|-----------|---------------|-------------|------|
| `call_expression` | OPERATOR | call | 函数调用 |
| `call_expression` (member callee) | OPERATOR | method_call | 方法调用 |
| `binary_expression` | OPERATOR | binary_op | 二元运算 |
| `unary_expression` | OPERATOR | unary_op | !/-/*/&/~ |
| `update_expression` | OPERATOR | unary_op | ++/-- |
| `assignment_expression` | OPERATOR | assign | = / += 等 |
| `cast_expression` | OPERATOR | type_cast | (type)expr |
| `sizeof_expression` | OPERATOR | unary_op | sizeof |
| `member_expression` / `field_expression` | OPERATOR | method_call | a.b / a->b |
| `subscript_expression` | OPERATOR | binary_op | a[i] |

### Identifier (2 types)

| C AST Node | Unified Label | IdentifierType |
|-----------|---------------|---------------|
| `identifier` | IDENTIFIER | variable |
| `field_identifier` | IDENTIFIER | property |
| `type_identifier` | IDENTIFIER | static |

### Const (3 types)

| C AST Node | Unified Label | ConstType |
|-----------|---------------|-----------|
| `number_literal` | CONST | number |
| `string_literal` | CONST | string |
| `char_literal` | CONST | string |
| `null` (→ NULL leaf) | CONST | null |

---

## Edge Type Mapping

| 边类型 | C 中的使用场景 |
|--------|---------------|
| OWN | file→import, file→function, function→param, class→field, branch→statement |
| AST | branch→condition, call→callee/arg, binary→left/right, assign→lhs/rhs, return→value |
| MEMBER | identifier→member_expression |
| FRG | import→dependency |

---

## tree-sitter C 关键陷阱

1. **函数名嵌套在 function_declarator 中** — `function_definition > function_declarator > identifier`
2. **返回类型是直接子节点** — `function_definition` 的第一个 `primitive_type`/`type_identifier`
3. **NULL 是 `null` 节点** — 子节点是 `NULL` 叶节点（不是 identifier）
4. **变量声明 init 在 init_declarator 内** — `declaration > init_declarator > identifier [= expr]`
5. **指针参数嵌套深** — `parameter_declaration > pointer_declarator > identifier`
6. **for 语句的 init 是 declaration** — 不是变量声明表达式
7. **三元运算有独立节点** — `conditional_expression`
