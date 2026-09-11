# Ruby AST → Unified Graph Mapping

## Parser: tree-sitter-ruby

Ruby 使用 `tree-sitter-ruby` 作为 AST 解析器（通过 `tree-sitter.Language` + `tree_sitter.Parser`）。

### tree-sitter 节点模型

| 属性 | 说明 |
|------|------|
| `node.type` | str，节点类型（如 `"method"`、`"call"`） |
| `node.text` | bytes，UTF-8 源码文本 |
| `node.children` | list[Node]，子节点列表 |
| `node.start_point` | (row, col)，row 从 0 开始 |
| `node.end_point` | (row, col) |
| 关键字/标点 | 独立的叶节点，如 `"if"`、`"end"`、`"do"`、`"+"` |

---

## Node Type Mapping

### Class (2 types)

| Ruby AST Node | Unified Label | ClassType | 备注 |
|--------------|---------------|-----------|------|
| `class` | CLASS | class | 类定义，含 `constant`（类名）、`superclass`（父类）、`body_statement`（类体） |
| `module` | MODULE | module | 模块定义，含 `constant`（模块名）、`body_statement`（模块体） |

**类/模块特殊处理：**
- 类名取自 `constant` 子节点
- 父类信息取自 `superclass` 子节点，记录在 `attrs.superclass` 中
- 类体为 `body_statement` 子节点，遍历其中所有方法、调用等

### Import (2 types)

| Ruby AST Node | Unified Label | ImportType | 备注 |
|--------------|---------------|------------|------|
| `call` (callee=`require`/`require_relative`/`load`) | IMPORT | require | 库引入，参数为字符串路径 |
| `call` (callee=`include`/`extend`/`prepend`) | IMPORT | include | Mixin 引入，参数为模块名（`constant`/`identifier`） |

**require/import 特殊处理：**
- 仅当无 receiver（顶层调用）时才识别为 import
- `require`/`require_relative`/`load` 的路径取自第一个字符串参数
- 会额外生成 DEPENDENCY 节点并通过 FRG 边关联（FrgType=use）
- `include`/`extend`/`prepend` 的模块名取自第一个 `constant` 或 `identifier` 参数

### Function (4 types)

| Ruby AST Node | Unified Label | FunctionType | 备注 |
|--------------|---------------|-------------|------|
| `method` (name=`initialize`) | FUNCTION | constructor | 构造函数 |
| `method` (含 `receiver` 子节点) | FUNCTION | method | 实例方法（单例方法），如 `def self.foo` |
| `method` (无 receiver) | FUNCTION | function | 普通方法/全局函数 |
| `block` / `lambda` | FUNCTION | lambda | 块/Lambda 表达式，名称为 `<lambda>` |

**方法声明特殊处理：**
- 方法名在 `identifier` 子节点中
- 存在 `receiver` 子节点时为实例方法（FunctionType.METHOD），fullname 格式为 `receiver.method`
- `initialize` 特殊映射为构造函数（FunctionType.CONSTRUCTOR）
- 参数取自 `method_parameters` 下的 `parameter` 子节点
- 块函数的参数取自 `block_parameters` 下的 `parameter` 子节点
- 函数签名格式：`def name(param1, param2, ...)`

### Branch (11 types)

| Ruby AST Node | Unified Label | BranchType | 备注 |
|--------------|---------------|------------|------|
| `if` | BRANCH | if | 条件分支 |
| `unless` | BRANCH | if | 反条件分支（映射为 if） |
| `elsif` | BRANCH | elif | if 的 elsif 子句 |
| `else` | BRANCH | else | else 子句 |
| `case` / `case_match` | BRANCH | switch | case 匹配语句 |
| `when` | BRANCH | case | case 的 when 子句 |
| `while` / `until` | BRANCH | while | 循环（until 也映射为 while） |
| `for` | BRANCH | foreach | for 循环（Ruby 的 for..in） |
| `begin` | BRANCH | try | 异常处理块（begin..rescue..ensure..end） |
| `rescue` | BRANCH | catch | 异常捕获子句 |
| `ensure` | BRANCH | finally | 异常确保执行子句 |

**分支特殊处理：**
- `if`：条件节点位于 `"if"` 关键字和 `body_statement` 之间的第一个非跳过子节点
- `elsif`：通过 IFFALSE 边连接到父 if 节点
- `else`：通过 IFFALSE 边连接到父 if/elsif 节点
- `case`：值节点（匹配目标）位于 `"case"` 关键字和 `case_body` 之间的第一个子节点
- `when`：通过 `case` 边连接到父 case 节点
- `begin`：遍历子节点时识别 `rescue` 和 `ensure` 子句并分别处理
- `rescue`：通过 IFTRUE 边连接到父 begin 节点
- `ensure`：通过 `finally` 边连接到父 begin 节点

### Operator (8 types)

| Ruby AST Node | Unified Label | OperatorType | 备注 |
|--------------|---------------|-------------|------|
| `call` (无 receiver，无 `.` 操作符) | OPERATOR | call | 普通函数调用 |
| `call` (含 receiver 且操作符为 `.`) | OPERATOR | method_call | 方法调用（如 `obj.method`） |
| `assignment` | OPERATOR | assign | 赋值（`=`） |
| `binary` | OPERATOR | binary_op | 二元运算（`+`、`-`、`&&`、`||` 等） |
| `yield` | OPERATOR | yield | yield 生成器调用 |
| `raise` | OPERATOR | throw | 抛出异常 |
| `break` | OPERATOR | break | 跳出循环/块 |
| `next` | OPERATOR | continue | 下一次迭代（Ruby 的 next ≈ continue） |

**运算符特殊处理：**
- `call` 节点：先检查是否为 import/mixin 调用，再根据是否有 `.` 操作符决定 call/method_call
- `binary` 节点：所有操作数通过 OPERAND 边连接
- `assignment` 节点：左侧通过 LEFT 边连接，右侧通过 RIGHT 边连接
- `redo`（在 `_SKIP_TYPES` 中）被跳过，不生成节点

### Identifier (6 types)

| Ruby AST Node | Unified Label | IdentifierType | 备注 |
|--------------|---------------|---------------|------|
| `identifier` | IDENTIFIER | variable | 普通标识符/变量名 |
| `constant` | IDENTIFIER | static | 常量名（如 `MyClass`、`PI`） |
| `instance_variable` | IDENTIFIER | field | 实例变量（`@var`） |
| `global_variable` | IDENTIFIER | global | 全局变量（`$var`） |
| `class_variable` | IDENTIFIER | static | 类变量（`@@var`） |
| `self` | IDENTIFIER | this | self 关键字 |

**标识符特殊处理：**
- Ruby 有 5 种变量前缀：无（局部）、`@`（实例）、`@@`（类）、`$`（全局）、大写（常量）
- `constant` 和 `class_variable` 都映射为 `static` 类型
- `super` 在 `_SKIP_TYPES` 中被跳过

### Const (6 types)

| Ruby AST Node | Unified Label | ConstType | 备注 |
|--------------|---------------|-----------|------|
| `integer` | CONST | number | 整数 |
| `float` | CONST | number | 浮点数 |
| `string` / `string_content` / `heredoc` | CONST | string | 字符串（含 heredoc） |
| `character` | CONST | string | 字符 |
| `simple_symbol` / `complex_symbol` / `hash_key_symbol` / `symbol` | CONST | constant | 符号字面量（`:foo`） |
| `true` / `false` | CONST | boolean | 布尔值 |
| `nil` | CONST | null | 空值 |

**常量特殊处理：**
- Ruby 的 Symbol（`:`）映射为 ConstType.CONSTANT（而非 STRING）
- heredoc 作为字符串处理
- 所有字面量值是源码文本（如 `"42"` 不是 `42`）

### Parameter

| Ruby AST Node | Unified Label | 备注 |
|--------------|---------------|------|
| `parameter` (in `method_parameters`) | PARAMETER | 方法参数，name 取自 `identifier`/`instance_variable`/`global_variable` 子节点 |
| `parameter` (in `block_parameters`) | PARAMETER | 块参数 |

### Return

| Ruby AST Node | Unified Label | 备注 |
|--------------|---------------|------|
| `return` | RETURN | return 语句，返回值通过 VALUE 边连接 |

---

## Edge Type Mapping

| 边类型 | Ruby 中的使用场景 |
|--------|-----------------|
| OWN | file→class, class→function, function→parameter, branch→statement, branch→condition-substatement |
| AST | branch→condition, call→receiver(OPERAND), call→arg(ARG), binary→operand(OPERAND), return→value(VALUE), assignment→left(LEFT), assignment→right(RIGHT), if→elsif/else(IFFALSE), begin→rescue(IFTRUE), begin→ensure(finally), case→when(case) |
| FRG | import→dependency (USE) |

### AST Edge Roles

| Role | 使用场景 |
|------|---------|
| CONDITION | branch→condition expression（if/unless/while/until/case 的条件表达式） |
| OPERAND | call→receiver, binary→operand（操作数） |
| ARG | call→argument |
| LEFT | assignment→left side（赋值左侧） |
| RIGHT | assignment→right side（赋值右侧） |
| VALUE | return→expression（返回值表达式） |
| IFTRUE | begin→rescue（try→catch 关联） |
| IFFALSE | if→elsif/else（条件分支的否定路径） |

---

## 跳过的节点类型（_SKIP_TYPES）

以下 tree-sitter 节点类型在遍历过程中被跳过，不生成任何图节点：

| 类别 | 节点类型 |
|------|---------|
| 标点符号 | `(` `)` `{` `}` `[` `]` `;` `:` `,` |
| 比较运算符 | `==` `!=` `>=` `<=` `>` `<` |
| 逻辑运算符 | `&&` `||` `and` `or` `not` |
| 算术运算符 | `+` `-` `*` `/` `%` `=` `!` `~` `&` `\|` `^` |
| 特殊运算符 | `->` `::` `.` `..` `...` `=>` |
| 关键字 | `then` `end` `do` `begin` `elsif` `when` `rescue` `ensure` `in` |
| 关键字语句 | `super` `redo` `proc` |
| 元编程指令 | `attr_accessor` `attr_reader` `attr_writer` |

> **说明：** 这些节点在 tree-sitter-ruby 中作为独立叶节点存在，但其语义由父节点（如 `binary`、`if`、`class` 等）统一处理，因此不需要单独生成图节点。

## 直接透传的容器节点

以下 tree-sitter 节点类型不生成独立节点，而是直接遍历其子节点：

| 类别 | 节点类型 |
|------|---------|
| 参数容器 | `argument_list`, `arguments`, `method_parameters`, `parameter`, `block_parameter`, `destructured_parameter` |
| 解构模式 | `hash_pattern`, `array_pattern`, `match_pattern`, `in_pattern`, `pattern` |
| 控制流容器 | `else`, `then`, `end`, `do_block`, `body_statement` |
| 守卫条件 | `if_guard`, `unless_guard` |
| 数据结构 | `array`, `hash`, `pair`, `scope`, `range` |
| 操作符相关 | `splat`, `hash_splat`, `operator`, `field`, `call_operator` |
| 特殊结构 | `singleton_class`, `alias`, `parenthesized_statements` |

---

## Ruby 语言特性限制说明

### 1. 不支持 AST→图映射的特性

| 特性 | 说明 |
|------|------|
| 单例类 (`singleton_class`) | 仅透传子节点，不生成独立 class 节点 |
| 方法定义别名 (`alias`) | 仅透传子节点，不生成独立节点 |
| 元编程方法 (`attr_accessor` 等) | 在 `_SKIP_TYPES` 中被跳过 |
| `super` 调用 | 在 `_SKIP_TYPES` 中被跳过，不生成 OPERATOR 节点 |
| `redo` 语句 | 在 `_SKIP_TYPES` 中被跳过 |
| `proc` 关键字 | 在 `_SKIP_TYPES` 中被跳过 |
| 条件赋值 (`||=`, `&&=`) | 未做特殊处理，作为 binary 表达式处理 |
| 多重赋值 (`a, b = [1, 2]`) | 仅按 assignment 处理，右侧为数组表达式 |

### 2. tree-sitter Ruby 关键陷阱

1. **Ruby 的 `unless` 映射为 `if` 类型** — `unless` 和 `if` 都映射为 BranchType.IF，通过 `raw_type` 属性区分原始语法
2. **Ruby 的 `until` 映射为 `while` 类型** — `until` 和 `while` 都映射为 BranchType.WHILE，通过 `raw_type` 属性区分
3. **Ruby 的 `next` 映射为 `continue`** — Ruby 的 `next` 语义等价于其他语言的 `continue`
4. **Ruby 没有 C 风格的 `for` 循环** — 所有 `for` 循环都是 `for..in`（foreach），映射为 BranchType.FOREACH
5. **Ruby 的异常处理结构不同** — `begin..rescue..ensure..end` 对应 try/catch/finally，`rescue` 映射为 CATCH，`ensure` 映射为 FINALLY
6. **关键字/标点是叶节点** — `"if"`、`"end"`、`"do"`、`"+"` 都是独立节点，需过滤跳过
7. **Literal 的值是源码文本** — 如 `"42"` 不是 `42`，与 Go 类似
8. **Symbol 不是字符串** — Ruby 的 `:symbol` 映射为 ConstType.CONSTANT（非 STRING）
9. **`nil`/`true`/`false` 是叶节点** — 不是 identifier，需特殊处理映射到 CONST
10. **Mixin 调用（include/extend/prepend）映射为 IMPORT** — 与标准 require/import 不同，使用 ImportType.INCLUDE
11. **方法类型判定依赖 receiver** — 有 `receiver` 子节点为 METHOD，无 receiver 且非 `initialize` 为 FUNCTION
