# tree-sitter 前端评估报告（2026-11-07）

评估环境：py tree-sitter 0.26.0 / tree-sitter-php 0.25.1 / tree-sitter-java / tree-sitter-javascript（PyPI `tree-sitter`，注意包名不是 `py-tree-sitter`；PHP 语法必须用 `language_php()`（php+html 模板）而非 `language_php_only()`，否则模板文件 36/306 假失败）

## 结论：语法覆盖全面胜出，性能 ~8x，但迁移成本极高——判"远期备选，不迁移"

### 1. 语法覆盖（冻结语料 + 边界用例）

| 语言 | 冻结语料 | 边界用例（战役实战缺口家族） |
|---|---|---|
| PHP | 306/306 ✅（php+html 语法） | heredoc/nowdoc/enum/match/nullsafe/attributes/readonly/first-class-callable/intersection-types/老式模板 10/10 ✅ |
| Java | 309/309 ✅ | record/sealed/yield/var/text-block/instanceof-pattern/switch-pattern/generic-method-ref/annotated-generic/enum-with-body 10/10 ✅ |
| JS | 68/68 ✅ | **BigInt 123n ✅**（lesprima 现缺口）+ optional-chain/nullish/class-fields/private-method/async-arrow/labeled-break/regex-lookbehind/exponent 9/9 ✅ |

三语言现役解析器已修到语料门 100%，tree-sitter 同样 100%——覆盖差距当前为零；差异在**未冻结区域**：tree-sitter 是增量维护的官方语法（新语法免修），自维护 fork 每个缺口要战役式修复。

### 2. 性能

- 单文件（196KB class.forms.php）：tree-sitter 44ms vs phply 330ms（**7.5x**）
- osticket 全量 717 文件：1.1s vs 9.5s（**8.4x**）
- 但：Kunlun-M build 段现只占 2.45min（Fix 63c 后），parse 是其中一部分——换 tree-sitter 端到端收益估计 <1min，非痛点。

### 3. 错误恢复（关键优势）

- tree-sitter：截断/损坏文件仍产出可遍历的部分 AST（局部 ERROR 节点，不吞兄弟）→ 引擎可继续分析合法前缀
- phply/ljavalang：截断=SyntaxError 全弃（ljavalang 2.1.3 刚修过 EOF 哨兵，仍只是报错弃文件）
- 实战意义：ureport 截断文件那类情况，tree-sitter 能救回部分检出

### 4. 迁移成本（否决近期迁移的原因）

- normalizer 层全部重写：现 normalizer 面向 phply/ljavalang/esprima 的 AST 形状（节点名/边角色），tree-sitter CST 完全不同（named/unamed 节点、字段名访问）
- 三语言 × 图构建 + 回溯语义对齐 + 全锚回归（6 锚 + CVE 门 + 3 语料门）——量级 ≥ 此前所有战役总和
- 图谱接口（NodeLabel/EdgeLabel 语义）不变，但每个 normalizer ~千行级

### 5. 建议

1. **不迁移**（现役三件套 100% 覆盖 + 性能非瓶颈 + 成本极高）
2. 新语言接入（go/c 复检、lua、py 的 tree-sitter 系）时**直接用 tree-sitter**，不再自维护 fork
3. JS 的 BigInt 真缺口：留给 lesprima 升级或将来 JS 前端换装时解决（gate 已反向 pin）
4. 本报告落 skill 存档，下次"解析器缺口"战役先查此结论，避免重复评估
