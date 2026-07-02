# 规则（Rule）开发

## 规则文件位置与命名
规则必须放在：
```
rules/<language>/CVI_<id>.py
```

要求：
- 文件名严格为 `CVI_<id>.py`
- 规则类名需与文件名一致（例如 `class CVI_1000:`）

可参考模板：
- `rules/rule.template`

## 规则最小字段
规则类 `__init__` 里通常需要：
- `svid`：编号
- `language`：语言（如 `php`、`javascript`）
- `author`
- `vulnerability`、`description`
- `level`：等级
- `status`：是否启用
- `match_mode`：匹配/验证模式
- `match`：命中点正则或敏感函数集合
- `vul_function`：用于语义分析的敏感函数集合（按 match_mode 决定是否使用）

## match_mode（常见模式）

### 图引擎模式（v3.0 推荐）
| match_mode | 说明 | 是否需要图 |
|---|---|---|
| `function-param-regex` | 图引擎 sink 匹配 + `vul_function` fullname + `parameters_back` 污点追踪 | ✅ AST 图 |
| `java-function-param-controllable` | Java 专用 sink 匹配路径 | ✅ AST 图 |
| `go-function-param-controllable` | Go 专用 sink 匹配路径 | ✅ AST 图 |
| `c-function-param-controllable` | C/C++ 专用 sink 匹配路径 | ✅ AST 图 |

### 独立扫描模式（不依赖图引擎）
| match_mode | 说明 | 是否需要图 |
|---|---|---|
| `file-pattern` | 文件名正则 + 内容正则双重匹配，独立于图引擎。适用场景：MyBatis `${}` 检测（`file_pattern = r'.*Mapper\.xml$'`）等需要按文件名限定扫描范围的规则 | ❌ |
| `framework-dependency` | 框架依赖版本检测 (pom.xml/build.gradle) | ❌ |
| `file-path-regex-match` | 敏感文件名/路径匹配 | ❌ |
| `special-crx-keyword-match` | Chrome 扩展关键字匹配 | ❌ |

### 已废弃模式（LEGACY，不走图引擎，待清理）
| match_mode | 说明 |
|---|---|
| `only-regex` | 纯正则命中（已跳过） |
| `vustomize-match` | 自定义参数匹配（已跳过） |
| `regex-return-regex` | 回馈式正则（已跳过） |
| `only-keyword` | 纯关键字匹配（已跳过） |

### `file-pattern` 规则示例

```python
class CVI_6071(SingleRuleMixin):
    def __init__(self):
        self.svid = 6071
        self.language = "java"
        self.vulnerability = "SQL Injection (MyBatis)"
        self.match_mode = "file-pattern"
        self.file_pattern = r'.*Mapper\.xml$'   # 文件名正则（限制只扫描 Mapper XML）
        self.match = r"\$\{[^}]+\}"              # 内容正则（${} 模式）
        self.vul_function = []

    def main(self, match_string):
        """可选二次筛选"""
        if not re.search(r'\$\{', match_string):
            return None
        return True
```

`file_pattern` 是可选的。如果不设置，则对所有文件都进行内容匹配。

## 规则加载与生效
运行时扫描会从 `rules/` 目录动态加载规则文件。规则会在进入 console 或执行 scan 时自动同步到数据库，无需手动操作。

如需手动触发同步（例如在 Web 端管理前）：
```bash
python kunlun.py config load
```

## 调试建议
- 用 `scan -r <id1,id2>` 只跑少量规则定位问题
- 用 `scan -d` 开启 debug 输出
- 用 `show rule -k <language>` 快速确认规则是否可被加载与识别
