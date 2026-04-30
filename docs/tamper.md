# Tamper（污点/修复策略）

Tamper 用于给引擎注入“过滤/净化函数（repair）”与“输入可控源（controlled）”的配置，从而减少特定框架/CMS 场景的误报。

## 文件位置与命名
Tamper 位于：
```
rules/tamper/<name>.py
```

可参考模板：
- `rules/tamper.template`

## 数据结构
一个 tamper 文件通常提供两个变量：
- `<name>`：过滤/净化函数映射（函数名 -> 适用规则列表等）
- `<name>_controlled`：输入可控源列表（如 `$_GET`、`$_POST` 等）

## 使用方式
### CLI 扫描时指定
```bash
python kunlun.py scan -t <target_path> -tp <name>
```

### 同步到数据库（用于 Web 展示/管理）
```bash
python kunlun.py config loadtamper
```

## 注意事项
- Tamper 会影响“可控性回溯/漏洞成立判断”的边界，建议按项目类型单独维护与验证。
- 不要在 tamper 中写入真实密钥或敏感配置；只维护“函数名/规则编号/输入源”这类抽象信息。

