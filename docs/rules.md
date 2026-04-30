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
- `regex-only-match`：纯正则命中，命中即视为结果（不进入语义分析）
- `function-param-regex`：匹配敏感函数调用点，并对参数做可控性回溯（PHP/JS）
- `vustomize-match`：先正则命中，再调用规则 `main()` 抽取需回溯的参数列表
- `regex-return-regex`：命中后生成二次正则进行进一步匹配
- `file-path-regex-match`：按路径/文件名命中（敏感文件类规则）
- `special-crx-keyword-match`：Chrome 扩展关键字匹配

## 规则加载与生效
运行时扫描会从 `rules/` 目录动态加载规则文件。

如果需要在 Web 侧展示/管理规则，需要把规则同步到数据库：
```bash
python kunlun.py config load
```

## 调试建议
- 用 `scan -r <id1,id2>` 只跑少量规则定位问题
- 用 `scan -d` 开启 debug 输出
- 用 `show rule -k <language>` 快速确认规则是否可被加载与识别

