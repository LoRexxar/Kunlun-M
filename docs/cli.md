# CLI 使用说明

Kunlun-M 的命令入口是：
```bash
python kunlun.py <subcommand> [args]
```

## 子命令一览

### init
初始化/迁移数据库：
```bash
python kunlun.py init initialize
python kunlun.py init checksql
```

### config
同步规则与 tamper（文件 <-> 数据库）：
```bash
python kunlun.py config load
python kunlun.py config recover
python kunlun.py config loadtamper
python kunlun.py config retamper
```

### scan
扫描目标路径或压缩包：
```bash
python kunlun.py scan -t tests/vulnerabilities
python kunlun.py scan -t tests/vulnerabilities -r 1000,1001
python kunlun.py scan -t tests/vulnerabilities -tp wordpress
```

常用参数：
- `-t/--target`：目标文件/目录（必填）
- `-r/--rule`：只跑指定规则（逗号分隔 CVI 编号）
- `-lan/--language`：指定语言（逗号分隔）；不传会自动识别主语言/框架
- `-b/--blackpath`：黑名单路径列表（逗号分隔，例如 `-b vendor,node_modules`）
- `--without-vendor`：关闭组件漏洞（SCA）扫描
- `-d/--debug`：开启 debug 日志

说明：
- 目标为 `.zip` 时会尝试自动解压后扫描。
- 未指定 `-o` 输出文件名时，会默认写到 `result/<target>.<format>`。

### show
查看规则与 tamper：
```bash
python kunlun.py show rule
python kunlun.py show rule -k php
python kunlun.py show tamper
```

### search
搜索组件/项目（vendor）信息：
```bash
python kunlun.py search vendor <keyword_name> <keyword_value> --with-vuls
```

### console
进入交互式控制台：
```bash
python kunlun.py console
```

### plugin
运行插件：
```bash
python kunlun.py plugin <plugin_name> -h
python kunlun.py plugin entrance_finder -t <target_path> -l 3
```

### web
启动 Web（Dashboard/API）：
```bash
python kunlun.py web -p 9999
```

