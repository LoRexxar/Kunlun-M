# 配置说明（Kunlun_M/settings.py）

首次使用建议从模板复制：
```bash
cp Kunlun_M/settings.py.bak Kunlun_M/settings.py
```

## 必改项（建议）
- `SECRET_KEY`：生产环境必须改成随机值
- `DEBUG`：生产环境务必关闭
- `API_TOKEN`：用于 `/api/*` 鉴权（参数名：`apitoken`）

## 数据库
默认使用 sqlite：
- 文件位置：`db/kunlun.db`

如果切换 MySQL，需要同时调整 `DATABASES` 并安装对应驱动（例如 `mysqlclient`）。

## 目录与路径
- `LOGS_PATH`：日志目录（默认 `logs/`）
- `PLUGIN_PATH`：插件目录（默认 `core/plugins/`）
- `IGNORE_PATH`：忽略文件（默认 `Kunlun_M/.kunlunmignore`）

## 供应链漏洞扫描（SCA）
- `WITH_VENDOR`：是否启用组件漏洞扫描（默认关闭）
- `ACTIVE_SCA_SYSTEM`：启用的漏洞源（例如 `osv`、`depsdev`、`ossindex`、`murphysec`）
- `MURPHYSEC_TOKEN`：使用 murphysec 时需要配置

推荐默认组合：
- `['osv', 'depsdev', 'ossindex']`

说明：
- 开启 SCA：将 `WITH_VENDOR = True`
- `osv` 优先命中；未命中时才会补充查询其它源（用于控制请求量）
- 依赖文件中带版本约束（如 `^1.2.3`）会先做版本规范化，无法解析则跳过漏洞查询（仍会入库组件）

## 远程模式（预留）
- `IS_OPEN_REMOTE_SERVER`、`REMOTE_URL`、`REMOTE_URL_APITOKEN`：用于对接远程 Server 的预留配置（以实际代码路径为准）
