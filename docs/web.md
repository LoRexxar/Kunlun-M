# Web / Dashboard / API

## 启动
```bash
python kunlun.py web -p 9999
```

主要入口：
- Dashboard：`http://127.0.0.1:9999/dashboard/`
- Backend（日志等）：`http://127.0.0.1:9999/backend/`
- API：`http://127.0.0.1:9999/api/`

## 鉴权方式

### 1) 登录（Session）
大部分 Dashboard 页面需要登录后访问。

### 2) 分享访问 token（URL 参数名：token）
用于在不登录的情况下查看单个任务/项目详情与日志（按任务的 `visit_token` 校验）。

示例：
```
/dashboard/tasks/detail/<task_id>?token=<visit_token>
/backend/debuglog/<task_id>?token=<visit_token>
```

### 3) API Token（参数名：apitoken）
访问 `/api/*` 需要提供 `apitoken`，其值来自 `Kunlun_M/settings.py` 的 `API_TOKEN`。

示例：
```
/api/task/list?apitoken=<API_TOKEN>
/api/task/<task_id>/result?apitoken=<API_TOKEN>
```

可在 Dashboard 的用户信息页查看当前配置的 API Token：
- `/dashboard/userinfo`

## API 列表（常用）
- `GET /api/task/list`
- `GET /api/task/<task_id>`
- `GET /api/task/<task_id>/result`
- `GET /api/task/<task_id>/taintchain`
- `GET /api/task/<task_id>/newevilfunc`
- `GET /api/rule/list`
- `GET /api/rule/<rule_id>`

## Web 新建扫描（上传 Zip）
Dashboard 提供“Tasks → New Scan”用于上传 zip 包并创建扫描任务。

要点：
- 任务状态：Queued(3) / Running(2) / Success(1) / Error(0)
- 上传落盘：`tmp/package/<task_id>/upload.zip`
- 解压目录：`tmp/package/<task_id>/src/`
- 执行方式：Web 侧派发子进程执行 `python kunlun.py scan --task-id <id> -t <dir> ...`

配置项（`Kunlun_M/settings.py`）：
- `WEB_UPLOAD_MAX_MB`：上传大小限制（默认 50）
- `WEB_PACKAGE_RETENTION_DAYS`：上传包与解压目录保留天数（默认 7）
- `WEB_SCAN_MAX_CONCURRENCY`：最大并发（默认 1，超出进入队列）

常用入口：
- 新建扫描：`/dashboard/tasks/new`
- 配置扫描：`/dashboard/tasks/config/<task_id>`
- 任务列表：`/dashboard/tasks/list`
- 任务详情：`/dashboard/tasks/detail/<task_id>`
- Debug 日志：`/backend/debuglog/<task_id>`
- 导出结果：`/backend/export/<task_id>?format=csv|json`
