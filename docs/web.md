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
/backend/tasklog/<task_id>?token=<visit_token>
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
- `GET /api/task/<task_id>/resultflow`
- `GET /api/task/<task_id>/newevilfunc`
- `GET /api/rule/list`
- `GET /api/rule/<rule_id>`

