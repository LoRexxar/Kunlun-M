# 供应链组件漏洞扫描（SCA）

Kunlun-M 的 SCA 目标是：在不引入大规模爬虫/离线漏洞库的前提下，基于项目依赖清单快速识别“当前版本是否命中已公开漏洞”，并把结果入库到 Dashboard 可展示的组件/漏洞视图。

默认配置下 SCA 是关闭的（`WITH_VENDOR = False`）。需要启用时，在 `Kunlun_M/settings.py` 将 `WITH_VENDOR = True`。

## 数据流

1. 扫描阶段解析依赖清单（requirements.txt / composer.json / go.mod / pom.xml / build.gradle / package.json）
2. 组件写入 `ProjectVendors`（按 project 维度）
3. 组件漏洞查询（按 `ACTIVE_SCA_SYSTEM` 启用源）
4. 漏洞写入/更新 `VendorVulns`
5. 若关联扫描任务（task_id），同时写入扫描结果流（ResultFlow）用于任务详情展示

## 为什么不做“全量漏洞库/爬虫”

开源项目往往难以承担：
- 定期同步全量漏洞库的数据体量与更新频率
- 漏洞源格式差异导致的解析与存储复杂度
- 对外提供爬虫/镜像服务带来的运维成本

因此默认采用“按需查询 + 本地入库缓存”的方式：效果可能弱于商业平台，但更可落地、维护成本更低。

## 数据源策略

默认策略是“优先主源命中，未命中再补充查询”：

- OSV：主来源（覆盖 Maven/PyPI/npm/Go/Packagist 等常用生态，开放 API）
- deps.dev：补充来源（适合 npm/go/maven 等）
- OSS Index：补充来源（适合 pypi/composer 等）
- murphysec：可选（需要 Token）

当前实现以“版本命中”为主：`VendorVulns.affected_versions` 默认只记录当前扫描到的版本号，从而避免受影响版本范围枚举导致的数据爆炸。

## 版本规范化

依赖文件中常见版本约束（例如 `^1.2.3`、`~1.0`、`>=1.0`），在请求外部数据源前会做一次规范化，尽量提取可用于查询的具体版本号；无法解析则视为 `unknown` 并跳过漏洞查询（仍会入库组件本身）。
