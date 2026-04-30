# 组件安全扫描（SCA）开源方案计划

## Summary

在现有“项目维度组件表（ProjectVendors）+ 组件漏洞表（VendorVulns）”的数据基础上，补齐一套**可在开源项目预算内落地**的组件安全扫描方案：以 **OSV API** 为主要数据源，并保留现有 **deps.dev / OSS Index** 作为补充；在 **/core/vendors.py** 的解析与入库流程上做“版本规范化、去重、批量查询、缓存/限流、结果入库一致性”改造，尽量在不引入大规模爬虫/离线漏洞库的前提下，让扫描结果稳定、可复现、可扩展。

你已确认的取舍：
- 数据源：OSV + 现有源（deps.dev / OSS Index）
- 扫描入口：扫描时同步（沿用现有流程）
- 准确性/成本：混合策略（默认“版本命中”，对少数生态做更精确处理）

## Current State Analysis

### 现有能力（已存在）
- 组件解析与扫描入口：[/core/vendors.py](file:///d:/program/Kunlun_M/core/vendors.py)
  - 扫描时会在目标目录内寻找 `requirements.txt / composer.json / go.mod / pom.xml / build.gradle / package.json` 等依赖清单并解析组件。
  - 每发现一个组件即调用 `get_and_save_vendor_vuls()` 拉取漏洞并入库（同步、逐条请求）。
- 漏洞数据源聚合：[/core/vuln_apis/__init__.py](file:///d:/program/Kunlun_M/core/vuln_apis/__init__.py)
  - 通过 `VENDOR_ECOSYSTEM` + `ACTIVE_SCA_SYSTEM` 决定启用哪些源。
- 已启用的数据源与生态映射：
  - [/Kunlun_M/const.py](file:///d:/program/Kunlun_M/Kunlun_M/const.py)：目前 `depsdev/ossindex/murphysec`（默认启用 depsdev + ossindex）
  - [/Kunlun_M/settings.py](file:///d:/program/Kunlun_M/Kunlun_M/settings.py)：`ACTIVE_SCA_SYSTEM = ['depsdev', 'ossindex']`
- 数据表：
  - `ProjectVendors`（项目组件表）与 `VendorVulns`（组件漏洞表）定义在 [models.py](file:///d:/program/Kunlun_M/web/index/models.py#L77-L181)
  - `ProjectVendors.source` 字段由迁移 [0009](file:///d:/program/Kunlun_M/web/index/migrations/0009_projectvendors_source.py) 增加

### 主要问题/风险点（需要在方案里解决）
1) **请求量放大与耗时不可控**
   - 当前是“发现一个组件 → 立刻对每个启用源发请求”，在组件数较多时会线性放大请求次数。
2) **版本字符串不规范导致命中率低**
   - `composer.json` / `package.json` 中常见 `^1.2.3 / ~1.0 / >=1.0` 等约束写法；当前会直接把原始字符串传给数据源，容易查询失败或返回不准确。
3) **ProjectVendors.hash 与 source 入库一致性存在缺陷**
   - `ProjectVendors.save()` 里 hash 计算与 `update_and_new_project_vendor()` 的 hash 计算方式不一致，且创建新记录时未写入 `source`，会影响“以项目为单位的组件数据”可靠性。
4) **affected_versions 结构偏“枚举”，不适合范围表达**
   - 现有保存逻辑与 UI 展示都倾向“受影响版本列表”；但对开源可承受方案而言，更现实的是“只确认当前版本是否受影响 + 记录来源/证据链接”。

## Proposed Changes

### A. 新增 OSV 数据源（主来源）
**目标**：用开源、覆盖面广、无需爬虫的 OSV API 作为主要漏洞源，避免维护离线漏洞库。

- 新增文件：`core/vuln_apis/osv.py`
  - 实现 `get_vulns_from_osv(ecosystem, package_name, version)`（与现有 `get_vulns_from_*` 约定一致）。
  - 优先使用 OSV 的 batch 查询接口（将同一生态的多个 `(package, version)` 合并请求），减少网络往返与 QPS 压力。
  - 结果字段对齐当前 `VendorVulns` 入库结构：`vuln_id/title/description/severity/cves/reference/affected_versions`
    - **混合策略落地**：
      - 默认：`affected_versions = [当前 version]`（只保证“版本命中”）
      - 对可轻量获得更精确信息的生态（例如能直接给出明确 fixed/introduced 的场景），在不引入巨大数据量的前提下，额外补充到 `description` 或 `reference`（不强制做全范围枚举，避免爆表）。
- 修改：[/Kunlun_M/const.py](file:///d:/program/Kunlun_M/Kunlun_M/const.py)
  - 在 `VENDOR_ECOSYSTEM` 中为现有语言加入 `osv` 映射（例如 Maven/PyPI/npm/Go/Packagist 等对应到 OSV 的 ecosystem 名称）。
- 修改：[/Kunlun_M/settings.py](file:///d:/program/Kunlun_M/Kunlun_M/settings.py)
  - 将 `osv` 加入 `ACTIVE_SCA_SYSTEM` 默认启用列表（同时保留 `depsdev/ossindex` 作为补充）。

### B. vendors.py：版本规范化 + 去重 + 批量查询
**目标**：控制请求量、提升命中率、让同一次扫描的结果更稳定。

- 修改：[/core/vendors.py](file:///d:/program/Kunlun_M/core/vendors.py)
  1. **版本规范化**
     - 在进入 `get_and_save_vendor_vuls()` 前，对 `vendor_version` 做统一清洗：
       - `abstract_version()`：提取最可能用于查询的“具体版本号”（对 `^/~/>=/<=` 等做降噪）
       - 清洗失败则标记为 `unknown`：仅入库组件，不发漏洞查询（避免无意义请求）
  2. **同文件/同项目依赖去重**
     - 对解析出的 `(language, name, version)` 去重后再发起漏洞查询，避免同一组件被多处声明导致重复请求。
  3. **批量查询策略**
     - OSV：按 `(language/ecosystem)` 聚合成 batch 请求（优先）。
     - OSS Index：利用其 component-report 支持一次提交多个 coordinates（按上限分批）。
     - deps.dev：缺少稳定 batch 时保持单条，但默认作为补充源（或仅在 OSV 无结果时触发）。
  4. **请求级缓存/限流（轻量）**
     - 基于本地文件缓存（例如 `tmp/sca_cache.json`）记录 `(source, ecosystem, package, version) -> last_result_hash/last_time`，同一次扫描与短期重复扫描直接复用，避免重复打外部 API。
     - 失败重试策略：小次数重试 + 退避（避免网络波动导致整次扫描失败）。

### C. 修复 ProjectVendors 的“以项目为单位组件数据”一致性
**目标**：确保 2.5.0 新增的“项目组件表”可作为可靠基座。

- 修改：[/web/index/models.py](file:///d:/program/Kunlun_M/web/index/models.py#L77-L127)
  - 统一 `ProjectVendors.hash` 的计算口径（建议包含 `project_id + name + language + source`；source 为空时回退到旧口径），避免 `save()` 覆盖掉 `update_and_new_project_vendor()` 写入的 hash。
  - `update_and_new_project_vendor()` 在创建新记录时补齐 `source/ext` 字段写入，避免 source 长期为空。
  - 保持兼容：不引入新的必填字段、不增加迁移，避免升级成本。

### D. 文档与可配置项
**目标**：让开源用户可以按成本开关数据源与扫描强度。

- 更新文档（建议位置）：
  - `docs/architecture.md` 或新增 `docs/sca.md`：说明“为什么不用离线全量漏洞库/爬虫”、OSV/deps.dev/OSS Index 的取舍、缓存策略与准确性边界。
  - `docs/configuration.md`：补充 `ACTIVE_SCA_SYSTEM`、缓存开关、batch 大小、超时/重试等配置说明。

## Assumptions & Decisions

- 不引入大规模离线漏洞库（如定期同步 NVD/全量 advisory 数据），避免数据体量与更新维护成本。
- 默认以 OSV 做“版本命中”判定；更精确的版本范围信息只做轻量补充，不做全量枚举写入数据库（避免 `affected_versions` 爆炸）。
- 仍以“扫描时同步”作为入口，不额外增加后台定时任务与新 UI（你已选择该入口）。

## Verification

1) 单元/自测脚本
- 构造最小依赖清单（requirements/composer/package.json/go.mod/pom.xml）覆盖：
  - 精确版本、约束版本（^/~/>=/<=）、unknown
  - 重复依赖声明（去重验证）
2) 功能验证（本地）
- 运行一次完整扫描流程，确认：
  - `ProjectVendors` 中 source/ext/version 正确写入且不被覆盖
  - 启用 `osv` 后，`VendorVulns` 能入库并在 Dashboard “组件漏洞列表”中展示
  - 网络失败时不会中断全流程（重试/降级生效）
3) 性能/请求量验证
- 对一个包含较多依赖的样例项目：
  - 统计外部请求次数（batch 前/后对比）
  - 确认缓存命中后重复扫描请求显著减少

