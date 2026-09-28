# 引擎缺陷清单（2026-09-28）

> 产物性质：给引擎侧的改进 backlog。每条都有可复现的证据锚点（vul id + 文件对照）。

## 链-sink 错配（最高优先级，已实锤 9 例）

**现象**：报告的 sink 文件与传播链文件完全不同源——链在中途接到了另一个数据流上。
典型：Piwigo rule 1015（unserialize），sink 在 `plugins.class.php`/`themes.class.php`，
但链全部终止于 `picture_modify.php` 的 SQL 拼接（`$_GET[image_id]` → implode → pwg_query）。

| vul id | 规则 | sink 文件 | 链实际文件 |
|---|---|---|---|
| #408 | 1015 | plugins.class.php | functions.php/picture_modify.php |
| #409 | 1015 | plugins.class.php | functions.php/picture_modify.php |
| #410 | 1015 | plugins.class.php | functions.php/picture_modify.php |
| #413 | 1015 | themes.class.php | batch_manager_global.php/functions.php |
| #414 | 1015 | themes.class.php | functions.php/picture_modify.php |
| #423 | 1015 | pwg.php | functions.php/group_perm.php |
| #1981 | 1015 | themes.class.php | functions.php/group_perm.php |
| #1982 | 1015 | themes.class.php | functions.php/user_perm.php |
| #1990 | 1015 | pwg.php | functions.php/picture_modify.php |

**建议修复方向**：parameters_back 回溯时校验每步文件与 sink 文件同源（或同函数调用链），
跨文件跳转必须经过明确的 include/require/call 边，否则剪链。

## 死代码后的不可达报告

helper.php 等公共库中 `die();`/`exit;` 之后的语句仍被报告（已由 21h-2 修复大部分，残留见 stale 列表）。

## 规则级 FP 率（结论回馈引擎侧参考）

| 规则 | 人工 FP 率 | 样本 | 说明 |
|---|---|---|---|
| CVI-1014 variable shadowing | 100% | 5 | 建议规则级复核/降噪 |
| CVI-1015 unserialize vulerablity | 100% | 10 | 建议规则级复核/降噪 |
| CVI-1000 Reflected XSS | 100% | 492 | 建议规则级复核/降噪 |
| CVI-7008 XSS | 100% | 1 | 建议规则级复核/降噪 |
| CVI-1017 Path Traversal | 100% | 2 | 建议规则级复核/降噪 |
| CVI-1008 Xml injection | 100% | 1 | 建议规则级复核/降噪 |
| CVI-1016 Unrestricted File Upload | 100% | 1 | 建议规则级复核/降噪 |
| CVI-1001 SSRF | 100% | 1 | 建议规则级复核/降噪 |
