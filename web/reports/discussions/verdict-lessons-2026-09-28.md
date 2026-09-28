# 判定经验教训（2026-09-28）

> 产物性质：本文件由审计数据自动汇总，供团队定期复盘讨论、修订后作为下一阶段的**判定标准**。
> 数据基线：513 条人工判定（其中 510 条含实质备注）。

## 一、FP 高频判定模式（按出现次数排序）

| 模式 | 次数 | 含义 |
|---|---|---|
| var-rebind | 3 | 变量被 foreach/赋值重绑定，源头已换 |
| var-shadow | 3 | 同名变量遮蔽，链的源头不是声明的源 |

## 二、TP 高频确认模式

| 模式 | 次数 | 含义 |
|---|---|---|

## 三、待讨论的判定口径分歧

以下口径在本批数据中出现过**两种立场**，建议复盘会上定标准：

1. **demo/示例代码算不算攻击面**——微信 sample 的 checkSignature 被人工判 FP（签名守卫不可伪造），
   AI 判 TP（访问控制非净化）。需要明确：第三方 SDK 的示例路由是否默认排除。
2. **老项目批量豁免是否持续有效**——"old CMS no filtering" 类项目级批量 TP 覆盖了引擎的链级判断，
   本次 AI 复核发现其中部分链本身错配（见引擎缺陷清单）。项目级豁免应标注有效期/复核轮次。
3. **二阶注入（存储型反序列化）算不算该规则的发现**——引擎把 SQL 注入链尾接到 unserialize sink，
   人工口径是"二阶需要额外前提，不算本规则的直接发现"。AI 已跟随此口径，建议成文。

## 四、规则级判定实录（备注最多 TOP5 规则）

### CVI-1000 Reflected XSS（492 条备注）

- `FP` wolf/plugins/markdown/MarkdownController.php:34： 判例批量采纳: P3判例覆盖(exact级): 同规则同代码模式已有 49 例人工判定 | 同模式人工判例一致判FP
- `FP` wolf/plugins/textile/TextileController.php:35： 判例批量采纳: P3判例覆盖(exact级): 同规则同代码模式已有 49 例人工判定 | 同模式人工判例一致判FP
- `FP` src/wp-includes/blocks/legacy-widget.php:142： 判例批量采纳: P3判例覆盖(exact级): 同规则同代码模式已有 49 例人工判定 | 同模式人工判例一致判FP

### CVI-1015 unserialize vulerablity（10 条备注）

- `FP` admin/include/plugins.class.php:439： 批量复核改判->fp: chain-mismatch-verified | 原人工标注: tp | 原注: 
- `FP` admin/include/plugins.class.php:540： 批量复核改判->fp: chain-mismatch-verified | 原人工标注: tp | 原注: 
- `FP` admin/include/plugins.class.php:593： 批量复核改判->fp: chain-mismatch-verified | 原人工标注: tp | 原注: 

### CVI-1014 variable shadowing（2 条备注）

- `FP` fp-plugins/gdprvideoembed/res/gdpr-video-embed.css.php:9： 判例批量采纳: P3判例覆盖(exact级): 同规则同代码模式已有 2 例人工判定 | 同模式人工判例一致判FP
- `FP` www/install/index.php:290： 判例批量采纳: P3判例覆盖(exact级): 同规则同代码模式已有 2 例人工判定 | 同模式人工判例一致判FP

### CVI-1017 Path Traversal（2 条备注）

- `FP` actions/fileupload.php:78： filename validated by validate_filename() + is_filename_allowed() whitelist before fopen
- `FP` htdocs/class/xoopseditor/tinymce4/external_plugins/filemanag： FP: L108 unlink($targetFile) — targetFile 由 $_FILES['file']['name'](客户端可控) 拼接但 path jail 已卡 storeFolder 前缀, unlink 仅删已上传文件, 无安全影响

### CVI-7008 XSS（1 条备注）

- `FP` src/werkzeug/debug/__init__.py:409： 批量复核改判->fp: sanitized | 原人工标注: tp | 原注: 
