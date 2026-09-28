# 裁决台账（2026-09-28）

> 产物性质：本批所有非常规裁决的完整证据链。每条可独立复核。

## A. 采信 AI 的改判（12 条）

- **#408** CVI-1015 `admin/include/plugins.class.php:439`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：报告的sink是admin/include/plugins.class.php:439的unserialize，来源为$_POST['cat_false']，但给出的传播链完全不符：链路实际追踪的是picture_modify.php中$_GET['image_id']拼入SQL语句后经get_taglist传入pwg_query执行，属于SQL查询流程，与
  - 独立核实：链文件 functions.php/picture_modify.php ≠ sink 文件 plugins.class.php ✓
- **#409** CVI-1015 `admin/include/plugins.class.php:540`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：报告的sink是plugins.class.php:540的unserialize，但给定传播链显示$_GET['image_id']仅流入picture_modify.php:198的SQL字符串拼接，最终经get_taglist→pwg_query执行查询，数据流并未到达unserialize调用点，链路与sink不匹配。该链路本质是疑似SQL拼接而非反
  - 独立核实：链文件 functions.php/picture_modify.php ≠ sink 文件 plugins.class.php ✓
- **#410** CVI-1015 `admin/include/plugins.class.php:593`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：传播链与sink不匹配：链中各步均为picture_modify.php中$_GET['image_id']拼接进SQL后传入get_taglist/pwg_query的流程，属于SQL注入痕迹，没有任何步骤显示$_POST['cat_true']流入plugins.class.php:593的unserialize。源与汇属于两条不同数据流，疑似引擎错误拼
  - 独立核实：链文件 functions.php/picture_modify.php ≠ sink 文件 plugins.class.php ✓
- **#413** CVI-1015 `admin/include/themes.class.php:492`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：传播链显示 $_POST['associate'] 被传入 associate_images_to_categories 后经 implode 拼入 SQL 查询（functions.php:2039），全程未流经所报 sink themes.class.php:492 的 unserialize，链路与反序列化规则不匹配，属 sink 错配的误报。但该数据
  - 独立核实：链文件 batch_manager_global.php/functions.php ≠ sink 文件 themes.class.php ✓
- **#414** CVI-1015 `admin/include/themes.class.php:545`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：传播链显示 $_GET['image_id'] 仅被拼接进 SQL 语句并传入 get_taglist/pwg_query 执行，数据流终点是数据库查询。而报告的 sink 是 themes.class.php:545 的 unserialize，链中没有任何步骤把该输入传递到该文件或该调用，链与 sink 明显脱节，反序列化规则不成立。即使该拼接存在 SQ
  - 独立核实：链文件 functions.php/picture_modify.php ≠ sink 文件 themes.class.php ✓
- **#421** CVI-1015 `include/functions.inc.php:2555`
  - 判定：人工 tp → **fp**（AI 推理）
  - AI 理由：$_POST['cat_false'] 经 get_uppercat_ids 后被 implode 直接拼入 SQL 查询，污点实际进入的是数据库查询层，而非直接传入 unserialize。unserialize 的输入来自数据库 uppercats 等存储字段，只有在借助 SQL 注入实现二阶攻击时才可能被控制，直接数据流在查询处已断裂。且 group_
  - 独立核实：未独立核实
- **#423** CVI-1015 `include/ws_functions/pwg.php:487`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：报告的sink是pwg.php:487的unserialize，但传播链实际终止于functions.php:977的implode拼入SQL查询，两者之间没有任何数据流连接，链路与sink不匹配。$_POST['cat_false']经get_uppercat_ids后仅用于构造SQL，未进入任何序列化/反序列化操作。该unserialize的输入来源在链
  - 独立核实：链文件 functions.php/group_perm.php ≠ sink 文件 pwg.php ✓
- **#502** CVI-7008 `src/werkzeug/debug/__init__.py:409`
  - 判定：人工 tp → **fp**（AI 推理）
  - AI 理由：该 sink 位于 display_pin_security_dialog，其响应体来自固定的 PIN_TEMPLATE，填充的是服务端生成的 PIN 与布尔值 trusted，均为非用户可控数据。传播链中 request.args 的 cmd/secret/frm 仅用于路由判断与相等比较（==）及 int 类型转换，并未拼接进该 HTML 响应。链路中 
  - 独立核实：未独立核实
- **#1981** CVI-1015 `admin/include/themes.class.php:495`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：传播链与报告漏洞不匹配：链路实际从$_POST['cat_false']经get_uppercat_ids汇入SQL的WHERE id IN拼接，终点是SQL查询，从未到达themes.class.php:495的unserialize点，链路中也未出现$_GET['image_id']。unserialize sink缺少用户可控输入的可达性证据，且入口位
  - 独立核实：链文件 functions.php/group_perm.php ≠ sink 文件 themes.class.php ✓
- **#1982** CVI-1015 `admin/include/themes.class.php:548`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：传播链与报告的 sink 不匹配：报告称漏洞点为 themes.class.php:548 的 unserialize，但链路实际终止于 functions.php:1343 的 SQL 拼接 implode，全链路无任何 unserialize 调用节点。且入口为 $_POST['cat_false']，并非规则所述的 $_GET['image_id']。
  - 独立核实：链文件 functions.php/user_perm.php ≠ sink 文件 themes.class.php ✓
- **#1990** CVI-1015 `include/ws_functions/pwg.php:581`
  - 判定：人工 tp → **fp**（链错配实锤）
  - AI 理由：报告的 sink 是 include/ws_functions/pwg.php:581 的 unserialize，但给出的传播链实际是 $_GET['image_id'] 拼接进 SQL 语句后流向 get_taglist/pwg_query，属于 SQL 执行 sink，链路与 unserialize 汇点完全不匹配，数据流并未到达反序列化点。此外该代码
  - 独立核实：链文件 functions.php/picture_modify.php ≠ sink 文件 pwg.php ✓
- **#6607** CVI-1000 `pts-core/phoromatic/pages/phoromatic_r_add_test_details.php:81`
  - 判定：人工 tp → **fp**（AI 推理）
  - AI 理由：传播链仅重复 sink 行，未展示 $_GET 到 $o->get_identifier() 的实际数据流。$_GET['result'] 只用于选择服务端已保存的结果文件，$o 的标识符来自解析结果文件得到的对象，并非直接反射用户输入，属于对象成员访问被过度污染传播的典型误报。但结果文件内容若由客户端上传，理论上存在二阶注入可能，与报告的反射型 XSS 路
  - 独立核实：未独立核实

## B. 保留人工的裁决（253 条，按原因分组）
- 190 条：substantive-note
- 56 条：unverifiable-keep-tp
- 4 条：fp-is-safe-side
- 3 条：chain-same-file

## C. 判例批量采纳（487 条）

- 来源分布：exact/module 判例覆盖
- 判例源头：同模式 ≥2 例人工一致判定（49 例 echo 族 FP 为主力判例）
