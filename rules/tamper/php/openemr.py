# -*- coding: utf-8 -*-
import json
import os

FRAMEWORK_NAME = 'OpenEMR'
DEPENDENCIES = {'composer': []}


def detect(project_dir, language='php'):
    """检测是否为 OpenEMR 项目（Fix 86, CVE-2026-126489）

    1) composer.json name == openemr/openemr（注意：OpenEMR 自身依赖
       symfony/* 组件，name 判定必须先于依赖判定，否则会被抢注为 symfony）
    2) 目录结构回退：library/sql.inc.php（DB 封装层）+ interface/
    """
    composer_json = os.path.join(project_dir, 'composer.json')
    if os.path.isfile(composer_json):
        try:
            with open(composer_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('name') == 'openemr/openemr':
                return True
        except (json.JSONDecodeError, OSError):
            pass
    return (os.path.isfile(os.path.join(project_dir, 'library', 'sql.inc.php'))
            and os.path.isdir(os.path.join(project_dir, 'interface')))


FILTER_FUNCTIONS = {}
# OpenEMR relies on _base.php standard library filter functions

# 二阶污点源：DB 读封装返回值（library/sql.inc.php @ v8_4_1 实测三读函数）。
# layout_options 等 admin 可编辑表经 sqlFetchArray/sqlQuery/sqlGetAssoc
# 读回后拼入 SQL（CVE-2026-126489 列名位注入）。
CONTROLLED_SOURCES = [
    'sqlFetchArray(',
    'sqlQuery(',
    'sqlGetAssoc(',
]

EXTRA_SINKS = [
    # Fix 106 (CVE-2026-126482): sqlQuery first arg (SQL text) accepts
    # only ONE bound param — SLEOB::slInvoiceNumber interpolated $pid
    # (uploaded 835 CLP01) into the query string.
    ("sqlQuery(", [1006]),
    ("sqlStatement(", [1006]),
    ("sqlStatementNoLog(", [1006]),
    ("sqlInsert(", [1006]),
    # Fix 111 (CVE-2026-126480): QueryUtils static wrapper family — same
    # semantics as the library/sql.inc.php wrappers (arg0 = query TEXT,
    # remaining args = bound params, not interpolable). Used by the Zend
    # modules (CcrTable::insertApprovedData builds "UPDATE patient_data
    # SET $fields" from request parameter NAMES).
    ("QueryUtils::sqlStatementThrowException(", [1006]),
    # Fix 115c (CVE-2026-126478): fetchRecords is the read-side sibling —
    # arg0 is the caller-built query text (arg1 bound params are safe).
    # Syndromicsurveillance module: form_icd_codes[] POST array imploded
    # into an unquoted numeric IN() clause, executed via fetchRecords.
    ("QueryUtils::fetchRecords(", [1006]),
    # Fix 113b (CVE-2026-126480 focused sweep): CDR-engine wrappers in
    # library/sql.inc.php (v8_4_1 :177/:313) are pure delegations to the
    # sqlStatement/sqlQuery family.  Before this, taint chains ended ON THE
    # WRAPPER BODY (sql.inc.php:185/:187/:321 rows) because callers of the
    # CdrEngine names were not sink lines.  Registering them moves the
    # verdict to each caller's own line (Fix 113 doctrine); their bodies
    # are demoted via _SQL_WRAPPER_FUNC_NAMES.
    ("sqlStatementCdrEngine(", [1006]),
    ("sqlQueryCdrEngine(", [1006]),
]

# Fix 108 (CVE-2026-126482): OpenEMR 官方输出转义助手（library/htmlspecialchars.inc.php
# v8_4_1 实测，全部为 htmlspecialchars/json_encode 包装）注册为 XSS repair。
# 只收编码函数，不收 xl()（裸翻译不转义）与渲染器（generate_display_field 等回显
# 型助手不属于公认编码函数）。
FILTER_FUNCTIONS = {
    # Fix 115d (CVE-2026-126478): escape_limit / CommonPlugin::escapeLimit
    # is `(int)` cast (library/formdata.inc.php:43 @ v8_2_0) — a genuine
    # numeric sanitizer for LIMIT fragments.  Registered for SQL-family
    # svids only.
    "escapeLimit": [1005, 1006],
    "escape_limit": [1005, 1006],
    "text": [1000, 10001, 10002],          # htmlspecialchars(ENT_NOQUOTES)
    "attr": [1000, 10001, 10002],          # htmlspecialchars(ENT_QUOTES)
    "attr_js": [1000, 10001, 10002],       # attr(json_encode(x))
    "js_escape": [1000, 10001, 10002],     # json_encode(x)
    "json_sanitize": [1000, 10001, 10002], # json 往返规范化（library/sanitize.inc.php）
    "xlt": [1000, 10001, 10002],           # text(xl(x))
    "xla": [1000, 10001, 10002],           # attr(xl(x))
    "xlj": [1000, 10001, 10002],           # js_escape(xl(x))
    # Fix 113c (CVE-2026-126480 focused sweep): OpenEMR SQL 防御函数族
    # （library/formdata.inc.php @ v8_4_1 实测）注册为 SQLi repair。
    # 只收【全上下文安全】的消毒器：schema/枚举白名单类。值位置编码器
    # add_escape_custom（mysqli_real_escape_string 包装）刻意不收——
    # ippf_issues/patient.inc 两个历史 TP 恰是它被误用在标识符/无引号
    # 位置（blanket 注册会杀真漏洞，CVE repro 门 2026-11-18 实证回归）；
    # 正确的值位置建模=上下文条件 repair（引号内才生效），属后续引擎
    # 资产。process_cols_escape（纯 explode 拆分）也不收。
    "escape_sql_column_name": [1006],      # DB 列名 schema 白名单 + 反引号包裹
    "escape_table_name": [1006],           # QueryUtils::escapeTableName（表名白名单）
    "escape_identifier": [1006],           # 白名单/正则标识符消毒
    "escape_sort_order": [1006],           # asc/desc 白名单
    # clinical_rules.php:3091 — 内部自构引号上下文（'...') 内包 add_escape_custom，
    # intervalValue 收窄为 (int)，返回值对 1006 安全（防御 builder，非攻击面）
    "sql_interval_string": [1006],
}
