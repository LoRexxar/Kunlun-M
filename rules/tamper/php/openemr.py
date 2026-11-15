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
    ("sqlStatement(", [1006]),
    ("sqlStatementNoLog(", [1006]),
    ("sqlInsert(", [1006]),
]
