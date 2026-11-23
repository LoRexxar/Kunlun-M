# -*- coding: utf-8 -*-
import json
import os

FRAMEWORK_NAME = 'SuiteCRM'
DEPENDENCIES = {'composer': []}


def detect(project_dir, language='php'):
    """检测是否为 SuiteCRM 项目（Fix 146a, CVE-2026-100365）

    1) composer.json name == suitecrm/suitecrm（项目型 composer，
       name 判定先于依赖判定，防止被 symfony/* 抢注）
    2) 目录结构回退：suitecrm_version.php（SuiteCRM 独有版本文件）
       + modules/ 目录
    """
    composer_json = os.path.join(project_dir, 'composer.json')
    if os.path.isfile(composer_json):
        try:
            with open(composer_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get('name') == 'suitecrm/suitecrm':
                return True
        except (json.JSONDecodeError, OSError):
            pass
    return (os.path.isfile(os.path.join(project_dir, 'suitecrm_version.php'))
            and os.path.isdir(os.path.join(project_dir, 'modules')))


FILTER_FUNCTIONS = {
    # Fix 146a: DBManager 消毒函数族（include/database/DBManager.php @ 7.15.1
    # 实测）。quote = 值位置编码器（mysqli_real_escape_string 等价包装，
    # AOR_Report Value 分支大量使用 $this->db->quote($condition->value)）；
    # quoteIdentifier = 标识符位置编码（反引号包裹 + 反引号转义，用于
    # table alias / column 拼接位）。两者都是真实编码函数，非白名单。
    # Fix 150b (CVE-2026-69134): quoted = DBManager::quoted() — 引号包裹+
    # 转义的值编码器（retrieve() WHERE :4593、mark_deleted :5278 先 quote
    # 再下传 mark_undeleted :5330）。三个都是真实编码函数，非白名单。
    "quote": [1005, 1006],
    "quoteIdentifier": [1005, 1006],
    "quoted": [1005, 1006],
}

# 二阶污点源：SugarBean ORM mutator 形态（$bean->retrieve($id) 把 DB 行
# 写进对象属性）由图引擎 source_discovery FRAMEWORK_CONFIGS['suitecrm']
# 的 orm_mutator_methods 承载（Fix 146b/c）——tamper 侧 CONTROLLED_SOURCES
# 只建模「返回值」形态，与 mutator 形态语义不同，故此处不注册 retrieve。

EXTRA_SINKS = [
    # Fix 146a (CVE-2026-100365): SuiteCRM 全部 SQL 执行走 DBManager 实例
    # （$this->db->query / limitQuery / getOne，AOR_Report.php:575/:431
    # 实测）。arg0 = 调用方拼接的完整 SQL 文本。
    ("->query(", [1006]),
    ("->limitQuery(", [1006]),
    ("->getOne(", [1006]),
]
