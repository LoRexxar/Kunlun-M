# -*- coding: utf-8 -*-

"""
    Node.js SQL 注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3104(SingleRuleMixin):
    """
    Node.js SQL 注入规则
    匹配 mysql.query、pg.query、sequelize.query/literal、knex.raw 等数据库操作
    """

    def __init__(self):
        self.svid = 3104
        self.language = "javascript"
        self.vulnerability = "SQL注入"
        self.description = "使用了数据库查询函数（connection.query、sequelize.query、knex.raw等）且SQL语句可能受用户控制，可能导致SQL注入漏洞。建议使用参数化查询（prepared statements）替代字符串拼接。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.query\s*\(|\.raw\s*\(|\.whereRaw\s*\(|\.literal\s*\(|sequelize\.query\s*\(|knex\.raw\s*\("

        self.vul_function = [
            "query", "raw", "whereRaw", "literal",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码SQL和安全的参数化查询
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除 ? 占位符的参数化查询（安全的）
        # connection.query("SELECT * FROM users WHERE id = ?", [userId]) — 安全
        match = re.search(r'\.query\s*\((.*)\)', regex_string)
        if match:
            args = match.group(1).strip()
            # 纯硬编码SQL
            if re.match(r'^["\'][^"\']*["\'](?:\s*,\s*\[.*\])?$', args):
                sql_str = re.match(r'^["\']([^"\']*)["\']', args)
                if sql_str:
                    sql = sql_str.group(1)
                    # 包含 ? 占位符 → 参数化查询，安全
                    if '?' in sql:
                        return False
                    # 不包含变量拼接的纯静态SQL
                    if '${' not in sql and '+' not in sql:
                        return False
            return True

        # .raw() / .whereRaw() / .literal()
        raw_match = re.search(r'(?:\.raw|\.whereRaw|\.literal)\s*\((.*)\)', regex_string)
        if raw_match:
            args = raw_match.group(1).strip()
            # 纯硬编码
            if re.match(r'^["\'][^"\']*["\'](?:\s*,.*)?$', args):
                return False
            return True

        return None
