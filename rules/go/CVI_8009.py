# -*- coding: utf-8 -*-

"""
    Go SQL注入(raw query)规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_8009(SingleRuleMixin):
    """
    Go SQL注入(raw query)规则
    匹配 db.Query / db.Exec / db.Raw 等
    """

    def __init__(self):
        self.svid = 8009
        self.language = "go"
        self.vulnerability = "SQL注入"
        self.description = "使用了直接拼接SQL语句的数据库查询函数（db.Query、db.Exec、db.Raw等），可能导致SQL注入漏洞。建议使用参数化查询（占位符?）或ORM框架，避免将用户输入直接拼接到SQL语句中。"
        self.level = 8

        self.match_mode = "function-param-regex"
        self.match = r"db\.Query\s*\(|db\.Exec\s*\(|db\.Raw\s*\("

        self.vul_function = ["db.Query", "db.Exec", "db.Raw"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：片段模式下无法判断参数是否拼接。
        保守策略：匹配到 raw query 函数就检出。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r'db\.(Query|Exec|Raw)\s*\(', regex_string):
            return True
        return None
