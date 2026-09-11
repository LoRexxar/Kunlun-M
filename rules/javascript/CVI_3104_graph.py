# -*- coding: utf-8 -*-

"""
    Graph engine rule for SQL injection
    ~~~~
    Covers: .query, .raw, .whereRaw, .literal, sequelize.query, knex.raw
"""

from utils.api import *


class CVI_3104_graph():
    """
    Graph engine rule: SQL injection via raw query builders
    """

    def __init__(self):
        self.svid = 3104
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "SQL注入"
        self.description = "使用了数据库查询函数（connection.query、sequelize.query、knex.raw等）且SQL语句可能受用户控制，可能导致SQL注入漏洞。建议使用参数化查询（prepared statements）替代字符串拼接。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"query|raw|whereRaw|literal|sequelize.query|knex.raw"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["query", "raw", "whereRaw", "literal", "sequelize.query", "knex.raw"]

    def main(self, regex_string, sink_args=None):
        """
        过滤非 SQL query 的调用：
        - chrome.tabs.query 是浏览器扩展 API
        - document.querySelector / querySelectorAll 是 DOM API
        - 其他非 SQL 的 query 方法
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        import re

        # 浏览器扩展 API — 不是 SQL
        if re.search(r'chrome\.\w+\.query', regex_string):
            return False

        # DOM querySelector / querySelectorAll — 不是 SQL
        if re.search(r'querySelector(?:All)?\s*\(', regex_string):
            return False

        # mediaQueryList / matchMedia — CSS media query
        if re.search(r'(?:matchMedia|mediaQuery)', regex_string):
            return False

        return None
