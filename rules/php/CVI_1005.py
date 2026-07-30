# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_1005(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1005
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SQLI"
        self.description = "SQL injection, 用户输入直接被拼接进Sql语句当中，有可能造成SQL注入漏洞。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(mysql_query|mysql_db_query)"

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
