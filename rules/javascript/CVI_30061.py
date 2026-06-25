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

class CVI_30061(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 30061
        self.language = "javascript"
        self.vulnerability = "JQuery HTML attr injection"
        self.description = "JQuery HTML attr injection可能会导致XSS漏洞"
        self.level = 4

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(\.attr\(\s*[^,]+,([\w_.]*)\s*\))"

        self.vul_function = r"attr"

    def main(self, regex_string):
        """
        regex string input
        just for sql statements
        :return:
        """
        sql_sen = regex_string[0][1]
        reg = r"[\w_.]+"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
