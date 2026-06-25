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

class CVI_3006(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 3006
        self.language = "javascript"
        self.vulnerability = "HTML attr injection"
        self.description = "HTML attr injection可能会导致XSS漏洞"
        self.level = 4

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(\.setAttribute\(\s*[^,]+,([\w_.]*)\s*\))"

        self.vul_function = r"setAttribute"

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
