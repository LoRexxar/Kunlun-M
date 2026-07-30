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

class CVI_10002(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 10002
        self.language = "php"
        self.vulnerability = "Reflected XSS"
        self.description = "echo参数可控会导致XSS漏洞"
        self.level = 4

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"echo|print"

        # for chrome ext
        self.keyword = "is_echo_statement"

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
