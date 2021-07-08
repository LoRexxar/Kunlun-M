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


class CVI_3003():
    """
    rule class
    """

    def __init__(self):

        self.svid = 3003
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "RCE"
        self.description = "eval参数可控可能会导致RCE漏洞或者XSS漏洞，这取决于执行的位置"
        self.level = 10

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"eval|setTimeout"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
