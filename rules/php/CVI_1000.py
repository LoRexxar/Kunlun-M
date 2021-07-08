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


class CVI_1000():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1000
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS，用户输入被直接/不完全过滤输出到页面内容当中，可能会导致XSS隐患。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"print|print_r|exit|die|printf|vprintf|trigger_error|user_error|odbc_result_all|ovrimos_result_all|ifx_htmltbl_result"

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
