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


class CVI_3009():
    """
    rule class
    """

    def __init__(self):

        self.svid = 3009
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "JQuery eval?"
        self.description = "JQuery 中 globalEval同eval 可导致eval"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"globalEval"

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
