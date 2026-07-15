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


class CVI_10003():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10003
        self.language = "php"
        self.author = "Kunlun-M"
        self.vulnerability = "test_eval_check"
        self.description = "test_eval_check"
        self.level = 1

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"eval\s*\("

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def main(self, regex_string):
        return None
