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


class CVI_3001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 3001
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "JQuery 原型链污染"
        self.description = "jQuery.extend 在3.4.0以下，"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['\\.extend\\(\\s*true\\s*,']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = ['\\bjQuery\\.extend\\s*=\\s*jQuery\\.fn\\.extend\\b']

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
