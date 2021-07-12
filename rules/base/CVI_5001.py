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


class CVI_5001():
    """
    rule class
    """

    def __init__(self):
        self.svid = 5001
        self.language = "base"
        self.author = "LoRexxar"
        self.vulnerability = "硬编码密码"
        self.description = "密码不应硬编码在代码当中，而是应该通过配置文件或更安全的方式引入。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['((password)\\b[\'"]?\\s*[:=(,]?\\s*[\'"]?(\\w{3,})[\'"]?\\b)']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
