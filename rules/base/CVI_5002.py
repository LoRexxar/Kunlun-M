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


class CVI_5002():
    """
    rule class
    """

    def __init__(self):
        self.svid = 5002
        self.language = "base"
        self.author = "LoRexxar"
        self.vulnerability = "硬编码IP"
        self.description = "IP不应硬编码在代码当中，而是应该通过配置文件或更安全的方式引入。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['((\\b|\'|"|\\/)[0-9]{1,3}\\.[0-9]{0,3}\\.[0-9]{0,3}\\.[0-9]{0,3}\\s*:[0-9]{2,5})']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = ['127.0.0.1', '172.1', '0.0.0.0']

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
