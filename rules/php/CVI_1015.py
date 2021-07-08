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


class CVI_1015():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1015
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "unserialize vulerablity"
        self.description = "unserialize反序列化漏洞配合pop chain可能会导致潜在的安全问题，即便没有pop chain存在，配合内置类也会导致SSRF漏洞等"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"is_a|unserialize"

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
