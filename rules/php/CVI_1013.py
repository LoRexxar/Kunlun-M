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


class CVI_1013():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1013
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "URL Redirector Abuse"
        self.description = "URL任意重定向漏洞可能会导致潜在的业务安全问题，配合其他漏洞可能会导致更严重的漏洞危害"
        self.level = 1

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"header"

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
