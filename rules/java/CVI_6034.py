# -*- coding: utf-8 -*-

"""
    Java SSRF (function-param-controllable)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_6034(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6034
        self.language = "java"
        self.vulnerability = "SSRF (function-param-controllable)"
        self.description = "通过AST分析检测openConnection参数是否来自用户可控输入，包括HttpURLConnection、RestTemplate、WebClient等HTTP请求。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "openConnection"

        # for solidity
        self.black_list = []

        # for regex
        self.unmatch = []
        self.vul_function = ["URL.openConnection"]

    def main(self, regex_string):
        pass
