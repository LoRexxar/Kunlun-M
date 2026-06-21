# -*- coding: utf-8 -*-

"""
    Graph engine rule for jQuery.globalEval
    ~~~~
    Covers: $.globalEval(userInput)
"""

from utils.api import *


class CVI_3009_graph():
    """
    Graph engine rule: jQuery globalEval (equivalent to eval)
    """

    def __init__(self):
        self.svid = 3009
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "JQuery eval?"
        self.description = "JQuery 中 globalEval同eval 可导致eval，可能会导致命令执行或XSS漏洞"
        self.level = 10

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

        self.vul_function = ["globalEval"]

    def main(self, regex_string):
        pass
