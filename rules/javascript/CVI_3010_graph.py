# -*- coding: utf-8 -*-

"""
    Graph engine rule for Handlebars SafeString XSS
    ~~~~
    Covers: new Handlebars.SafeString(userInput)
"""

from utils.api import *


class CVI_3010_graph():
    """
    Graph engine rule: Handlebars SafeString XSS
    """

    def __init__(self):
        self.svid = 3010
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "Handlebars XSS"
        self.description = "Handlebars 中 SafeString 可导致XSS"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"SafeString"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["SafeString"]

    def main(self, regex_string, sink_args=None):
        pass
