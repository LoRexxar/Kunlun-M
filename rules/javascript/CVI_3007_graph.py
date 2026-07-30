# -*- coding: utf-8 -*-

"""
    Graph engine rule for jQuery DOM insertion XSS
    ~~~~
    Covers: $(...).html(userInput), $(...).append(userInput), etc.
"""

from utils.api import *


class CVI_3007_graph():
    """
    Graph engine rule: jQuery XSS via DOM insertion methods
    """

    def __init__(self):
        self.svid = 3007
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "JQuery XSS"
        self.description = "JQuery XSS是署于JQuery独有的XSS漏洞函数"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"html|before|insertBefore|insertAfter|after|append|prepend|wrap|wrapAll|wrapInner|appendTo|prependTo"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["html", "before", "insertBefore", "insertAfter", "after", "append",
                             "prepend", "wrap", "wrapAll", "wrapInner", "appendTo", "prependTo"]

    def main(self, regex_string, sink_args=None):
        pass
