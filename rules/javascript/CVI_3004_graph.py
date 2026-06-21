# -*- coding: utf-8 -*-

"""
    Graph engine rule for URL redirect
    ~~~~
    Covers: document.location.replace(userInput), window.location.replace(userInput)
"""

from utils.api import *


class CVI_3004_graph():
    """
    Graph engine rule: URL redirect via location.replace
    """

    def __init__(self):
        self.svid = 3004
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "URL Redirect"
        self.description = "URL Redirect，url重定向可能导致很多潜在的安全问题"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"document.location.replace|window.location.replace"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["document.location.replace", "window.location.replace"]

    def main(self, regex_string):
        pass
