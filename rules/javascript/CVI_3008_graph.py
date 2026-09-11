# -*- coding: utf-8 -*-

"""
    Graph engine rule for Chrome extension XSS
    ~~~~
    Covers: chrome.tabs.update(...), chrome.tabs.executeScript(...)
"""

from utils.api import *


class CVI_3008_graph():
    """
    Graph engine rule: Chrome extension function XSS
    """

    def __init__(self):
        self.svid = 3008
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "Chrome ext function XSS"
        self.description = "Chrome ext function XSS，chrome插件独有的XSS漏洞"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"chrome.tabs.update|chrome.tabs.executeScript"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["chrome.tabs.update", "chrome.tabs.executeScript"]

    def main(self, regex_string, sink_args=None):
        pass
