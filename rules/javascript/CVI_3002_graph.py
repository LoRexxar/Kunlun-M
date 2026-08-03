# -*- coding: utf-8 -*-

"""
    Graph engine rule for document.write XSS
    ~~~~
    Covers: document.write(userInput), document.writeln(userInput)
"""

from utils.api import *


class CVI_3002_graph():
    """
    Graph engine rule: XSS via document.write / document.writeln
    """

    def __init__(self):
        self.svid = 3002
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "XSS"
        self.description = "可控内容被直接写入页面内，会导致XSS漏洞"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"document.write|document.writeln"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["document.write", "document.writeln", "write", "writeln"]

    def main(self, regex_string, sink_args=None):
        pass
