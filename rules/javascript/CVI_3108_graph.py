# -*- coding: utf-8 -*-

"""
    Graph engine rule for ReDoS
    ~~~~
    Covers: RegExp constructor with user input
"""

from utils.api import *


class CVI_3108_graph():
    """
    Graph engine rule: ReDoS via RegExp constructor
    """

    def __init__(self):
        self.svid = 3108
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "ReDoS"
        self.description = "使用用户输入构造正则表达式（new RegExp(userInput)），可能导致正则表达式拒绝服务（ReDoS）攻击。建议避免将用户输入直接用作正则表达式模式，或对特殊字符进行转义。"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"RegExp"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["RegExp"]

    def main(self, regex_string, sink_args=None):
        pass
