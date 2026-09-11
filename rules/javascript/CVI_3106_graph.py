# -*- coding: utf-8 -*-

"""
    Graph engine rule for open redirect
    ~~~~
    Covers: res.redirect, ctx.redirect, response.redirect, redirect
"""

from utils.api import *


class CVI_3106_graph():
    """
    Graph engine rule: open redirect via redirect functions
    """

    def __init__(self):
        self.svid = 3106
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "开放重定向"
        self.description = "使用了重定向函数（res.redirect、ctx.redirect等）且目标URL可能受用户控制，可能导致开放重定向漏洞。建议对重定向目标进行白名单校验。"
        self.level = 5

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"res.redirect|ctx.redirect|response.redirect|redirect"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["res.redirect", "ctx.redirect", "response.redirect", "redirect"]

    def main(self, regex_string, sink_args=None):
        pass
