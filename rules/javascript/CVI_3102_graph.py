# -*- coding: utf-8 -*-

"""
    Graph engine rule for SSRF via http/https/net functions
    ~~~~
    Covers: http.get, http.request, https.get, https.request,
            net.connect, net.createConnection
"""

from utils.api import *


class CVI_3102_graph():
    """
    Graph engine rule: SSRF via http/https/net functions
    """

    def __init__(self):
        self.svid = 3102
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "SSRF"
        self.description = "使用了HTTP请求函数（http.get、http.request、https.get、https.request、axios、fetch等）且URL参数可能受用户控制，可能导致服务端请求伪造（SSRF）漏洞。建议对用户输入的URL进行严格的白名单校验。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"http.get|http.request|https.get|https.request|net.connect|net.createConnection"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["http.get", "http.request", "https.get", "https.request",
                             "net.connect", "net.createConnection"]

    def main(self, regex_string, sink_args=None):
        pass
