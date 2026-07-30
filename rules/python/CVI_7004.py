# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7004(SingleRuleMixin):
    """
    Python SSRF
    覆盖: requests, urllib, http.client, aiohttp, httpx 等
    """
    def __init__(self):
        self.svid = 7004
        self.language = "python"
        self.vulnerability = "SSRF"
        self.description = "使用了可能存在SSRF风险的HTTP请求函数"
        self.level = 6
        self.match_mode = "function-param-regex"
        self.match = r"requests\.get|requests\.post|requests\.put|requests\.delete|requests\.head|requests\.patch|requests\.options|requests\.request|urllib\.request\.urlopen|urllib\.request\.urlretrieve|urlopen|http\.client\.HTTPConnection|http\.client\.HTTPSConnection|aiohttp\.ClientSession|httpx\.Client|httpx\.get|httpx\.post|httpx\.request|treq\.get|treq\.post"

    def main(self, regex_string, sink_args=None):
        pass
