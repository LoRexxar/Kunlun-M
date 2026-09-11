# -*- coding: utf-8 -*-

"""
    Graph engine rule for eval / setTimeout RCE
    ~~~~
    Covers: eval(userInput), setTimeout(userInput)
"""

from utils.api import *


class CVI_3003_graph():
    """
    Graph engine rule: RCE via eval / setTimeout
    """

    def __init__(self):
        self.svid = 3003
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "RCE"
        self.description = "eval参数可控可能会导致RCE漏洞或者XSS漏洞，这取决于执行的位置"
        self.level = 10

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"eval|setTimeout"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["eval", "setTimeout"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除 setTimeout/setInterval 第一个参数是硬编码
        函数表达式（箭头函数、function 关键字）的情况——这不是 RCE。
        只当第一个参数是变量（可能用户可控的字符串）时才报。
        """
        if not regex_string:
            return None
        # setTimeout(()=>{...}, ms) 或 setTimeout(function(){...}, ms) — 安全
        if re.search(r'(?:setTimeout|setInterval)\s*\(\s*(?:\([^)]*\)\s*=>|function\s*\(|async\s+)', regex_string):
            return False
        return None
