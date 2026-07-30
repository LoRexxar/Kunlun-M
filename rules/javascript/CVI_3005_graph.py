# -*- coding: utf-8 -*-

"""
    Graph engine rule for innerHTML HTML injection
    ~~~~
    Covers: element.innerHTML = userInput
"""

from utils.api import *


class CVI_3005_graph():
    """
    Graph engine rule: HTML injection via innerHTML property assignment
    """

    def __init__(self):
        self.svid = 3005
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "HTML injection"
        self.description = "将用户可控数据赋值给 element.innerHTML 可能导致 XSS 漏洞。建议使用 textContent 或安全的 DOM API 替代。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"innerHTML"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["innerHTML"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除硬编码字符串赋值
        """
        if not isinstance(regex_string, str):
            return None
        # 排除纯字符串字面量赋值
        import re
        if re.match(r'^["\'][^"\']*["\']$', regex_string.strip()):
            return False
        return None
