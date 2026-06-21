# -*- coding: utf-8 -*-

"""
    Graph engine rule for setAttribute HTML attribute injection
    ~~~~
    Covers: element.setAttribute(attrName, userInput)
"""

from utils.api import *


class CVI_3006_graph():
    """
    Graph engine rule: HTML attribute injection via setAttribute
    """

    def __init__(self):
        self.svid = 3006
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "HTML attr injection"
        self.description = "通过 setAttribute 设置事件处理器属性（如 onclick）或特殊属性（如 src/href）时，如果属性值受用户控制，可能导致 XSS 或其他注入漏洞。建议对用户输入进行充分转义后再使用。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"setAttribute"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["setAttribute"]

    def main(self, regex_string):
        """
        二次筛选：排除硬编码属性值
        """
        if not isinstance(regex_string, str):
            return None
        import re
        # setAttribute("class", "fixed-value") — 纯硬编码，安全
        match = re.search(r'setAttribute\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']*["\']\s*\)', regex_string)
        if match:
            return False
        return None
