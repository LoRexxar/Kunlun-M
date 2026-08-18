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

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除硬编码字符串参数（非用户可控的重定向目标）
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            return None
        # 排除纯字符串字面量参数
        import re
        if re.match(r'^["\'][^"\']*["\']$', regex_string.strip()):
            return False
        return None
