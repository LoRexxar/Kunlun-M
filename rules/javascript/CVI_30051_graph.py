# -*- coding: utf-8 -*-

"""
    Graph engine rule for outerHTML HTML injection
    ~~~~
    Covers: element.outerHTML = userInput
"""

from utils.api import *


class CVI_30051_graph():
    """
    Graph engine rule: HTML injection via outerHTML property assignment
    """

    def __init__(self):
        self.svid = 30051
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "HTML injection"
        self.description = "将用户可控数据赋值给 element.outerHTML 可能导致 XSS 漏洞。outerHTML 会替换整个元素及其子元素，风险比 innerHTML 更高。建议使用安全的 DOM API 替代。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"outerHTML"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["outerHTML"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除硬编码字符串赋值
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
        import re
        if re.match(r'^["\'][^"\']*["\']$', regex_string.strip()):
            return False
        return None
