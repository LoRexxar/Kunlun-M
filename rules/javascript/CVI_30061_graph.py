# -*- coding: utf-8 -*-

"""
    Graph engine rule for JQuery $.attr HTML attribute injection
    ~~~~
    Covers: $(el).attr(attrName, userInput)
"""

from utils.api import *


class CVI_30061_graph():
    """
    Graph engine rule: JQuery HTML attribute injection via $.attr()
    """

    def __init__(self):
        self.svid = 30061
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "JQuery HTML attr injection"
        self.description = "通过 JQuery 的 $.attr() 设置事件处理器属性或特殊属性时，如果属性值受用户控制，可能导致 XSS 漏洞。建议使用 $.prop() 或对用户输入进行充分转义。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"attr"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["attr"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除单参数 attr（getter，非 setter）和硬编码值
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
        # .attr("name") — 只有 1 个参数，是 getter，安全
        if re.search(r'\.attr\s*\(\s*["\'][^"\']*["\']\s*\)', regex_string):
            return False
        return None
