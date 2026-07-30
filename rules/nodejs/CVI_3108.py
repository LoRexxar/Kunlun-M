# -*- coding: utf-8 -*-

"""
    Node.js ReDoS 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3108(SingleRuleMixin):
    """
    Node.js ReDoS 规则
    匹配 new RegExp(user_input) 等动态正则表达式构造
    """

    def __init__(self):
        self.svid = 3108
        self.language = "javascript"
        self.vulnerability = "ReDoS"
        self.description = "使用用户输入构造正则表达式（new RegExp(userInput)），可能导致正则表达式拒绝服务（ReDoS）攻击。建议避免将用户输入直接用作正则表达式模式，或对特殊字符进行转义。"
        self.level = 5

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"new\s+RegExp\s*\("

        self.vul_function = [
            "RegExp",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码正则
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
            regex_string = str(regex_string)

        match = re.search(r'new\s+RegExp\s*\((.*)\)', regex_string)
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量（硬编码正则模式）
            if re.match(r'^["\'][^"\']*["\'](?:\s*,\s*["\'][^"\']*["\'])?$', args):
                return False
            return True

        return None
