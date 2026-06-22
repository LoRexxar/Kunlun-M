# -*- coding: utf-8 -*-

"""
    csharp XSS规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9210(SingleRuleMixin):
    """
    csharp XSS规则
    """

    def __init__(self):
        self.svid = 9210
        self.language = "csharp"
        self.vulnerability = "XSS"
        self.description = "使用Response.Write或Html.Raw直接输出未转义的用户输入可能导致XSS漏洞。建议使用HtmlEncoder对输出进行编码。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Response\.Write\s*\(|@Html\.Raw\s*\(|Html\.Raw\s*\("

        self.vul_function = [
        "Response.Write", "Html.Raw"
        ]

    def main(self, regex_string):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        args = regex_string.strip()

        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        return True

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_single and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif in_single or in_double:
                current.append(ch)
            elif ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args
