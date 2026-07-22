# -*- coding: utf-8 -*-

"""
    Ruby XSS规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9407(SingleRuleMixin):
    """
    Ruby XSS规则
    匹配 raw、html_safe、content_tag 等可能绕过自动转义的函数/方法
    """

    def __init__(self):
        self.svid = 9407
        self.language = "ruby"
        self.vulnerability = "XSS"
        self.description = "使用了可能存在XSS（跨站脚本攻击）风险的方法（raw、html_safe、content_tag等），会绕过Rails的自动HTML转义机制。如果数据来自用户输入且未经过滤，攻击者可注入恶意JavaScript代码。建议避免使用html_safe和raw，对用户输入进行sanitize处理。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.raw\s*\(|\.html_safe|content_tag\s*\("

        self.vul_function = ["html_safe", "content_tag"]

    def main(self, regex_string):
        """
        二次筛选：排除硬编码字符串的情况。
        如果参数是纯硬编码字符串字面量，返回 False（安全）。
        注意：html_safe 不带参数（后缀调用），需要单独处理。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 处理 html_safe（无参数后缀调用）
        if re.search(r'\.html_safe', regex_string):
            # 检查 html_safe 前面是否是硬编码字符串
            html_safe_match = re.search(r'(["\'][^"\']*["\'])\s*\.html_safe', regex_string)
            if html_safe_match:
                return False
            return True

        # 处理 raw() 调用
        raw_match = re.search(r'\.raw\s*\((.*)\)', regex_string, re.DOTALL)
        if raw_match:
            args = raw_match.group(1).strip()
            if not args:
                return False
            if re.match(r'^["\'][^"\']*["\']$', args):
                return False
            return True

        # 处理 content_tag() 调用
        tag_match = re.search(r'content_tag\s*\((.*)\)', regex_string, re.DOTALL)
        if tag_match:
            args = tag_match.group(1).strip()
            if not args:
                return False
            # 提取参数，如果内容参数是硬编码字符串则排除
            arg_parts = self._split_args(args)
            # content_tag(name, content = nil, ...)
            if len(arg_parts) >= 2:
                content_arg = arg_parts[1].strip()
                if re.match(r'^["\'][^"\']*["\']$', content_arg):
                    return False
            return True

        return None

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
