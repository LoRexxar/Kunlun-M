# -*- coding: utf-8 -*-

"""
    Java CRLF Injection Rule
    ~~~~
    检测用户输入被注入到HTTP响应头中导致的CRLF注入漏洞。
    典型模式: response.setHeader("Custom-Header", userInput)
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6075(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6075
        self.language = "java"
        self.vulnerability = "CRLF Injection"
        self.description = "通过AST分析检测用户可控输入被直接设置到HTTP响应头(setHeader/addHeader/setCookie)中导致的CRLF注入漏洞。攻击者可注入\\r\\n分割HTTP响应头和body，实现HTTP响应拆分攻击。建议对输入中的CR(\\r)和LF(\\n)字符进行过滤。"
        self.level = 5

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r'\.setHeader\s*\(|\.addHeader\s*\(|\.addCookie\s*\('

        # for regex
        self.unmatch = []

        self.vul_function = [
            "setHeader",
            "addHeader",
            "addCookie",
            "set",
        ]

    def main(self, regex_string):
        """二次筛选：确认不是已知安全的header设置"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除固定值或白名单校验的header设置
        if re.search(r'Content-Type|Content-Length|Content-Disposition|X-Frame-Options|X-Content-Type|X-XSS', regex_string):
            # 这些header如果值固定则安全，但有变量拼接则危险
            # 简单判断：如果包含+号拼接则可能是CRLF
            if not re.search(r'\+\s*\w+', regex_string):
                return False
        return None
