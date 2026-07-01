# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule (String Concatenation in Response)
    ~~~~
    检测Controller方法直接将用户输入拼接到HTTP响应体中返回的反射型XSS。
    典型模式: return "<html>" + userInput + "</html>"
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6072(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6072
        self.language = "java"
        self.vulnerability = "Reflected XSS (String Concatenation)"
        self.description = "通过AST分析检测Controller方法直接将用户输入通过字符串拼接拼入HTTP响应体返回导致的反射型XSS漏洞。常见模式如 return \"<h1>\" + param + \"</h1>\"。建议使用模板引擎(Thymeleaf/FreeMarker)并启用自动HTML转义。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r'return\s+.*["\x27]<.*>["\x27]\s*\+'

        # for regex
        self.unmatch = []

        self.vul_function = []

    def main(self, regex_string):
        """二次筛选：确认是直接拼接HTML返回的模式"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 确认包含HTML标签拼接和return关键字
        if re.search(r'return\s+', regex_string) and re.search(r'<[a-zA-Z]+', regex_string):
            # 排除使用转义函数的安全写法
            if re.search(r'escapeHtml|htmlEscape|Encode\.forHtml|URLEncoder', regex_string):
                return False
            return True
        return None
