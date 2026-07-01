# -*- coding: utf-8 -*-

"""
    Java XStream Deserialization Rule
    ~~~~
    检测 XStream.fromXML() 反序列化用户可控输入
    CVE-2019-10173 等相关漏洞
"""

import re

from utils.api import *

class CVI_6044(SingleRuleMixin):
    def __init__(self):
        self.svid = 6044
        self.language = "java"
        self.vulnerability = "XStream Deserialization"
        self.description = "XStream.fromXML()反序列化用户可控XML可能导致远程代码执行。建议配置XStream安全框架：XStream.addPermission()限制允许的类型。"
        self.level = 9

        self.match_mode = "java-function-param-regex"
        self.match = r"fromXML"
        self.unmatch = [
            r"XStream\.setupDefaultSecurity",
            r"addPermission",
            r"allowTypes",
        ]
        self.vul_function = ["XStream.fromXML"]

    def main(self, regex_string):
        """二次筛选：只保留 XStream 上下文"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        if not re.search(r'XStream|xStream|xstream', code):
            return False
        return None
