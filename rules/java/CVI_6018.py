# -*- coding: utf-8 -*-

"""
    Java Insecure Reflection Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6018(SingleRuleMixin):
    def __init__(self):
        self.svid = 6018
        self.language = "java"
        self.vulnerability = "Insecure Reflection"
        self.description = "用户可控的反射调用可能导致绕过安全检查或代码执行"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = "forName|getDeclaredMethod|getMethod"
        self.vul_function = ["Class.forName", "Class.getDeclaredMethod", "Class.getMethod"]

    def main(self, regex_string):
        """函数名足够精确，不做额外筛选"""
        return None
