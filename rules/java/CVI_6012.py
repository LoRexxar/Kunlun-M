# -*- coding: utf-8 -*-

"""
    Java SpEL/OGNL Injection Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6012(SingleRuleMixin):
    def __init__(self):
        self.svid = 6012
        self.language = "java"
        self.vulnerability = "SpEL/OGNL Injection"
        self.description = "用户输入进入SpEL/OGNL表达式解析可能导致代码注入"
        self.level = 4

        self.match_mode = "function-param-regex"
        self.match = "parseExpression|getValue"
        self.unmatch = [r"SimpleEvaluationContext"]
        self.vul_function = ["ExpressionParser.parseExpression", "StandardEvaluationContext.getValue", "SpelExpression.getValue"]

    def main(self, regex_string):
        """函数名足够精确，不做额外筛选"""
        return None
