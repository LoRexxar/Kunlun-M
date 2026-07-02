# -*- coding: utf-8 -*-
from utils.api import *

class CVI_6031(SingleRuleMixin):
    def __init__(self):
        self.svid = 6031
        self.language = "java"
        self.vulnerability = "JDBC SQL Injection (function-param-controllable)"
        self.description = "通过AST分析检测executeQuery参数是否来自用户可控输入"
        self.level = 9
        self.match_mode = "function-param-regex"
        self.match = "executeQuery|executeUpdate"
        self.unmatch = []
        self.black_list = []
        self.vul_function = [
            "Statement.executeQuery",
            "Statement.executeUpdate",
            "PreparedStatement.executeQuery",
            "PreparedStatement.executeUpdate",
        ]

    def main(self, regex_string):
        pass
