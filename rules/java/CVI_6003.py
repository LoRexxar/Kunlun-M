# -*- coding: utf-8 -*-

"""
    Java Command Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6003(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6003
        self.language = "java"
        self.vulnerability = "Command Injection"
        self.description = "通过AST分析检测Runtime.getRuntime().exec()构造参数是否来自用户可控输入，追踪数据流以发现命令注入漏洞。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "(?<!execute)exec\\s*\\("

        # for regex
        self.unmatch = []

        self.vul_function = ["exec", "start", "ProcessBuilder"]

    def main(self, regex_string):
        """二次筛选：确认 Runtime.exec 或 ProcessBuilder.start 调用"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除 Playground scenario 字符串
        if re.search(r'scenario', regex_string, re.I):
            return False
        # exec 需要确认是 Runtime.exec 上下文
        if re.search(r'exec\s*\(', regex_string):
            if not re.search(r'Thread|Executor|pool|execute', regex_string, re.I):
                return True
            return False
        # ProcessBuilder.start 上下文
        if re.search(r'ProcessBuilder|processBuilder', regex_string, re.I):
            return True
        return None
