# -*- coding: utf-8 -*-

"""
    Java Log Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_6010(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 6010
        self.language = "java"
        self.vulnerability = "Log Injection"
        self.description = "用户输入直接拼接到日志中可能导致日志注入攻击"
        self.level = 3

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "info|debug|warn|error|fatal"

        self.vul_function = [

            "Logger.info",

            "Logger.debug",

            "Logger.warn",

            "Logger.error",

            "Logger.fatal",

            "Logger.trace",

        ]

    def main(self, regex_string):
        """log 方法交给 AST 分析判断上下文"""
        return None

