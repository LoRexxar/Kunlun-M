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
        """过滤非用户直接控制的日志调用"""
        if not isinstance(regex_string, str):
            return None
        import re
        # SLF4J 参数化日志（log.debug("msg {}", arg)）是安全的
        if '{}' in regex_string:
            return False
        # 异常消息拼接（log.error("..." + e.getMessage())）不是用户直接输入
        if re.search(r'\+\s*\w+\.getMessage\(\)', regex_string):
            return False
        # 纯变量传入（log.debug(variable)）不含字符串拼接 → 非典型注入模式
        if re.match(r'\s*log\.\w+\(\w+\)\s*;', regex_string):
            return False
        return None

