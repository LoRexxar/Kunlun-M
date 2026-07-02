# -*- coding: utf-8 -*-

"""
    Java ProcessBuilder Command Injection (function-param-controllable)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_6038(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6038
        self.language = "java"
        self.vulnerability = "ProcessBuilder Command Injection (function-param-controllable)"
        self.description = "通过AST分析检测ProcessBuilder构造参数是否来自用户可控输入，命令注入可导致远程代码执行。"
        self.level = 9

        # 部分配置
        # ProcessBuilder 通过 ClassCreator 匹配，match 为精确正则避免匹配注释
        self.match_mode = "function-param-regex"
        self.match = r"new\s+ProcessBuilder\s*\("

        # for solidity
        self.black_list = []

        # for regex
        self.unmatch = []

        # AST 分析搜索 ProcessBuilder ClassCreator
        self.vul_function = ["ProcessBuilder"]

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除 Playground scenario 字符串
        if re.search(r'scenario', regex_string, re.I):
            return False
        return None
