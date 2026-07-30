# -*- coding: utf-8 -*-

"""
    Graph engine rule for code injection via dynamic execution
    ~~~~
    Covers: eval, vm.runInContext, vm.runInNewContext, vm.runInThisContext,
            vm.compileFunction, new Function
"""

from utils.api import *


class CVI_3103_graph():
    """
    Graph engine rule: code injection via eval / vm / new Function
    """

    def __init__(self):
        self.svid = 3103
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "代码注入"
        self.description = "使用了动态代码执行函数（eval、vm.runInContext、vm.runInNewContext、new Function等），可能导致代码注入漏洞。建议避免将用户输入传递给动态代码执行函数，使用安全的替代方案。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"eval|vm.runInContext|vm.runInNewContext|vm.runInThisContext|vm.compileFunction|Function"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["eval", "vm.runInContext", "vm.runInNewContext",
                             "vm.runInThisContext", "vm.compileFunction", "Function"]

    def main(self, regex_string, sink_args=None):
        pass
