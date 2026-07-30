# -*- coding: utf-8 -*-

"""
    Node.js 代码注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3103(SingleRuleMixin):
    """
    Node.js 代码注入规则
    匹配 eval、vm.runInContext、vm.runInNewContext、new Function、require(动态) 等代码执行
    """

    def __init__(self):
        self.svid = 3103
        self.language = "javascript"
        self.vulnerability = "代码注入"
        self.description = "使用了动态代码执行函数（eval、vm.runInContext、vm.runInNewContext、new Function等），可能导致代码注入漏洞。建议避免将用户输入传递给动态代码执行函数，使用安全的替代方案。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\beval\s*\(|vm\.runInContext\s*\(|vm\.runInNewContext\s*\(|vm\.runInThisContext\s*\(|vm\.compileFunction\s*\(|new\s+Function\s*\("

        self.vul_function = [
            "eval", "vm.runInContext", "vm.runInNewContext",
            "vm.runInThisContext", "vm.compileFunction", "Function",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码字符串
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # eval("hardcoded string") — 排除
        match = re.search(r'\beval\s*\((.*)\)', regex_string)
        if match:
            args = match.group(1).strip()
            if re.match(r'^["\'][^"\']*["\']$', args):
                return False
            return True

        # vm 模块函数
        vm_match = re.search(
            r'(?:vm\.runInContext|vm\.runInNewContext|vm\.runInThisContext|vm\.compileFunction)\s*\((.*)\)',
            regex_string
        )
        if vm_match:
            args = vm_match.group(1).strip()
            if re.match(r'^["\'][^"\']*["\'](?:\s*,.*)?$', args):
                return False
            return True

        # new Function(...)
        func_match = re.search(r'new\s+Function\s*\((.*)\)', regex_string)
        if func_match:
            args = func_match.group(1).strip()
            if re.match(r'^["\'][^"\']*["\'](?:\s*,\s*["\'][^"\']*["\'])*$', args):
                return False
            return True

        return None
