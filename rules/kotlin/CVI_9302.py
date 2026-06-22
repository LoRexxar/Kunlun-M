# -*- coding: utf-8 -*-

"""
    Kotlin 命令注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9302(SingleRuleMixin):
    """
    Kotlin 命令注入规则
    匹配 Runtime.getRuntime().exec, ProcessBuilder 等
    """

    def __init__(self):
        self.svid = 9302
        self.language = "kotlin"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（Runtime.getRuntime().exec、ProcessBuilder等），当命令参数来自用户输入时，可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，或使用白名单机制限制可执行的命令。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|ProcessBuilder\s*\(|\.exec\s*\(|\.start\s*\("

        self.vul_function = [
            "Runtime.getRuntime().exec", "ProcessBuilder", "exec", "start",
        ]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的命令执行调用，
        排除硬编码字符串参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # ProcessBuilder 参数全部为硬编码字符串字面量
        if re.match(r'^"[^"]*"(?:\s*,\s*"[^"]*")*$', args):
            return False

        # Runtime.exec 参数全部为硬编码字符串字面量
        match_exec = re.search(r'exec\s*\((.*)\)', regex_string)
        if match_exec:
            exec_args = match_exec.group(1).strip()
            if re.match(r'^"[^"]*"$', exec_args):
                return False

        # 确认包含危险的命令执行调用
        dangerous_patterns = [
            r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
            r"ProcessBuilder\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                # 字符串拼接或模板变量
                if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
                    return True
                # 变量作为参数传入
                if re.search(r'(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder)\s*\(\s*\w+', regex_string):
                    return True

        return None
