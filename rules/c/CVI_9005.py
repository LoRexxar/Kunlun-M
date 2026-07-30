# -*- coding: utf-8 -*-

"""
    C/C++ 整数溢出（堆溢出）规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9005(SingleRuleMixin):
    """
    C/C++ 整数溢出（堆溢出）规则
    匹配 malloc、calloc、realloc、alloca 等内存分配函数
    注意：参数来自用户输入时才可能导致整数溢出
    """

    def __init__(self):
        self.svid = 9005
        self.language = "c"
        self.vulnerability = "整数溢出"
        self.description = "使用了内存分配函数（malloc、calloc、realloc、alloca等），且分配大小参数可能受用户控制，可能导致整数溢出从而分配过小的内存，引发堆溢出。建议对用户输入的大小参数进行校验，使用安全的整数运算。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(|\balloca\s*\("

        self.vul_function = ["malloc", "calloc", "realloc", "alloca"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的内存分配调用，
        排除纯数字参数（如 malloc(1024)）和硬编码大小的调用。
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:malloc|calloc|realloc|alloca)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯数字参数 -> 排除（如 malloc(1024)、malloc(0x1000)）
        if re.match(r'^(0x[0-9a-fA-F]+|\d+)(\s*\*\s*(0x[0-9a-fA-F]+|\d+))*$', args):
            return False

        # 纯数字 + sizeof 表达式 -> 排除（如 malloc(sizeof(int) * 10)）
        if re.match(r'^sizeof\s*\([^)]*\)(\s*\*\s*\d+)*$', args):
            return False

        # 确认包含危险的内存分配调用
        dangerous_patterns = [
            r"malloc\s*\(",
            r"calloc\s*\(",
            r"realloc\s*\(",
            r"alloca\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
