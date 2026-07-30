# -*- coding: utf-8 -*-

"""
    C/C++ 格式化字符串漏洞规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9002(SingleRuleMixin):
    """
    C/C++ 格式化字符串漏洞规则
    匹配 printf、fprintf、sprintf、vprintf、vfprintf、vsnprintf 等
    注意：第一个参数为用户可控变量时才是漏洞，有正确格式串的调用应排除。
    """

    def __init__(self):
        self.svid = 9002
        self.language = "c"
        self.vulnerability = "格式化字符串漏洞"
        self.description = "使用了格式化字符串函数（printf、fprintf、sprintf等），且格式串参数可能受用户控制，可能导致格式化字符串漏洞。攻击者可利用 %n、%x 等格式符读取或写入内存。建议确保格式串为硬编码字符串常量。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bprintf\s*\(|\bfprintf\s*\(|\bsprintf\s*\(|\bvprintf\s*\(|\bvfprintf\s*\(|\bvsnprintf\s*\("

        self.vul_function = ["printf", "fprintf", "sprintf", "vprintf", "vfprintf", "vsnprintf"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的格式化字符串调用。
        排除第一个参数为硬编码格式串的情况（printf("hello %s", user_input)）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:printf|fprintf|sprintf|vprintf|vfprintf|vsnprintf)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # fprintf 的第一个参数是文件指针(FILE*)，第二个才是格式串
        # 其余 printf 系列的第一个参数就是格式串
        func_match = re.search(r'(fprintf|vfprintf)\s*\(', regex_string)
        if func_match:
            # fprintf/vfprintf: 提取第二个参数作为格式串
            arg_parts = self._split_args(args)
            if len(arg_parts) >= 2:
                fmt_arg = arg_parts[1].strip()
            else:
                return None
        else:
            # printf/sprintf/vprintf/vsnprintf: 第一个参数是格式串
            arg_parts = self._split_args(args)
            if len(arg_parts) >= 1:
                fmt_arg = arg_parts[0].strip()
            else:
                return None

        # 如果格式串参数是硬编码字符串字面量（以引号开头），排除
        if re.match(r'^\"', fmt_arg):
            return False

        # 确认包含危险的格式化字符串调用
        dangerous_patterns = [
            r"printf\s*\(",
            r"fprintf\s*\(",
            r"sprintf\s*\(",
            r"vprintf\s*\(",
            r"vfprintf\s*\(",
            r"vsnprintf\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_string = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_string:
                in_string = True
                current.append(ch)
            elif ch == '"' and in_string:
                in_string = False
                current.append(ch)
            elif in_string:
                current.append(ch)
            elif ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args
