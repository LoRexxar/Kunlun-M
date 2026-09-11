# -*- coding: utf-8 -*-

"""
    C/C++ 缓冲区溢出规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9003(SingleRuleMixin):
    """
    C/C++ 缓冲区溢出规则
    匹配 strcpy、strcat、gets、wcscpy、wcscat 等不安全函数
    """

    def __init__(self):
        self.svid = 9003
        self.language = "c"
        self.vulnerability = "缓冲区溢出"
        self.description = "使用了不安全的字符串操作函数（strcpy、strcat、gets、wcscpy、wcscat等），这些函数不检查目标缓冲区大小，可能导致缓冲区溢出。建议使用 strncpy、strncat、fgets 等带长度限制的安全替代函数。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bstrcpy\s*\(|\bstrcat\s*\(|\bgets\s*\(|\bwcscpy\s*\(|\bwcscat\s*\("

        self.vul_function = ["strcpy", "strcat", "gets", "wcscpy", "wcscat"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的不安全字符串函数调用，
        排除硬编码字符串参数（如 strcpy(buf, "hello")）。
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
        match = re.search(r'(?:strcpy|strcat|gets|wcscpy|wcscat)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # gets() 无参数需要判断，只要调用就是危险
        func_match = re.search(r'gets\s*\(', regex_string)
        if func_match:
            return True

        # strcpy/strcat: 检查源参数（第二个参数）是否为硬编码字符串
        # 如果所有参数都是硬编码字符串，则排除
        if re.match(r'^\"[^\"]*\"\s*,\s*\"[^\"]*\"$', args):
            return False

        # 确认包含危险的不安全函数调用
        dangerous_patterns = [
            r"strcpy\s*\(",
            r"strcat\s*\(",
            r"gets\s*\(",
            r"wcscpy\s*\(",
            r"wcscat\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
