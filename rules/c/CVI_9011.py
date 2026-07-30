# -*- coding: utf-8 -*-

"""
    C/C++ 竞态条件(TOCTOU)规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_9011(SingleRuleMixin):
    """
    C/C++ 竞态条件(TOCTOU)规则
    匹配 access、stat、lstat、fstat 等文件状态检查函数。
    TOCTOU漏洞的本质是：先检查再使用（check-then-use）模式，
    攻击者可在检查和使用之间替换文件。
    """

    def __init__(self):
        self.svid = 9011
        self.language = "c"
        self.vulnerability = "竞态条件"
        self.description = "使用了文件状态检查函数（access、stat、lstat、fstat），存在TOCTOU（Time-of-Check-to-Time-of-Use）竞态条件风险。攻击者可在检查和使用操作之间替换文件符号链接，从而绕过安全检查。建议避免使用access()+open()模式，直接使用open()并根据返回值判断，或使用O_NOFOLLOW标志防止符号链接攻击。"
        self.level = 7

        self.match_mode = "function-param-regex"
        self.match = r"\baccess\s*\(|\bstat\s*\(|\blstat\s*\(|\bfstat\s*\("

        self.vul_function = ["access", "stat", "lstat", "fstat"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：
        - 如果 access/stat/lstat/fstat 的路径参数是硬编码字符串字面量，排除（风险极低）
        - 如果参数是变量，返回 True（存在TOCTOU风险）
        - fstat 的第一个参数是文件描述符(fd)，需特殊处理
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        func_match = re.search(r'(access|stat|lstat|fstat)\s*\((.*)\)', regex_string)
        if not func_match:
            return None

        func_name = func_match.group(1)
        args = func_match.group(2).strip()
        arg_parts = self._split_args(args)

        if not arg_parts:
            return None

        # fstat(fd, buf) — 第一个参数是文件描述符，非路径，标记为风险较低但仍需关注
        if func_name == "fstat":
            # fstat 本身不直接涉及路径，但如果与 open 配合使用仍可能有 TOCTOU 风险
            # 保守策略：fstat 调用返回 True
            return True

        # access/stat/lstat — 第一个参数是文件路径
        path_arg = arg_parts[0].strip()

        # 路径参数是硬编码字符串字面量，排除
        if re.match(r'^\"[^\"]*\"$', path_arg):
            return False

        # 参数是变量，存在 TOCTOU 风险
        return True

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
