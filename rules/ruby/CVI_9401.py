# -*- coding: utf-8 -*-

"""
    Ruby 命令注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9401(SingleRuleMixin):
    """
    Ruby 命令注入规则
    匹配 system、exec、IO.popen、Open3.capture2/capture3/popen3、spawn 等命令执行函数
    """

    def __init__(self):
        self.svid = 9401
        self.language = "ruby"
        self.vulnerability = "命令注入"
        self.description = "使用了可能存在命令注入风险的函数（system、exec、IO.popen、Open3.capture2、Open3.capture3、spawn等），且参数可能受用户控制。攻击者可注入任意系统命令导致服务器被完全控制。建议使用参数数组形式（如 system('ls', user_input)）替代字符串拼接。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"system\s*\(|\bexec\s*\(|IO\.popen\s*\(|Open3\.(capture2|capture3|popen3)\s*\(|spawn\s*\("

        self.vul_function = ["system", "exec", "popen", "spawn", "capture2", "capture3"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        如果所有参数都是硬编码字符串（如 system("ls")），返回 False（安全）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:system|exec|popen|capture2|capture3|spawn)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量（单引号或双引号包裹），排除
        # 同时考虑多参数的情况，如果所有参数都是字面量则排除
        arg_parts = self._split_args(args)

        # 检查是否所有参数都是硬编码字符串字面量
        all_literal = True
        for arg in arg_parts:
            arg = arg.strip()
            if not arg:
                continue
            if not re.match(r'^["\'][^"\']*["\']$', arg):
                all_literal = False
                break

        if all_literal:
            return False

        # 确认包含危险的命令执行调用
        dangerous_patterns = [
            r"system\s*\(",
            r"\bexec\s*\(",
            r"IO\.popen\s*\(",
            r"Open3\.(?:capture2|capture3|popen3)\s*\(",
            r"spawn\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_single and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif in_single or in_double:
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
