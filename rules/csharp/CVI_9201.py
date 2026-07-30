# -*- coding: utf-8 -*-

"""
    C# 命令注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9201(SingleRuleMixin):
    """
    C# 命令注入规则
    匹配 Process.Start、ShellExecute 等命令执行函数
    """

    def __init__(self):
        self.svid = 9201
        self.language = "csharp"
        self.vulnerability = "命令注入"
        self.description = "使用了可能存在命令注入风险的函数（Process.Start、ShellExecute等），且参数可能受用户控制。攻击者可注入任意系统命令导致服务器被完全控制。建议使用 ProcessStartInfo 并设置 UseShellExecute=false，配合参数化调用避免拼接用户输入。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Process\.Start\s*\(|ShellExecute\s*\("

        self.vul_function = ["Start", "ShellExecute"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        如果所有参数都是硬编码字符串（如 Process.Start("cmd.exe", "/c dir")），返回 False（安全）。
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
        match = re.search(r'(?:Process\.Start|ShellExecute)\s*\((.*)\)', regex_string, re.DOTALL)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 分割参数并检查是否全部为硬编码字面量
        arg_parts = self._split_args(args)

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
            r"Process\.Start\s*\(",
            r"ShellExecute\s*\(",
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
