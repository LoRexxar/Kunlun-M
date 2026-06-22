# -*- coding: utf-8 -*-

"""
    C# XSS（跨站脚本攻击）规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9205(SingleRuleMixin):
    """
    C# XSS（跨站脚本攻击）规则
    匹配 Response.Write、HttpContext.Current.Response.Write 等输出函数
    注意：嵌套 member expression 的 callee 可能是 Write（如 HttpContext.Current.Response.Write 中 callee 为 Write）
    """

    def __init__(self):
        self.svid = 9205
        self.language = "csharp"
        self.vulnerability = "XSS"
        self.description = "使用了可能存在XSS（跨站脚本攻击）风险的输出函数（Response.Write、HttpContext.Current.Response.Write等），且输出内容可能受用户控制。攻击者可注入恶意JavaScript代码在受害者浏览器中执行。建议对输出内容进行HTML编码（HttpUtility.HtmlEncode 或 Encoder.HtmlEncode），避免直接输出用户输入。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:HttpContext\.Current\.)?Response\.Write\s*\(|Response\.Output\.Write\s*\("

        self.vul_function = ["Write"]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的XSS输出调用，
        排除硬编码字符串参数（如 Response.Write("<div>Hello</div>")）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:HttpContext\.Current\.)?Response\.(?:Output\.)?Write\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 提取输出参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            output_arg = arg_parts[0].strip()
        else:
            return None

        # 如果输出参数是纯硬编码字符串字面量，排除
        if re.match(r'^"[^"]*"$', output_arg) or re.match(r'^@"[^"]*"$', output_arg):
            return False

        # 确认包含危险的输出调用
        dangerous_patterns = [
            r"Response\.Write\s*\(",
            r"Response\.Output\.Write\s*\(",
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
