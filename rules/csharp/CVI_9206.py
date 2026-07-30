# -*- coding: utf-8 -*-

"""
    C# XXE（XML外部实体注入）规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9206(SingleRuleMixin):
    """
    C# XXE（XML外部实体注入）规则
    匹配 XmlReader.Create、XmlDocument.LoadXml 等XML解析函数
    """

    def __init__(self):
        self.svid = 9206
        self.language = "csharp"
        self.vulnerability = "XXE"
        self.description = "使用了可能存在XXE（XML外部实体注入）风险的XML解析函数（XmlReader.Create、XmlDocument.LoadXml等），且XML输入可能受用户控制。攻击者可利用此漏洞读取服务器文件、探测内网端口或实施拒绝服务攻击。建议禁用外部实体解析（设置 XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit），或使用安全的解析器配置。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"XmlReader\.Create\s*\(|XmlDocument\.LoadXml\s*\(|XmlDocument\.Load\s*\(|XDocument\.Load\s*\(|XDocument\.Parse\s*\("

        self.vul_function = ["Create", "LoadXml", "Load", "Parse"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的XXE调用，
        排除硬编码XML字符串参数（如 XmlDocument.LoadXml("<root/>")）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:XmlReader\.Create|XmlDocument\.LoadXml|XmlDocument\.Load|XDocument\.Load|XDocument\.Parse)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 提取输入参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            input_arg = arg_parts[0].strip()
        else:
            return None

        # 如果输入参数是纯硬编码字符串字面量，排除
        if re.match(r'^"[^"]*"$', input_arg) or re.match(r'^@"[^"]*"$', input_arg):
            return False

        # 确认包含危险的XML解析调用
        dangerous_patterns = [
            r"XmlReader\.Create\s*\(",
            r"XmlDocument\.LoadXml\s*\(",
            r"XmlDocument\.Load\s*\(",
            r"XDocument\.Load\s*\(",
            r"XDocument\.Parse\s*\(",
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
