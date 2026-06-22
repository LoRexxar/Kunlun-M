# -*- coding: utf-8 -*-

"""
    C# 代码注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9208(SingleRuleMixin):
    """
    C# 代码注入规则
    匹配 CodeDomProvider.CompileAssemblyFromSource、Assembly.Load、Activator.CreateInstance 等动态代码执行函数
    """

    def __init__(self):
        self.svid = 9208
        self.language = "csharp"
        self.vulnerability = "代码注入"
        self.description = "使用了可能存在代码注入风险的动态代码执行函数（CodeDomProvider.CompileAssemblyFromSource、Assembly.Load、Assembly.LoadFrom、Activator.CreateInstance、Type.GetType等），且参数可能受用户控制。攻击者可利用此漏洞加载并执行任意代码，导致服务器被完全控制。建议限制动态代码加载，使用白名单机制控制可加载的程序集和类型，避免接受用户输入作为类型名或程序集路径。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"CodeDomProvider.*\.CompileAssemblyFromSource\s*\(|CSharpCodeProvider.*\.CompileAssemblyFromSource\s*\(|Assembly\.Load(?:From)?\s*\(|Activator\.CreateInstance\s*\(|Type\.GetType\s*\("

        self.vul_function = ["CompileAssemblyFromSource", "Load", "LoadFrom",
                             "CreateInstance", "GetType"]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的代码注入调用，
        排除硬编码字符串参数的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:CodeDomProvider|CSharpCodeProvider).*?CompileAssemblyFromSource\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        assembly_match = re.search(r'Assembly\.Load(?:From)?\s*\((.*)\)', regex_string, re.DOTALL)
        activator_match = re.search(r'Activator\.CreateInstance\s*\((.*)\)', regex_string, re.DOTALL)
        type_match = re.search(r'Type\.GetType\s*\((.*)\)', regex_string, re.DOTALL)

        args = None
        if match:
            args = match.group(1).strip()
        elif assembly_match:
            args = assembly_match.group(1).strip()
        elif activator_match:
            args = activator_match.group(1).strip()
        elif type_match:
            args = type_match.group(1).strip()

        if args is None:
            return None

        # 如果参数为空，排除
        if not args:
            return False

        # 提取关键参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            key_arg = arg_parts[0].strip()
        else:
            return None

        # 如果关键参数是纯硬编码字符串字面量，排除
        if re.match(r'^"[^"]*"$', key_arg) or re.match(r'^@"[^"]*"$', key_arg):
            return False

        # 确认包含危险的代码注入调用
        dangerous_patterns = [
            r"CodeDomProvider.*\.CompileAssemblyFromSource\s*\(",
            r"CSharpCodeProvider.*\.CompileAssemblyFromSource\s*\(",
            r"Assembly\.Load\s*\(",
            r"Assembly\.LoadFrom\s*\(",
            r"Activator\.CreateInstance\s*\(",
            r"Type\.GetType\s*\(",
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
