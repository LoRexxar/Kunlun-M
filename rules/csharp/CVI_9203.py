# -*- coding: utf-8 -*-

"""
    C# 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9203(SingleRuleMixin):
    """
    C# 路径遍历规则
    匹配 File.ReadAllText、File.WriteAllText、File.Delete、File.Copy、FileInfo、Directory 等文件/目录操作
    """

    def __init__(self):
        self.svid = 9203
        self.language = "csharp"
        self.vulnerability = "路径遍历"
        self.description = "使用了可能存在路径遍历风险的文件操作函数（File.ReadAllText、File.WriteAllText、File.Delete、File.Copy、FileInfo、Directory.GetFiles等），且路径参数可能受用户控制。攻击者可利用 ../ 序列访问预期目录之外的文件。建议对用户输入进行路径规范化校验（Path.GetFullPath），限制在安全目录内。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"File\.(?:ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Delete|Copy|Move|Open|Create|AppendAllText)\s*\(|(?:new\s+)?FileInfo\s*\(|Directory\.(?:GetFiles|GetDirectories|GetParent|CreateDirectory|Delete|Move)\s*\("

        self.vul_function = ["ReadAllText", "ReadAllBytes", "WriteAllText", "WriteAllBytes",
                             "Delete", "Copy", "Move", "Open", "Create", "AppendAllText",
                             "FileInfo", "GetFiles", "GetDirectories", "CreateDirectory"]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的路径遍历调用，
        排除硬编码路径参数（如 File.ReadAllText("config.ini")）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:File\.|Directory\.)(?:ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|'
            r'Delete|Copy|Move|Open|Create|AppendAllText|GetFiles|GetDirectories|'
            r'GetParent|CreateDirectory)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        # FileInfo 构造函数
        fileinfo_match = re.search(r'(?:new\s+)?FileInfo\s*\(\s*(.*?)\s*\)', regex_string, re.DOTALL)

        args = None
        if match:
            args = match.group(1).strip()
        elif fileinfo_match:
            args = fileinfo_match.group(1).strip()

        if args is None:
            return None

        # 如果参数为空，排除
        if not args:
            return False

        # 提取路径参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            path_arg = arg_parts[0].strip()
        else:
            return None

        # 如果路径参数是纯硬编码字符串字面量，排除
        if re.match(r'^"[^"]*"$', path_arg) or re.match(r'^@"[^"]*"$', path_arg):
            return False

        # 确认包含危险的文件操作调用
        dangerous_patterns = [
            r"File\.ReadAllText\s*\(",
            r"File\.ReadAllBytes\s*\(",
            r"File\.WriteAllText\s*\(",
            r"File\.WriteAllBytes\s*\(",
            r"File\.Delete\s*\(",
            r"File\.Copy\s*\(",
            r"File\.Move\s*\(",
            r"File\.Open\s*\(",
            r"File\.Create\s*\(",
            r"File\.AppendAllText\s*\(",
            r"FileInfo\s*\(",
            r"Directory\.GetFiles\s*\(",
            r"Directory\.GetDirectories\s*\(",
            r"Directory\.CreateDirectory\s*\(",
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
