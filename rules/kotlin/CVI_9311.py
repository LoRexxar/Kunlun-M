# -*- coding: utf-8 -*-

"""
    kotlin LDAP注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9311(SingleRuleMixin):
    """
    kotlin LDAP注入规则
    """

    def __init__(self):
        self.svid = 9311
        self.language = "kotlin"
        self.vulnerability = "LDAP注入"
        self.description = "将用户输入拼接到LDAP搜索过滤器中可能导致LDAP注入。建议对过滤条件进行参数化处理。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.search\s*\(|\.lookup\s*\(|Context\.search\s*\("

        self.vul_function = [
            "search", "lookup",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查是否为 LDAP 搜索/查找调用，且参数包含可控输入。
        排除硬编码的搜索过滤器。
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
        match = re.search(
            r'(?:search|lookup)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        if not args:
            return False

        # 纯字符串字面量（硬编码 LDAP filter）
        if re.match(r'^"[^"]*"$', args):
            return False

        # 包含字符串模板变量 ($var) 或字符串拼接
        if re.search(r'\$\w+', args) or re.search(r'"\s*\+\s*\w+', args):
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
