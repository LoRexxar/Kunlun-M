# -*- coding: utf-8 -*-

"""
    C/C++ 环境变量注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9006(SingleRuleMixin):
    """
    C/C++ 环境变量注入规则
    匹配 setenv、putenv、unsetenv 等环境变量操作函数
    """

    def __init__(self):
        self.svid = 9006
        self.language = "c"
        self.vulnerability = "环境变量注入"
        self.description = "使用了环境变量操作函数（setenv、putenv、unsetenv等），且参数可能受用户控制，可能导致环境变量注入。攻击者可通过注入恶意环境变量影响程序行为或利用 LD_PRELOAD 等机制执行代码。建议对用户输入进行严格校验，避免直接传递给环境变量操作函数。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bsetenv\s*\(|\bputenv\s*\(|\bunsetenv\s*\("

        self.vul_function = ["setenv", "putenv", "unsetenv"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的环境变量操作调用，
        排除硬编码字符串参数（如 setenv("PATH", "/usr/bin", 1)）。
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
        match = re.search(r'(?:setenv|putenv|unsetenv)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 提取第一个参数（变量名或键值对）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            first_arg = arg_parts[0].strip()
        else:
            return None

        # 如果第一个参数是纯硬编码字符串字面量，排除
        # setenv("PATH", "/usr/bin", 1) 或 unsetenv("TERM")
        if re.match(r'^\"[^\"]*\"$', first_arg):
            return False

        # 确认包含危险的环境变量操作调用
        dangerous_patterns = [
            r"setenv\s*\(",
            r"putenv\s*\(",
            r"unsetenv\s*\(",
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
