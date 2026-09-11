# -*- coding: utf-8 -*-

"""
    C/C++ 路径穿越规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9004(SingleRuleMixin):
    """
    C/C++ 路径穿越规则
    匹配 fopen、remove、rename、access、unlink、openat 等文件操作函数
    注意：路径参数需要可控才算漏洞
    """

    def __init__(self):
        self.svid = 9004
        self.language = "c"
        self.vulnerability = "路径穿越"
        self.description = "使用了文件操作函数（fopen、remove、rename、access、unlink、openat等），且路径参数可能受用户控制，可能导致路径穿越漏洞。攻击者可利用 ../ 序列访问预期目录之外的文件。建议对用户输入进行路径规范化校验，限制在安全目录内。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bfopen\s*\(|\bremove\s*\(|\brename\s*\(|\baccess\s*\(|\bunlink\s*\(|\bopenat\s*\("

        self.vul_function = ["fopen", "remove", "rename", "access", "unlink", "openat"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的路径穿越调用，
        排除硬编码路径参数（如 fopen("/etc/passwd", "r")）。
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
        match = re.search(r'(?:fopen|remove|rename|access|unlink|openat)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 提取路径参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            path_arg = arg_parts[0].strip()
        else:
            return None

        # 如果路径参数是纯硬编码字符串字面量，排除
        if re.match(r'^\"[^\"]*\"$', path_arg):
            return False

        # 确认包含危险的文件操作调用
        dangerous_patterns = [
            r"fopen\s*\(",
            r"remove\s*\(",
            r"rename\s*\(",
            r"access\s*\(",
            r"unlink\s*\(",
            r"openat\s*\(",
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
