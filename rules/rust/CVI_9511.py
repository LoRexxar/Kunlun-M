# -*- coding: utf-8 -*-

"""
    rust 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9511(SingleRuleMixin):
    """
    rust 路径遍历规则
    """

    def __init__(self):
        self.svid = 9511
        self.language = "rust"
        self.vulnerability = "路径遍历"
        self.description = "使用PathBuf::push或Path::new拼接用户输入可能导致路径遍历漏洞。攻击者可使用../序列访问任意文件。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"PathBuf::new\s*\(|Path::new\s*\(|PathBuf::push\s*\("

        self.vul_function = [
        "PathBuf::new", "Path::new", "PathBuf::push"
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
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

        args = regex_string.strip()

        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        return True

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
