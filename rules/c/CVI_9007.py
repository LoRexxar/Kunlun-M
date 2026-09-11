# -*- coding: utf-8 -*-

"""
    C/C++ 任意文件读取规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9007(SingleRuleMixin):
    """
    C/C++ 任意文件读取规则
    匹配 open、pread 等 POSIX 文件操作函数
    注意：与 CVI_9004 的 fopen 区分，这里关注 POSIX open() 和 pread()
    """

    def __init__(self):
        self.svid = 9007
        self.language = "c"
        self.vulnerability = "任意文件读取"
        self.description = "使用了 POSIX 文件操作函数（open、pread等），且文件路径参数可能受用户控制，可能导致任意文件读取漏洞。攻击者可利用此漏洞读取系统敏感文件（如 /etc/passwd、/etc/shadow）。建议对用户输入进行路径规范化校验，使用白名单限制可访问的文件。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bopen\s*\(|\bpread\s*\("

        self.vul_function = ["open", "pread"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除 fopen/fread 等（属其他 CVI 范畴），仅关注 POSIX open()/pread()。
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

        # 排除 fopen、fread、fgetc 等标准 C 库函数（前缀 f）
        if re.search(r'\bf(open|read|getc|gets|puts|seek|tell|flush|close|eof|error|write|lock|unlock|reopen)\s*\(', regex_string):
            return False

        # 提取函数调用参数部分
        match = re.search(r'(?:open|pread)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 提取第一个参数（文件路径）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            path_arg = arg_parts[0].strip()
        else:
            return None

        # 如果路径参数是纯硬编码字符串字面量，排除
        # 如 open("/tmp/file", O_RDONLY) 或 open("/dev/null", O_RDWR)
        if re.match(r'^\"[^\"]*\"$', path_arg):
            return False

        # 确认包含危险的文件读取调用
        dangerous_patterns = [
            r"open\s*\(",
            r"pread\s*\(",
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
