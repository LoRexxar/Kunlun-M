# -*- coding: utf-8 -*-

"""
    C/C++ 任意文件写入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_9009(SingleRuleMixin):
    """
    C/C++ 任意文件写入规则
    匹配 open（含写入标志）、fopen（写入模式）、rename 等文件写入操作函数。
    """

    def __init__(self):
        self.svid = 9009
        self.language = "c"
        self.vulnerability = "任意文件写入"
        self.description = "使用了文件写入函数（open带O_WRONLY/O_CREAT/O_RDWR标志、fopen带写入模式、rename等），且文件路径参数可能受用户控制，可能导致任意文件写入漏洞。攻击者可利用此漏洞覆盖系统关键文件或写入恶意代码。建议对用户输入进行路径规范化校验，使用白名单限制可写入的目录。"
        self.level = 8

        self.match_mode = "function-param-regex"
        self.match = r"\bfopen\s*\(|\brename\s*\(|(?<!\w)open\s*\([^)]*(?:O_WRONLY|O_CREAT|O_RDWR)"

        self.vul_function = ["open", "fopen", "rename"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：
        - open(): 检测是否包含 O_WRONLY、O_CREAT、O_RDWR 等写入标志
        - fopen(): 检测是否包含 "w"/"a"/"r+" 等写入模式
        - rename(): 直接视为危险操作
        排除文件路径是硬编码字符串字面量的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除 fopen 以外的 f 前缀函数（fclose、fprintf 等）
        if re.search(r'\bf(close|read|getc|gets|puts|seek|tell|flush|eof|error|printf|lock|unlock|reopen)\s*\(', regex_string):
            return False

        # 检测 rename() 调用
        if re.search(r'\brename\s*\(', regex_string):
            match = re.search(r'rename\s*\((.*)\)', regex_string)
            if match:
                arg_parts = self._split_args(match.group(1).strip())
                if arg_parts:
                    path_arg = arg_parts[0].strip()
                    # 路径参数是硬编码字符串字面量，排除
                    if re.match(r'^\"[^\"]*\"$', path_arg):
                        return False
                    return True
            return None

        # 检测 fopen() 调用
        if re.search(r'\bfopen\s*\(', regex_string):
            match = re.search(r'fopen\s*\((.*)\)', regex_string)
            if match:
                arg_parts = self._split_args(match.group(1).strip())
                if len(arg_parts) >= 2:
                    path_arg = arg_parts[0].strip()
                    mode_arg = arg_parts[1].strip()
                    # 路径是硬编码字符串字面量，排除
                    if re.match(r'^\"[^\"]*\"$', path_arg):
                        return False
                    # 检查模式是否包含写入标志
                    if re.search(r'[wa+]', mode_arg):
                        return True
                return None

        # 检测 POSIX open() 调用 — 含写入标志
        if re.search(r'(?<!\w)open\s*\(', regex_string):
            # 排除带 f 前缀的误匹配（已在上面排除）
            if re.search(r'\bf\w*open\s*\(', regex_string):
                return None

            match = re.search(r'(?<!\w)open\s*\((.*)\)', regex_string)
            if match:
                arg_parts = self._split_args(match.group(1).strip())
                if not arg_parts:
                    return None

                path_arg = arg_parts[0].strip()
                # 路径是硬编码字符串字面量，排除
                if re.match(r'^\"[^\"]*\"$', path_arg):
                    return False

                # 检查是否包含写入标志
                for part in arg_parts[1:]:
                    if re.search(r'O_WRONLY|O_CREAT|O_RDWR', part):
                        return True
            return None

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
