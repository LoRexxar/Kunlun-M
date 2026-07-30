# -*- coding: utf-8 -*-

"""
    C/C++ 命令注入增强规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_9010(SingleRuleMixin):
    """
    C/C++ 命令注入增强规则
    匹配 execl、execle、execlp、execv、execve、execvp、popen、system、posix_spawn 等
    命令执行函数，检测是否存在命令注入风险。
    """

    def __init__(self):
        self.svid = 9010
        self.language = "c"
        self.vulnerability = "命令注入"
        self.description = "使用了命令执行函数（system、popen、execl、execv、execve、execvp、execlp、execle、posix_spawn等），且命令参数可能受用户控制，可能导致命令注入漏洞。攻击者可利用此漏洞执行任意系统命令。建议避免直接拼接用户输入到命令字符串中，使用参数化方式传递命令参数。"
        self.level = 8

        self.match_mode = "function-param-regex"
        self.match = r"\bexecl\s*\(|\bexecle\s*\(|\bexeclp\s*\(|\bexecv\s*\(|\bexecve\s*\(|\bexecvp\s*\(|\bpopen\s*\(|\bsystem\s*\(|\bposix_spawn\s*\("

        self.vul_function = ["execl", "execle", "execlp", "execv", "execve", "execvp", "popen", "system", "posix_spawn"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除命令参数是硬编码字符串字面量的情况。
        system("echo hello")、popen("ls -la") 等硬编码命令应排除。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        func_match = re.search(r'(execl|execle|execlp|execv|execve|execvp|popen|system|posix_spawn)\s*\((.*)\)', regex_string)
        if not func_match:
            return None

        func_name = func_match.group(1)
        args = func_match.group(2).strip()
        arg_parts = self._split_args(args)

        if not arg_parts:
            return None

        # system() 和 popen() — 第一个参数是命令字符串
        if func_name in ("system", "popen"):
            cmd_arg = arg_parts[0].strip()
            # 命令参数是硬编码字符串字面量，排除
            if re.match(r'^\"[^\"]*\"$', cmd_arg):
                return False
            return True

        # posix_spawn() — 第2个参数是路径
        # int posix_spawn(pid_t *pid, const char *path, ...)
        if func_name == "posix_spawn":
            if len(arg_parts) >= 2:
                path_arg = arg_parts[1].strip()
                # 路径参数是硬编码字符串字面量，排除
                if re.match(r'^\"[^\"]*\"$', path_arg):
                    return False
                return True
            return None

        # exec* 系列函数 — 保守策略
        # execv/execve/execvp 的第二个参数是 argv 数组，无法从片段判断内容
        # 只要匹配到就检出
        if func_name in ("execl", "execle", "execlp", "execv", "execve", "execvp"):
            return True

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
