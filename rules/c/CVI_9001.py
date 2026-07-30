# -*- coding: utf-8 -*-

"""
    C/C++ 命令注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9001(SingleRuleMixin):
    """
    C/C++ 命令注入规则
    匹配 system、popen、exec* 等
    """

    def __init__(self):
        self.svid = 9001
        self.language = "c"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（system、popen、exec*等），可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，或避免将用户输入直接传递给命令执行函数。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bsystem\s*\(|\bpopen\s*\(|\bexecl\s*\(|\bexeclp\s*\(|\bexecle\s*\(|\bexecv\s*\(|\bexecvp\s*\(|\bexecvpe\s*\(|\bfexecve\s*\(|\bposix_spawn|\bposix_spawnp"

        self.vul_function = ["system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execvpe", "fexecve", "posix_spawn", "posix_spawnp"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的命令执行调用，
        排除硬编码字符串参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:system|popen|execl|execlp|execle|execv|execvp|execvpe|fexecve|posix_spawn|posix_spawnp)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号包裹的硬编码命令）
        # system("ls -la") -> 硬编码，排除
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含危险的命令执行调用
        dangerous_patterns = [
            r"system\s*\(",
            r"popen\s*\(",
            r"execl\s*\(",
            r"execlp\s*\(",
            r"execle\s*\(",
            r"execv\s*\(",
            r"execvp\s*\(",
            r"execvpe\s*\(",
            r"fexecve\s*\(",
            r"posix_spawn",
            r"posix_spawnp",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
