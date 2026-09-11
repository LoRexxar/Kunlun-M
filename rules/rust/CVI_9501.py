# -*- coding: utf-8 -*-

"""
    Rust 命令注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9501(SingleRuleMixin):
    """
    Rust 命令注入规则
    匹配 Command::new、std::process::Command 等命令创建调用。
    normalizer 中 sink callee name 为方法名 "new"（不含路径前缀），
    但函数体/上下文中会出现 Command::new / process::Command::new 等模式，
    因此 match regex 同时覆盖方法名调用和完整路径。
    """

    def __init__(self):
        self.svid = 9501
        self.language = "rust"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（Command::new、std::process::Command::new等），可能导致命令注入漏洞。建议对用户输入进行严格校验，或避免将用户输入直接传递给命令执行函数。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        # normalizer callee name 为方法名（如 "new"），需配合上下文匹配
        self.match = r"\bCommand\s*::\s*new\s*\(|\bprocess\s*::\s*Command\s*::\s*new\s*\("

        self.vul_function = ["Command::new", "process::Command::new"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的命令创建调用，
        排除硬编码命令名。
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

        # 提取 Command::new 参数部分
        match = re.search(r'(?:Command|process::Command)::new\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（硬编码命令名）
        # Command::new("ls") 或 Command::new("ls", "-la")
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含危险的命令创建调用
        dangerous_patterns = [
            r"Command::new\s*\(",
            r"process::Command::new\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
