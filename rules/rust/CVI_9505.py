# -*- coding: utf-8 -*-

"""
    Rust 命令注入(variant)规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9505(SingleRuleMixin):
    """
    Rust 命令注入(variant)规则
    匹配某些 crate 中的 exec、shell_exec 等命令执行函数
    （如 command_group、shell-words 等第三方库中的危险函数）。
    normalizer 中 sink callee name 为方法名（如 exec, shell_exec 等）。
    """

    def __init__(self):
        self.svid = 9505
        self.language = "rust"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（exec、shell_exec等第三方crate中的命令执行函数），可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，或避免使用此类危险函数。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        # 匹配 exec / shell_exec 等变体命令执行函数
        self.match = (
            r"\bshell_exec\s*\("
            r"|\bshell_words\s*::\s*split\s*\("
            r"|\bcommand_group\s*::\s*(?:exec|spawn|status)\s*\("
            r"|\bbat\s*::\s*(?:exec|command)\s*\("
            r"|\brustyline\s*::\s*exec\s*\("
            r"|\bstd::process::Command.*\.spawn\s*\("
        )

        self.vul_function = [
            "shell_exec",
            "shell_words::split",
            "command_group::exec", "command_group::spawn", "command_group::status",
            "bat::exec", "bat::command",
            "rustyline::exec",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的命令执行变体调用，
        排除硬编码命令参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:shell_exec|shell_words::split|command_group::(?:exec|spawn|status)|bat::(?:exec|command)|rustyline::exec|\.spawn)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（硬编码命令）
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含危险的命令执行变体调用
        dangerous_patterns = [
            r"shell_exec\s*\(",
            r"shell_words::split\s*\(",
            r"command_group::(?:exec|spawn|status)\s*\(",
            r"bat::(?:exec|command)\s*\(",
            r"rustyline::exec\s*\(",
            r"\.spawn\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
