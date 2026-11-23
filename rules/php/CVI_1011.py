# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_1011(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1011
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "system这类函数参数可控可能会导致远程命令执行"
        self.level = 10

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(system|passthru|exec|pcntl_exec|shell_exec|popen|proc_open|expect_popen|mb_send_mail|w32api_register_function|w32api_invoke_function|ssh2_exec)|\bProcess\s*::\s*fromShellCommandline\s*\("

        self.vul_function = ["system", "passthru", "exec", "pcntl_exec", "shell_exec",
                             "popen", "proc_open", "expect_popen", "mb_send_mail",
                             "w32api_register_function", "w32api_invoke_function",
                             "ssh2_exec",
                             # Symfony Process 静态工厂：命令串经 /bin/sh -c 执行
                             "fromShellCommandline"]

        # CVE-2026-118755（Volmarg PMS tree 命令注入）：Symfony
        # Process::fromShellCommandline(trim($command)) 是库内封装的 shell-out
        # sink，等价 shell_exec。命令串由 buildCommand() 空格拼接用户可控目录
        # 名而来；库/框架边界内无框架 source 可溯，presence + main() 常量过滤
        # 即报告（同 fix35 CVI_9512 / fix 21858 CVI_9703 模式）。
        self.require_taint = False

        # static_call 短名（Process::fromShellCommandline）：Process 是 Symfony
        # 库类，语料内无 function 定义节点，qualified 匹配永远不中——按
        # scanner L698 method_sinks 约定（Path C）由规则显式声明裸方法名。
        self.method_sinks = ["fromShellCommandline"]

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
