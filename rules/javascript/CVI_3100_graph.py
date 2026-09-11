# -*- coding: utf-8 -*-

"""
    Graph engine rule for command injection via child_process
    ~~~~
    Covers: exec, execSync, execFile, execFileSync, spawn, spawnSync, fork
"""

from utils.api import *


class CVI_3100_graph():
    """
    Graph engine rule: command injection via child_process functions
    """

    def __init__(self):
        self.svid = 3100
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（child_process.exec、child_process.execSync、child_process.spawn等），可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，避免将用户输入直接传递给命令执行函数。"
        self.level = 8

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"exec|execSync|execFile|execFileSync|spawn|spawnSync|fork"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]

    def main(self, regex_string, sink_args=None):
        pass
