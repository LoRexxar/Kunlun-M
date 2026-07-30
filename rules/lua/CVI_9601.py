# -*- coding: utf-8 -*-

"""
    Lua 命令执行规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9601(SingleRuleMixin):
    """
    Lua 命令执行规则
    匹配 os.execute / io.popen / os.system 等
    注意: Lua 中 sink callee name 为方法名，如 execute, popen, system
    """

    def __init__(self):
        self.svid = 9601
        self.language = "lua"
        self.vulnerability = "命令执行"
        self.description = "使用了可能执行系统命令的函数（os.execute、io.popen等），可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，或避免将用户输入直接传递给命令执行函数。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\bexecute\s*\(|\bpopen\s*\(|\bsystem\s*\("

        self.vul_function = ["os.execute", "io.popen", "os.system"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的命令执行调用，
        排除硬编码字符串参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:execute|popen|system)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码命令）
        # execute("ls -la") -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
