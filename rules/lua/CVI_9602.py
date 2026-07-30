# -*- coding: utf-8 -*-

"""
    Lua 代码注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9602(SingleRuleMixin):
    """
    Lua 代码注入规则
    匹配 loadstring / load / dofile / dostring 等
    注意: Lua 中 sink callee name 在 normalizer 中是方法名，如 loadstring, load, dofile, dostring
    """

    def __init__(self):
        self.svid = 9602
        self.language = "lua"
        self.vulnerability = "代码注入"
        self.description = "使用了可能执行动态代码的函数（loadstring、load、dofile、dostring等），可能导致代码注入漏洞。攻击者可能通过控制传入的代码字符串执行任意Lua代码。建议避免将用户输入传递给动态代码执行函数，或对输入进行严格的白名单校验。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\bloadstring\s*\(|\bload\s*\(|\bdofile\s*\(|\bdostring\s*\("

        self.vul_function = ["loadstring", "load", "dofile", "dostring"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的代码注入调用，
        排除硬编码字符串参数。
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

        # 提取函数调用参数部分
        match = re.search(r'(?:loadstring|load|dofile|dostring)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码路径/代码）
        # dofile("config.lua") -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
