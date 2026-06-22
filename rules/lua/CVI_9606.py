# -*- coding: utf-8 -*-

"""
    Lua 动态require规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9606(SingleRuleMixin):
    """
    Lua 动态require规则
    匹配 require 动态路径注入
    注意: Lua 中 sink callee name 在 normalizer 中是方法名，如 require
    """

    def __init__(self):
        self.svid = 9606
        self.language = "lua"
        self.vulnerability = "动态require"
        self.description = "使用了动态require加载模块，如果模块路径参数包含用户输入，可能导致任意代码加载执行。攻击者可能通过构造恶意模块路径加载恶意代码。建议对require的模块名进行白名单校验，避免使用用户输入作为require的参数。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\brequire\s*\("

        self.vul_function = ["require"]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的动态require调用，
        排除硬编码模块名。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'require\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码模块名）
        # require("lfs") -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）—— 动态路径
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用 —— 动态路径
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
