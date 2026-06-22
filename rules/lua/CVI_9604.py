# -*- coding: utf-8 -*-

"""
    Lua SQL注入(LuaSQL)规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9604(SingleRuleMixin):
    """
    Lua SQL注入规则 (LuaSQL)
    匹配 execute / query / fetch / prepare 等数据库操作函数
    注意: Lua 中 sink callee name 在 normalizer 中是方法名，如 execute, query, fetch, prepare
    """

    def __init__(self):
        self.svid = 9604
        self.language = "lua"
        self.vulnerability = "SQL注入"
        self.description = "使用了LuaSQL数据库操作函数（execute、query、fetch、prepare等），如果SQL语句参数包含用户输入且未使用参数化查询，可能导致SQL注入漏洞。建议使用参数化查询(prepare + bind)代替字符串拼接SQL语句。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\bexecute\s*\(|\bquery\s*\(|\bfetch\s*\(|\bprepare\s*\("

        self.vul_function = ["execute", "query", "fetch", "prepare"]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正存在SQL注入风险，
        排除硬编码SQL和使用参数化查询的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:execute|query|fetch|prepare)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码SQL）
        # conn:execute("SELECT * FROM users") -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 使用参数化查询（:? 或 :var 等参数绑定占位符）
        if re.search(r':\w+\b|\?\s*\)', args):
            return False

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
