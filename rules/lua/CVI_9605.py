# -*- coding: utf-8 -*-

"""
    Lua SSRF规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9605(SingleRuleMixin):
    """
    Lua SSRF规则 (LuaSocket/LuaSec)
    匹配 socket.connect / http.request / wget 等
    注意: Lua 中 sink callee name 在 normalizer 中是方法名，如 connect, request, wget
    """

    def __init__(self):
        self.svid = 9605
        self.language = "lua"
        self.vulnerability = "SSRF"
        self.description = "使用了网络请求函数（socket.connect、http.request、wget等），如果目标地址参数包含用户输入，可能导致SSRF（服务端请求伪造）漏洞。攻击者可能利用此漏洞访问内网服务或敏感资源。建议对请求目标地址进行严格的白名单校验，禁止访问内网地址。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\bconnect\s*\(|\brequest\s*\(|\bwget\s*\("

        self.vul_function = ["socket.connect", "http.request", "wget"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正存在SSRF风险，
        排除硬编码地址。
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
        match = re.search(r'(?:connect|request|wget)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码URL/地址）
        # socket.connect("localhost", 80) -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 多个纯字符串字面量参数（如 socket.connect("localhost", 80)）
        if re.match(r'^["\'][^"\']*["\']\s*,\s*["\'][^"\']*["\']$', args):
            return False

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
