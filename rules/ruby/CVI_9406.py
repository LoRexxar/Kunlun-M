# -*- coding: utf-8 -*-

"""
    Ruby SSRF规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9406(SingleRuleMixin):
    """
    Ruby SSRF规则
    匹配 Net::HTTP.get/post/put/delete/head、URI.open、HTTParty.get/post、Faraday.get/post 等
    """

    def __init__(self):
        self.svid = 9406
        self.language = "ruby"
        self.vulnerability = "SSRF"
        self.description = "使用了可能存在SSRF（服务端请求伪造）风险的HTTP请求函数（Net::HTTP.get/post/put/delete/head、URI.open、HTTParty.get/post、Faraday.get/post等），且URL参数可能受用户控制。攻击者可利用此访问内网服务或敏感资源。建议对URL参数进行白名单校验，限制协议（仅允许http/https）和目标地址范围。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Net::HTTP\.(get|post|put|delete|head)|URI\.open\s*\(|HTTParty\.(get|post)|Faraday\.(get|post)"

        self.vul_function = ["get", "post", "put", "delete", "head"]

    def main(self, regex_string):
        """
        二次筛选：排除硬编码URL的情况。
        如果URL参数是纯硬编码字符串字面量，返回 False（安全）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:Net::HTTP\.(?:get|post|put|delete|head)|URI\.open|HTTParty\.(?:get|post)|Faraday\.(?:get|post))\s*\((.*)\)', regex_string, re.DOTALL)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 如果第一个参数是纯硬编码字符串字面量（看起来像URL），排除
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            url_arg = arg_parts[0].strip()
            if re.match(r'^["\'][^"\']*["\']$', url_arg):
                return False

        # 确认包含危险的HTTP请求调用
        dangerous_patterns = [
            r"Net::HTTP\.(?:get|post|put|delete|head)",
            r"URI\.open\s*\(",
            r"HTTParty\.(?:get|post)",
            r"Faraday\.(?:get|post)",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_single and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif in_single or in_double:
                current.append(ch)
            elif ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args
