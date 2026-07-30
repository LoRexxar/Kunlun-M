# -*- coding: utf-8 -*-

"""
    Go SSRF 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8005(SingleRuleMixin):
    """
    Go SSRF 规则
    匹配 http.Get/http.Post/http.NewRequest/http.DefaultClient.Get/net.Dial 等
    """

    def __init__(self):
        self.svid = 8005
        self.language = "go"
        self.vulnerability = "SSRF"
        self.description = "使用了HTTP请求函数（http.Get、http.Post、http.NewRequest、http.DefaultClient.Get等），如果请求URL来自用户输入，可能导致服务端请求伪造(SSRF)攻击。建议对URL进行白名单校验，禁止访问内网地址和敏感端口。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"http\.Get\s*\(|http\.Post\s*\(|http\.NewRequest\s*\(|http\.Head\s*\(|http\.PostForm\s*\(|\.Get\s*\(|\.Post\s*\(|\.Do\s*\(|net\.Dial\s*\(|net\.DialTimeout\s*\("

        self.vul_function = [
            "http.Get", "http.Post", "http.NewRequest", "http.Head",
            "http.PostForm", "http.DefaultClient.Get", "http.DefaultClient.Post",
            "net.Dial", "net.DialTimeout",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查URL参数是否为硬编码，排除安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数
        match = re.search(r'(?:http\.\w+|\.Get|\.Post|\.Do|net\.Dial(?:Timeout)?)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量硬编码URL
        # http.Get("https://api.example.com/data") -> 硬编码，排除
        if re.match(r'^"[^"]*"$', args):
            return False

        # 确认包含危险的HTTP请求调用
        dangerous_patterns = [
            r"http\.Get\s*\(",
            r"http\.Post\s*\(",
            r"http\.NewRequest\s*\(",
            r"http\.Head\s*\(",
            r"http\.PostForm\s*\(",
            r"\.Get\s*\(\s*ctx",
            r"\.Post\s*\(\s*ctx",
            r"\.Do\s*\(\s*req",
            r"net\.Dial\s*\(",
            r"net\.DialTimeout\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
