# -*- coding: utf-8 -*-

"""
    Kotlin SSRF 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9305(SingleRuleMixin):
    """
    Kotlin SSRF 规则
    匹配 URL, HttpURLConnection, OkHttp (OkHttpClient.newCall) 等网络请求
    """

    def __init__(self):
        self.svid = 9305
        self.language = "kotlin"
        self.vulnerability = "SSRF"
        self.description = "使用了HTTP网络请求函数（URL、HttpURLConnection、OkHttpClient.newCall等）且URL参数可能受用户控制，可能导致服务端请求伪造（SSRF）漏洞。建议对用户输入的URL进行严格的白名单校验，禁止访问内网地址和敏感端口。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"java\.net\s*\.\s*URL\s*\(\s*\w+|URL\s*\(\s*\w+|HttpURLConnection\s*\(|HttpsURLConnection\s*\(\s*\(|openConnection\s*\(\s*\)|OkHttpClient\s*\(\s*\)|\.newCall\s*\(\s*\)|\.execute\s*\(\s*\)|Retrofit\s*\(\s*\)|AsyncHttpClient\s*\(\s*\)"

        self.vul_function = [
            "URL", "HttpURLConnection", "HttpsURLConnection",
            "openConnection", "OkHttpClient.newCall",
            "execute", "AsyncHttpClient",
        ]

    def main(self, regex_string):
        """
        二次筛选：排除纯硬编码URL的安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 安全写法：对URL进行了白名单校验
        if re.search(r'(?:whitelist|allowlist|allowedHosts|isAllowed|isValidUrl|validateUrl)\s*\(', regex_string):
            return False

        # 安全写法：检查了协议
        if re.search(r'(?:startsWith\s*\(\s*"https")|(?:protocol\s*==\s*"https")', regex_string):
            return False

        # 确认包含网络请求上下文
        has_network_context = bool(re.search(
            r'URL\s*\(|HttpURLConnection|HttpsURLConnection|openConnection|OkHttpClient|newCall|AsyncHttpClient',
            regex_string
        ))

        if not has_network_context:
            return None

        # 检测 URL 构造与变量拼接
        match = re.search(r'URL\s*\((.*?)\)', regex_string)
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量URL（硬编码）
            if re.match(r'^"[^"]*"$', args):
                return False

        # 字符串拼接或模板变量
        if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
            return True

        # 变量作为URL参数
        if re.search(r'(?:URL|newCall|OkHttpClient)\s*\(\s*\w+', regex_string):
            return True

        return None
