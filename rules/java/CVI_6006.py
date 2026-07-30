# -*- coding: utf-8 -*-

"""
    Java SSRF Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6006(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6006
        self.language = "java"
        self.vulnerability = "SSRF"
        self.description = "通过AST分析检测URL.openConnection()、HttpURLConnection、RestTemplate等HTTP请求方法的URL参数是否来自用户可控输入，追踪数据流以发现SSRF漏洞。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"new\s+URL\(|\.openConnection\(\)|\.openStream\(\)|new\s+RestTemplate\(|new\s+OkHttpClient\(|new\s+DefaultHttpClient\(|new\s+HttpClient\(|Request\.Get\(|Request\.Post\("

        # for regex
        self.unmatch = []

        self.vul_function = [
            # 方法: 图引擎有use edge, 可用fullname
            "URL.openConnection",
            "URL.openStream",
            "HttpURLConnection",
            # 构造函数: callee是短名(无use edge), 保持短名
            "URL",
            "RestTemplate",
            "OkHttpClient",
            "DefaultHttpClient",
            "HttpClient",
            # 短名fallback: 链式调用如 new URL().openStream 的callee解析为短名
            "openStream",
            "Request.Get",
            "Request.Post",
        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: const URL arg is hardcoded (safe).
        Empty args = no-arg constructor (just client creation, not SSRF).
        """
        if sink_args is not None:
            # No args → new RestTemplate() — just creating client object
            if not sink_args:
                return False
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r"allowedHosts|ALLOWED_HOSTS|isUrlAllowed|whitelist|urlWhitelist|allowedDomains", regex_string, re.I):
            return False
        if re.search(r"new\s+(RestTemplate|OkHttpClient|DefaultHttpClient|HttpClient)\s*\(\s*\)", regex_string):
            return False
        return None

