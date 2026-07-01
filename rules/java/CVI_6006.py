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

            "URL.openConnection",

            "URL.openStream",

            "HttpURLConnection",

            "RestTemplate",

            "OkHttpClient",

            "DefaultHttpClient",

            "HttpClient",

            "Request.Get",

            "Request.Post",

        ]

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有白名单校验的写法
        if re.search(r"allowedHosts|ALLOWED_HOSTS|isUrlAllowed|whitelist|urlWhitelist|allowedDomains", regex_string, re.I):
            return False
        return None

