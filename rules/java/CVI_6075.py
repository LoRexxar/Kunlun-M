# -*- coding: utf-8 -*-

"""
    Java CRLF Injection Rule
    ~~~~
    检测用户输入被注入到HTTP响应头中导致的CRLF注入漏洞。
    典型模式: response.setHeader("Custom-Header", userInput)
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6075(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6075
        self.language = "java"
        self.vulnerability = "CRLF Injection"
        self.description = "通过AST分析检测用户可控输入被直接设置到HTTP响应头(setHeader/addHeader/setCookie)中导致的CRLF注入漏洞。攻击者可注入\\r\\n分割HTTP响应头和body，实现HTTP响应拆分攻击。建议对输入中的CR(\\r)和LF(\\n)字符进行过滤。"
        self.level = 5

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r'\.setHeader\s*\(|\.addHeader\s*\(|\.setIntHeader\s*\('

        # for regex
        self.unmatch = []

        self.vul_function = [

            "HttpServletResponse.setHeader",

            "HttpServletResponse.addHeader",

            "HttpServletResponse.setIntHeader",

        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based CRLF filtering: known safe headers are not CRLF vectors.
        sink_args: list of {name, type, label, vid} from graph arg nodes.
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # Try resolved_value first, then direct const
                header_val = arg0.get('resolved_value', '')
                if not header_val:
                    if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                        header_val = arg0.get('name', '')
                if header_val:
                    header_name = header_val.strip('"').strip("'").lower()
                    # All Access-Control-* headers use constant names,
                    # not injectable via CRLF.
                    if header_name.startswith('access-control-'):
                        return False
                    safe_headers = {'content-type', 'content-length', 'content-disposition',
                                    'x-frame-options', 'x-content-type-options',
                                    'x-xss-protection'}
                    if header_name in safe_headers:
                        return False
            return None

        # Regex fallback
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r'Content-Type|Content-Length|Content-Disposition|X-Frame-Options|X-Content-Type|X-XSS', regex_string):
            if not re.search(r'\+\s*\w+', regex_string):
                return False
        return None
