# -*- coding: utf-8 -*-

"""
    Node.js SSRF 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3102(SingleRuleMixin):
    """
    Node.js SSRF 规则
    匹配 http.get/http.request/https.get/https.request 等网络请求函数
    """

    def __init__(self):
        self.svid = 3102
        self.language = "javascript"
        self.vulnerability = "SSRF"
        self.description = "使用了HTTP请求函数（http.get、http.request、https.get、https.request、axios、fetch等）且URL参数可能受用户控制，可能导致服务端请求伪造（SSRF）漏洞。建议对用户输入的URL进行严格的白名单校验。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"http\.get\s*\(|http\.request\s*\(|https\.get\s*\(|https\.request\s*\(|net\.connect\s*\(|net\.createConnection\s*\("

        self.vul_function = [
            "http.get", "http.request", "https.get", "https.request",
            "net.connect", "net.createConnection",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码URL
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

        # 检查是否有 http/https 模块上下文
        has_http_context = bool(re.search(
            r'http\.get|http\.request|https\.get|https\.request|net\.connect|net\.createConnection',
            regex_string
        ))

        if not has_http_context:
            return None

        # 排除纯硬编码URL
        match = re.search(
            r'(?:http\.get|http\.request|https\.get|https\.request|net\.connect|net\.createConnection)\s*\((.*)\)',
            regex_string
        )
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量URL（硬编码）
            if re.match(r'^["\'][^"\']*["\'](?:\s*,.*)?$', args):
                return False

        return True
