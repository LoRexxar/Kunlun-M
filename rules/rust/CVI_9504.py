# -*- coding: utf-8 -*-

"""
    Rust SSRF规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9504(SingleRuleMixin):
    """
    Rust SSRF（服务端请求伪造）规则
    匹配 reqwest::Client, ureq, http::Request::builder 等 HTTP 请求调用。
    normalizer 中 sink callee name 为方法名（如 get, post, request 等）。
    """

    def __init__(self):
        self.svid = 9504
        self.language = "rust"
        self.vulnerability = "SSRF"
        self.description = "使用了可能发起HTTP请求的函数（reqwest::Client、ureq、http::Request::builder等），可能导致SSRF（服务端请求伪造）漏洞。建议对用户输入的URL进行严格校验，限制可请求的目标地址范围。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = (
            r"\breqwest\s*::\s*Client\s*::\s*(?:new|builder)\s*\("
            r"|\bclient\s*\.\s*(?:get|post|put|delete|patch|head|request|execute)\s*\("
            r"|\bureq\s*::\s*(?:get|post|put|delete|patch|head|agent|request)\s*\("
            r"|\bhttp\s*::\s*Request\s*::\s*builder\s*\("
        )

        self.vul_function = [
            "reqwest::Client::new", "reqwest::Client::builder",
            "client.get", "client.post", "client.put", "client.delete",
            "client.patch", "client.head", "client.request", "client.execute",
            "ureq::get", "ureq::post", "ureq::put", "ureq::delete",
            "ureq::patch", "ureq::head", "ureq::agent", "ureq::request",
            "http::Request::builder",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的HTTP请求调用，
        排除硬编码URL参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取HTTP请求函数的参数部分
        match = re.search(
            r'(?:client|ureq)\s*[.:]\s*(?:get|post|put|delete|patch|head|request|execute)\s*\((.*)\)'
            r'|(?:ureq)\s*::\s*(?:get|post|put|delete|patch|head|agent|request)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        # match.group(1) 或 match.group(2)
        args = match.group(1) or match.group(2) or ""
        args = args.strip()

        # 纯字符串字面量（硬编码URL）
        # client.get("https://api.example.com")
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含危险的HTTP请求调用
        dangerous_patterns = [
            r"reqwest::Client::(?:new|builder)\s*\(",
            r"\.client\s*\.\s*(?:get|post|put|delete|patch|head|request|execute)\s*\(",
            r"\bclient\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(",
            r"ureq::(?:get|post|put|delete|patch|head|agent|request)\s*\(",
            r"http::Request::builder\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
