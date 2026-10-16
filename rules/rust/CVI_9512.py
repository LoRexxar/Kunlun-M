# -*- coding: utf-8 -*-

"""
    Rust 库边界 SSRF 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_9512(SingleRuleMixin):
    """
    Rust 库边界 SSRF（http::Request 构造形态）

    CVE-2026-95634 (Adobe CAI Content Credentials): c2pa-rs
    verify 路径 load_jumbf_from_stream -> handle_remote_manifest ->
    fetch_remote_manifest -> http::Request::get(url)，url 取自
    asset 内嵌的远程 manifest 引用；is_valid_remote_url 只校验
    scheme（http/https），不校验 host/私网/重定向，服务器在
    verify 用户提供的 asset 时对任意 URL 发起 GET（SSRF，CVSS 8.6）。
    """

    def __init__(self):
        self.svid = 9512
        self.language = "rust"
        self.vulnerability = "SSRF"
        self.description = "通过 http::Request::get/post 等构造 HTTP 请求且目标 URL 来自非字面量（函数参数/变量），可能存在 SSRF（服务端请求伪造）漏洞。库代码的漏洞边界是公开 API 参数，静态污点不可证时仍建议人工复核：对 URL 做 host 白名单校验、禁止私网/环回/链路本地地址、禁用跨主机重定向。"
        self.level = 7

        self.match_mode = "function-param-regex"
        # 只匹配 http::Request 构造形态的**限定名**（不含裸 get/post——
        # 那会撞上 HashMap::get 等无害方法）。
        self.match = (
            r"\bhttp\s*::\s*Request\s*::\s*(?:builder|get|post|put|delete|patch|head)\s*\("
        )

        self.vul_function = [
            "http.Request.builder", "http.Request.get", "http.Request.post",
            "http.Request.put", "http.Request.delete", "http.Request.patch",
            "http.Request.head",
        ]

        # 库边界 sink：c2pa-rs 这类 SDK/CLI 库没有 web framework source，
        # 污点无法证到框架入口。漏洞边界是公开 API 的参数（asset 内嵌
        # 的远程引用），presence + main() 常量过滤即报告。
        self.require_taint = False

    def main(self, regex_string, sink_args=None):
        """二次筛选：排除硬编码 URL（常量目标不构成 SSRF）。"""
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get("label") == "const" or arg0.get("type") in ("string", "constant"):
                    return False
                if arg0.get("resolved_value", ""):
                    return False
            return None

        if not isinstance(regex_string, str):
            return None
        m = re.search(
            r"http\s*::\s*Request\s*::\s*\w+\s*\(\s*(.+?)\s*[\),]",
            regex_string,
        )
        if m:
            arg = m.group(1).strip()
            # 纯字面量 URL（"https://..." 或 String::from("https://...")）
            if re.match(r'^"[^"]*"$', arg) or re.match(
                r"^String::from\s*\(\s*\"[^\"]*\"\s*\)$", arg
            ):
                return False
        return None
