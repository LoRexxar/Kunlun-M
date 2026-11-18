# -*- coding: utf-8 -*-
from utils.api import *


class CVI_7016(SingleRuleMixin):
    r"""
    Python 出站请求头注入 (Outbound HTTP header injection)

    覆盖: httpx.AsyncClient, httpx2.AsyncClient, requests.Session 等
    出站 HTTP 客户端构造/会话入口的 headers= 参数。

    Fix 117d (CVE-2026-110279, IBM ContextForge MCP Gateway): 客户端可控的
    入站请求头（X-Upstream-Authorization）经 {k.lower(): v for k, v in
    request_headers.items()} 派生 + passthrough_headers["Authorization"]=v
    改名注入后，作为 headers= 传入 httpx2.AsyncClient 发往上游 MCP 服务
    ——凭证走私/认证覆盖（CWE-287）。该 sink 形态此前完全无规则覆盖：
    CVI_7004 的 match 只有 httpx\.Client（不匹配 AsyncClient），且其
    require_taint=False presence 语义与"具体哪个参数污点"无关。

    本规则 TAINT-GATED（require_taint=True）：仅在调用真实携带
    headers= 实参且图中参数回溯到 source 时报告。main() 用调用行文本
    过滤无 headers= 实参的构造（follow_redirects/timeout 类误报面）。
    语义约束：sink 的凭证边界是 headers kwarg —— 报告行即出站点。
    """
    def __init__(self):
        self.svid = 7016
        self.language = "python"
        self.vulnerability = "HTTP头注入"
        self.description = "出站HTTP客户端的headers参数携带用户可控数据（凭证走私/请求头注入）"
        self.level = 5
        self.match_mode = "function-param-regex"
        # 只收 CVI_7004 (presence) 未占领的构造形态：
        # httpx.Client / aiohttp.ClientSession 已在 7004 的 match 中，
        # presence 规则按排序先认领会遮蔽本规则（无谓的死代码）。
        self.match = r"httpx\.AsyncClient|httpx2\.AsyncClient|requests\.Session|requests\.session"

    def main(self, regex_string, sink_args=None):
        if not regex_string:
            return False
        # 必须真实携带 headers= 实参（含 **options 展开形态时由
        # taint proof 兜底；无 headers= 的构造不构成头注入面）。
        if not re.search(r'headers\s*=|\*\*', regex_string):
            return False
        return None
