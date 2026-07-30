# -*- coding: utf-8 -*-

"""
    Node.js 开放重定向规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3106(SingleRuleMixin):
    """
    Node.js 开放重定向规则
    匹配 res.redirect、ctx.redirect 等重定向函数
    """

    def __init__(self):
        self.svid = 3106
        self.language = "javascript"
        self.vulnerability = "开放重定向"
        self.description = "使用了重定向函数（res.redirect、ctx.redirect等）且目标URL可能受用户控制，可能导致开放重定向漏洞。建议对重定向目标进行白名单校验。"
        self.level = 5

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"res\.redirect\s*\(|ctx\.redirect\s*\(|response\.redirect\s*\("

        self.vul_function = [
            "res.redirect", "ctx.redirect", "response.redirect",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码URL重定向
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

        match = re.search(r'(?:res|ctx|response)\.redirect\s*\((.*)\)', regex_string)
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量（硬编码URL）
            if re.match(r'^["\'][^"\']*["\'](?:\s*,.*)?$', args):
                return False
            # 数字状态码开头：res.redirect(301, url) — 第二个参数是URL
            if re.match(r'^\d+\s*,\s*["\'][^"\']*["\']$', args):
                return False
            return True

        return None
