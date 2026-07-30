# -*- coding: utf-8 -*-

"""
    Go XSS 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8003(SingleRuleMixin):
    """
    匹配 template.HTML/template.JS/template.URL 类型转换绕过自动转义
    """

    def __init__(self):
        self.svid = 8003
        self.language = "go"
        self.vulnerability = "XSS"
        self.description = "使用了template.HTML/template.JS/template.URL类型转换绕过Go模板引擎的自动转义机制，可能导致跨站脚本攻击(XSS)。建议避免使用不安全的类型转换，使用html/template的自动转义功能。"
        self.level = 6

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"template\.HTML\s*\(|template\.JS\s*\(|template\.URL\s*\(|template\.HTMLAttr\s*\(|template\.Srcset\s*\("

        self.vul_function = [
            "template.HTML", "template.JS", "template.URL",
            "template.HTMLAttr", "template.Srcset",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否属于危险的XSS相关调用。
        排除硬编码字符串和安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 检查 template.HTML 等不安全类型转换
        unsafe_type_patterns = [
            r"template\.HTML\s*\(",
            r"template\.JS\s*\(",
            r"template\.URL\s*\(",
            r"template\.HTMLAttr\s*\(",
            r"template\.Srcset\s*\(",
        ]
        for pat in unsafe_type_patterns:
            if re.search(pat, regex_string):
                # 排除纯硬编码字符串：template.HTML("<div>static</div>")
                inner = re.search(r'template\.\w+\s*\(\s*"([^"]*)"\s*\)', regex_string)
                if inner:
                    # 如果字符串中不含 < > 等HTML标签，风险较低但仍标记
                    content = inner.group(1)
                    if '<' not in content and '>' not in content and '&' not in content:
                        return False
                return True

        return None
