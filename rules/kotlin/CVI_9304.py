# -*- coding: utf-8 -*-

"""
    Kotlin XSS 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9304(SingleRuleMixin):
    """
    Kotlin XSS 规则
    匹配 SpannableString.append/appendHtml, WebView.loadData/loadDataWithBaseURL,
    WebView.evaluateJavascript 等
    """

    def __init__(self):
        self.svid = 9304
        self.language = "kotlin"
        self.vulnerability = "XSS"
        self.description = "使用了可能插入HTML/JS内容的函数（SpannableString.append/appendHtml、WebView.loadData、WebView.evaluateJavascript等），当内容来自用户输入且未经转义时，可能导致跨站脚本攻击（XSS）。建议对用户输入进行HTML转义（如Html.escape），或使用安全的文本设置方式。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"appendHtml\s*\(|WebView\s*\.\s*loadData\s*\(|WebView\s*\.\s*loadDataWithBaseURL\s*\(|WebView\s*\.\s*evaluateJavascript\s*\(|\.loadData\s*\(|\.loadDataWithBaseURL\s*\(|\.evaluateJavascript\s*\(|\.setText\s*\(\s*Html\s*\.\s*from\s*\(|Html\s*\.\s*from\s*\("

        self.vul_function = [
            "appendHtml", "append",
            "WebView.loadData", "WebView.loadDataWithBaseURL",
            "WebView.evaluateJavascript",
            "Html.fromHtml",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除使用了安全转义函数的写法。
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

        # 安全写法：使用了 Html.escape 转义用户输入
        if re.search(r'Html\s*\.\s*escape\s*\(', regex_string):
            return False

        # 安全写法：使用了 TextUtils.htmlEncode
        if re.search(r'TextUtils\s*\.\s*htmlEncode\s*\(', regex_string):
            return False

        # 安全写法：WebView.loadData 使用了编码和 "data:text/html" 基准 URL
        if re.search(r'loadData\s*\([^)]*"text/html"[^)]*,\s*"[^"]*base64"[^)]*\)', regex_string):
            return False

        # 确认包含危险调用
        dangerous_patterns = [
            r"appendHtml\s*\(",
            r"loadData\s*\(",
            r"loadDataWithBaseURL\s*\(",
            r"evaluateJavascript\s*\(",
            r"Html\s*\.\s*from\s*\(",
        ]
        has_dangerous = False
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                has_dangerous = True
                break

        if not has_dangerous:
            return None

        # 字符串拼接或模板变量
        if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
            return True

        # 变量作为参数传入
        for pat in dangerous_patterns:
            if re.search(re.escape(pat.rstrip('(')) + r'\s*\(\s*\w+', regex_string):
                return True

        return None
