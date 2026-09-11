# -*- coding: utf-8 -*-

"""
    Graph engine rule for jQuery DOM insertion XSS
    ~~~~
    Covers: $(...).html(userInput), $(...).append(userInput), etc.
"""

from utils.api import *


class CVI_3007_graph():
    """
    Graph engine rule: jQuery XSS via DOM insertion methods
    """

    def __init__(self):
        self.svid = 3007
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "JQuery XSS"
        self.description = "JQuery XSS是署于JQuery独有的XSS漏洞函数"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"html|before|insertBefore|insertAfter|after|append|prepend|wrap|wrapAll|wrapInner|appendTo|prependTo"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["html", "before", "insertBefore", "insertAfter", "after", "append",
                             "prepend", "wrap", "wrapAll", "wrapInner", "appendTo", "prependTo"]

    def main(self, regex_string, sink_args=None):
        """
        过滤非 jQuery 的 DOM 操作调用：
        - 原生 JS insertBefore/append/prepend 不是 jQuery XSS
        - element.style[...] 赋值不是 jQuery XSS
        - node.textContent / innerText 赋值不是 jQuery XSS
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        import re

        # 原生 DOM API（非 jQuery）— 这些不是 jQuery XSS
        native_dom_patterns = [
            r'\.(?:parentNode\s*\.)?insertBefore\s*\(',
            r'\.(?:parentNode\s*\.)?appendChild\s*\(',
            r'\.removeChild\s*\(',
            r'\.replaceChild\s*\(',
        ]
        for pat in native_dom_patterns:
            if re.search(pat, regex_string):
                return False

        # element.style[...] = ... 或 elementStyle[...] = ... — 不是 jQuery XSS
        if re.search(r'\[.*?style.*?\]\s*=|\w+Style\[', regex_string, flags=re.IGNORECASE):
            return False

        # 如果匹配的是 jQuery $().html() 等调用模式，保留
        # match 中的 html|before|insertBefore|... 是通过 jQuery 对象调用的
        if re.search(r'\$\s*\(', regex_string):
            return None  # jQuery 调用，不做额外过滤

        # 非 jQuery 上下文中匹配到了 html/append 等方法名
        # 可能是 React/原生 DOM，默认返回 None（交给上层判断）
        return None
