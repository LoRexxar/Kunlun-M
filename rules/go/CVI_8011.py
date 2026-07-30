# -*- coding: utf-8 -*-

"""
    Go XPath注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_8011(SingleRuleMixin):
    """
    Go XPath注入规则
    匹配 xpath.Query / xpath.Evaluate 等
    """

    def __init__(self):
        self.svid = 8011
        self.language = "go"
        self.vulnerability = "XPath注入"
        self.description = "使用了XPath查询函数（xpath.Query、xpath.Evaluate等），可能导致XPath注入漏洞。建议对用户输入进行严格校验和转义，或使用参数化XPath查询，避免将用户输入直接拼接到XPath表达式中。"
        self.level = 7

        self.match_mode = "function-param-regex"
        self.match = r"xpath\.Query|xpath\.Evaluate|libxml2.*XPath"

        self.vul_function = ["xpath.Query", "xpath.Evaluate"]

    def main(self, regex_string, sink_args=None):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r'xpath\.(Query|Evaluate)', regex_string):
            return True
        return None
