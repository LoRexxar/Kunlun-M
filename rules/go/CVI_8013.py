# -*- coding: utf-8 -*-

"""
    Go 开放重定向规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_8013(SingleRuleMixin):
    """
    Go 开放重定向规则
    匹配 http.Redirect
    """

    def __init__(self):
        self.svid = 8013
        self.language = "go"
        self.vulnerability = "开放重定向"
        self.description = "使用了HTTP重定向函数（http.Redirect），且重定向URL参数可能由用户输入控制，可能导致开放重定向漏洞。建议对重定向URL进行白名单校验，仅允许本站相对路径或可信域名，避免将用户输入直接作为重定向目标。"
        self.level = 5

        self.match_mode = "function-param-regex"
        self.match = r"http\.Redirect\s*\("

        self.vul_function = ["http.Redirect"]

    def main(self, regex_string, sink_args=None):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r'http\.Redirect\s*\(', regex_string):
            # 重定向到变量（如 rURL）通常是自身 URL 重定向
            if re.search(r'req\.URL|request\.URL|r\.URL|rURL|c\.Request', regex_string):
                return False
            return True
        return None
