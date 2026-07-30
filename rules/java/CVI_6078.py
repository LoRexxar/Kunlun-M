# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule — Spring MVC @ResponseBody / @RestController
    ~~~~
    Detects user input returned directly from @ResponseBody or @RestController
    annotated methods, which will be serialized to the HTTP response body
    without escaping (JSON/XML/etc).

    Coverage:
      - @ResponseBody annotated methods returning user-controlled data
      - @RestController classes whose methods return user-controlled data

    Sink matching: a:ResponseBody prefix → annotation → function → return node

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2024 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6078(SingleRuleMixin):
    def __init__(self):
        self.svid = 6078
        self.language = "java"
        self.vulnerability = "Reflected XSS (@ResponseBody)"
        self.description = "Spring MVC @ResponseBody或@RestController注解方法直接返回用户可控数据，未经HTML转义输出到HTTP响应体。"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = r"a:ResponseBody"

        self.vul_function = ["a:ResponseBody"]

    def main(self, regex_string, sink_args=None):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if regex_string.lstrip().startswith("import "):
            return False
        return None
