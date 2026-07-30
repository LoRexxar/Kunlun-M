# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule — Spring MVC ModelAndView
    ~~~~
    Detects user input passed to ModelAndView.addObject() which will be
    rendered in a template without guaranteed escaping.

    Coverage:
      - modelAndView.addObject("key", userInput)
      - mav.addObject("key", userInput)

    Note: Thymeleaf auto-escapes by default, but JSP templates (JSTL)
    may not. SAST cannot determine template engine behavior, so this
    is flagged as a potential risk.

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2024 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6002_spring(SingleRuleMixin):
    def __init__(self):
        self.svid = "6002-spring"
        self.language = "java"
        self.vulnerability = "Reflected XSS (ModelAndView)"
        self.description = "用户输入通过Spring MVC ModelAndView.addObject传入模板渲染，可能未经转义。"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = r"addObject"

        self.vul_function = ["ModelAndView.addObject"]

    def main(self, regex_string, sink_args=None):
        """Graph path: import filtering handled by graph engine."""
        if sink_args:
            # const model value → static, safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if regex_string.lstrip().startswith("import "):
            return False
        if not re.search(r"addObject\s*\(", regex_string):
            return False
        return None
