# -*- coding: utf-8 -*-

"""
    Java Reflected XSS Rule — PrintWriter / Servlet Response Output
    ~~~~
    Detects user input written directly to HTTP response via
    PrintWriter.write() / println() / print() without encoding.

    Coverage:
      - response.getWriter().write(userInput)
      - PrintWriter out = response.getWriter(); out.write(userInput)
      - out.println(userInput)  (PrintWriter from getWriter())

    Exclusions (in main):
      - System.out / System.err  (stdout/stderr logging)
      - FileWriter / FileOutputStream / BufferedWriter  (file I/O)
      - Files.write()  (NIO file operations)
      - os.write()  (low-level file descriptor)
      - Lines containing escape/sanitize keywords

    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2024 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6002(SingleRuleMixin):
    def __init__(self):
        self.svid = 6002
        self.language = "java"
        self.vulnerability = "Reflected XSS (PrintWriter Output)"
        self.description = "将用户输入通过PrintWriter直接写入HTTP响应，未进行编码转义。"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = r"write|println|print"

        self.vul_function = [

            "PrintWriter.write",

            "PrintWriter.println",

            "PrintWriter.print",

            "ServletOutputStream.write",

            "ServletOutputStream.println",

        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: const arg is static output (safe).
        Also excludes System.out/System.err and file I/O writers.
        """
        # Check regex_string (source line) for non-HTTP output sinks
        if isinstance(regex_string, str):
            if re.search(r"System\.out\.|System\.err\.", regex_string):
                return False
            if re.search(r"[Ff]ile[Ww]riter|FileOutputStream|BufferedWriter|Files\.write|os\.write", regex_string):
                return False
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # const string → static output, safe
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r"System\.out\.|System\.err\.", regex_string):
            return False
        if re.search(r"[Ff]ile[Ww]riter|FileOutputStream|BufferedWriter|Files\.write|os\.write|OutputStream", regex_string):
            return False
        if re.search(r"escapeHtml|htmlEscape|escapeHtml4|HtmlUtils|encode|sanitize|ESAPI|StringEscapeUtils|URLEncoder", regex_string, re.I):
            return False
        return None
