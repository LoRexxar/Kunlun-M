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

        self.match_mode = "function-param-controllable"
        self.match = r"write|println|print"

        self.vul_function = ["write", "println", "print"]

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除 import 语句
        if regex_string.lstrip().startswith("import "):
            return False
        # 排除 System.out/System.err (标准输出/错误，非HTTP响应)
        if re.search(r"System\.out\.|System\.err\.", regex_string):
            return False
        # 排除文件写入操作 (变量名如 fileWriter/outputStream 也是文件操作)
        if re.search(r"[Ff]ile[Ww]riter|FileOutputStream|BufferedWriter|Files\.write|os\.write|OutputStream", regex_string):
            return False
        # 排除经过转义的安全输出
        if re.search(r"escapeHtml|htmlEscape|escapeHtml4|HtmlUtils|encode|sanitize|ESAPI|StringEscapeUtils|URLEncoder", regex_string, re.I):
            return False
        return None
