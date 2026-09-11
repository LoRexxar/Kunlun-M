# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_1000(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1000
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS，用户输入被直接/不完全过滤输出到页面内容当中，可能会导致XSS隐患。"
        self.level = 4

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"echo|print|print_r|printf|vprintf|odbc_result_all|ovrimos_result_all|ifx_htmltbl_result"

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: filter out print_r($var, true) which returns a string
        instead of outputting to the browser. When the second argument is
        boolean true, print_r is a string function, not an XSS output sink.
        """
        if sink_args and len(sink_args) >= 2:
            # Check if this is a print_r call with second arg = true
            arg1 = sink_args[1]
            val = arg1.get('resolved_value', '') or ''
            if not val:
                val = arg1.get('name', '')
            if val and val.strip().lower() in ('true', '1', 'true'):
                return False

        # Also check source code line for print_r(..., true) pattern
        if regex_string and 'print_r' in regex_string.lower():
            import re
            # Match print_r(..., true) where second arg is literal true
            if re.search(r'print_r\s*\([^)]*,\s*true\s*\)', regex_string, re.IGNORECASE):
                return False

        return None
