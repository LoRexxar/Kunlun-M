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

class CVI_1012(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1012
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "Information Disclosure"
        self.description = "var_dump这类函数不应该存在于正式环境中，可能会导致信息泄露"
        self.level = 2

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(print_r|var_dump|show_source|highlight_file)"

    def main(self, regex_string, sink_args=None, **kwargs):
        """Skip print_r when called with return=true (2nd arg).
        print_r($arr, true) returns a string instead of printing to output,
        so it is safe for debug logging into variables.
        """
        # Build context text for checks
        ctx_text = ''
        if isinstance(regex_string, str):
            ctx_text = regex_string
        context = kwargs.get('context')
        if context and isinstance(context, str):
            ctx_text = ctx_text + ' ' + context

        import re
        # Skip print_r($arr, true) — second arg 'true' means return, not print
        if sink_args and len(sink_args) >= 2:
            arg1 = sink_args[1]
            if arg1.get('resolved_value', '') in ('true', 'True', '1', 'true', True):
                return False

        # Also check via regex for print_r(..., true) pattern
        if ctx_text and re.search(r"print_r\s*\([^)]*,\s*true\s*\)", ctx_text, re.I):
            return False

        return None
