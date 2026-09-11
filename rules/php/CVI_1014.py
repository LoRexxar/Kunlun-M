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

class CVI_1014(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1014
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "variable shadowing"
        self.description = "variable 覆盖可能会导致潜在的安全问题，甚至可能导致远程代码执行漏洞"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"import_request_variables|parse_str|mb_parse_str|extract"
        self.vul_function = ["parse_str", "extract"]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering:
        - parse_str with 2 args (output array) is safe — variables go into array.
        - $zip->extract() is PclZip extraction, not PHP extract().
        """
        if sink_args:
            # PclZip $zip->extract() is not PHP extract()
            # Check if this is a method call on an object (->extract)
            # The graph callee_name would contain '->' or '.'
            if 'extract' in regex_string.lower():
                # If called as method (not standalone function), it's PclZip etc.
                # Check: standalone extract() is function call,
                # $obj->extract() is method call — graph node type tells us.
                # sink_args from arg_vids: if arg_vids is empty and it's
                # a method_call, it's likely $zip->extract(options...).
                pass  # handled by find_sinks qualified-name guard
            # parse_str: if 2+ args, second arg is output array → safe
            if 'parse_str' in regex_string.lower():
                if len(sink_args) >= 2:
                    return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        # parse_str with comma (second arg) is safe
        import re
        m = re.search(r'parse_str\s*\([^)]+\)', regex_string)
        if m and m.group().count(',') >= 1:
            return False
        # PclZip $zip->extract()
        if '->extract(' in regex_string.lstrip().lstrip('\\'):
            return False
        return None
