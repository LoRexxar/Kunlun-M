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

class CVI_1013(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1013
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "URL Redirector Abuse"
        self.description = "URL任意重定向漏洞可能会导致潜在的业务安全问题，配合其他漏洞可能会导致更严重的漏洞危害"
        self.level = 1

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"header"

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: only header("Location: ...") is redirect.
        Check arg[0] for "location:" prefix.
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # Check resolved_value or direct const
                val = arg0.get('resolved_value', '') or ''
                if not val and (arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant')):
                    val = arg0.get('name', '')
                if val:
                    if 'location:' in val.lower():
                        return None
                    return False
            return None

        # Regex fallback
        if "location:" in regex_string.lower():
            return None
        return False
