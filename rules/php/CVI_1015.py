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

class CVI_1015(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1015
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "unserialize vulerablity"
        self.description = "unserialize反序列化漏洞配合pop chain可能会导致潜在的安全问题，即便没有pop chain存在，配合内置类也会导致SSRF漏洞等"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"unserialize"

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: unserialize with allowed_classes option is safe.
        unserialize($data, ['allowed_classes' => false]) prevents
        object instantiation.
        """
        # Check regex_string (source line) first — applies to all paths
        if isinstance(regex_string, str) and 'allowed_classes' in regex_string.lower():
            return False
        if sink_args:
            # 2+ args means options array is passed
            if len(sink_args) >= 2:
                for a in sink_args[1:]:
                    rv = a.get('resolved_value', '') or ''
                    if not rv and (a.get('label') == 'const' or a.get('type') in ('string', 'constant')):
                        rv = a.get('name', '')
                    if 'allowed_classes' in str(rv).lower():
                        return False
            return None
        return None
