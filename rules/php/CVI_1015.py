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
        regex string input
        :regex_string: regex match string
        :return:
        """
        return None
