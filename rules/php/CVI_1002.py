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

class CVI_1002(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1002
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "file_get_contents函数的参数可控，可能会导致SSRF漏洞"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"file_get_contents"
        self.vul_function = ["file_get_contents"]

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
