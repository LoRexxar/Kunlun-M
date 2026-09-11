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

class CVI_1008(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1008
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "Xml injection"
        self.description = "Xml injection可能会导致任意文件读取/SSRF，特殊坏境下还可能导致RCE"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"simplexml_load_file|simplexml_load_string"

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
