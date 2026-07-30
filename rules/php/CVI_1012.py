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

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
