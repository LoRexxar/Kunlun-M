# -*- coding: utf-8 -*-

"""
    CVI-1015
    ~~~~

    unserialize vulerablity

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class CVI_1015():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1015
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "unserialize vulerablity"
        self.description = "unserialize vulerablity"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "is_a|unserialize"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
