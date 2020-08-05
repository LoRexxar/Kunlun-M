# -*- coding: utf-8 -*-

"""
    CVI-1007
    ~~~~

    remote file include

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class CVI_1007():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1007
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RFI"
        self.description = "remote file include"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "include|include_once|require|require_once|parsekit_compile_file|php_check_syntax|runkit_import|virtual"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
