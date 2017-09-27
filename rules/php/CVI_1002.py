# -*- coding: utf-8 -*-

"""
    CVI-1002
    ~~~~

    SSRF

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1002():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1002
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "file_get_contents SSRF"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "file_get_contents"

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
