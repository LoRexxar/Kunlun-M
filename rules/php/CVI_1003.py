# -*- coding: utf-8 -*-

"""
    CVI-1003
    ~~~~

    SSRF

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1003():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1003
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "get_headers SSRF"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "get_headers"

    def main(self, target_file):
        """
        regular for Sensitivity Function
        :return: 
        """
        return file_grep(target_file, self.match)
