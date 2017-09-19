# -*- coding: utf-8 -*-

"""
    CVI-1012
    ~~~~

    Information Disclosure

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1012():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1012
        self.language = "PHP"
        self.author = "LoRexxar"
        self.vulnerability = "Information Disclosure"
        self.description = "Information Disclosure"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "(print_r|var_dump|show_source|highlight_file)\s*\("

    def main(self, target_file):
        """
        regular for Sensitivity Function
        :return: 
        """
        return file_grep(target_file, self.match)
