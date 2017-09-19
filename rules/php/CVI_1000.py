# -*- coding: utf-8 -*-

"""
    CVI-1000
    ~~~~

    Reflected XSS

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1000():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1000
        self.language = "PHP"
        self.author = "LoRexxar"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "echo|print|print_r|exit|die|printf|vprintf|trigger_error|user_error|odbc_result_all|ovrimos_result_all|ifx_htmltbl_result"

    # def main(self, target_file):
    #     """
    #     regular for Sensitivity Function
    #     :return:
    #     """
    #     return file_grep(target_file, self.regexp)
