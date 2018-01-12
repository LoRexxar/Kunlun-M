# -*- coding: utf-8 -*-

"""
    CVI-1009
    ~~~~

    Remote code execute

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1009():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1009
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "Remote code execute"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        # preg_replace  preg_replace_callback
        self.match = "(array_map|create_function|call_user_func|call_user_func_array|assert|eval|dl|register_tick_function|register_shutdown_function)"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
