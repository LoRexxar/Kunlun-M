# -*- coding: utf-8 -*-

"""
    CVI-1014
    ~~~~

    variable shadowing

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1014():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1014
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "variable shadowing"
        self.description = "variable shadowing"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "import_request_variables|parse_str|mb_parse_str|extract"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
