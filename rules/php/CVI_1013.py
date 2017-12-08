# -*- coding: utf-8 -*-

"""
    CVI-1013
    ~~~~

    URL Redirector Abuse

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1013():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1013
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "URL Redirector Abuse"
        self.description = "URL Redirector Abuse"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "header"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
