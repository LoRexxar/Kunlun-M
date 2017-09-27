# -*- coding: utf-8 -*-

"""
    CVI-1004
    ~~~~

    Sqli

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re


class CVI_1004():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1004
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SQLI"
        self.description = "SQL injection"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = "(\"\s*(select|SELECT|insert|INSERT|update|UPDATE)\s*(([^;]\s*)*)?\$(.+?);?\")"

    def main(self, regex_string):
        """
        regex string input
        just for sql statements
        :return: 
        """
        sql_sen = regex_string[0][0]
        reg = "\$\w+"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None

