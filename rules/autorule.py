# -*- coding: utf-8 -*-

"""
    ~~~~

    new auto rule base class

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import re


class autorule():
    """
    auto rule class
    
    """
    def __init__(self):

        self.svid = 00000
        self.language = "Auto Rule"
        self.author = "LoRexxar/Cobra-W"
        self.vulnerability = "Auto Rule"
        self.description = "Auto Rule"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = ""
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :return: 
        """
        sql_sen = regex_string[0]
        reg = "\$\w+"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
