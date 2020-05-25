# -*- coding: utf-8 -*-

"""
    CVI-10001
    ~~~~

    Reflected XSS only for echo
    
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""
import re


class CVI_10001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10001
        self.language = "PHP"
        self.author = "LoRexxar"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS for echo"

        # status
        self.status = False

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = "(echo\s?['\"]?(.+?)?\$(.+?)?['\"]?(.+?)?;)"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        sql_sen = regex_string[0][0]
        reg = "\$\w+"
        if re.search(reg, sql_sen, re.I):
            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None

