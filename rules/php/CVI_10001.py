# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_10001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 10001
        self.language = "php"
        self.author = "LoRexxar"
        self.vulnerability = "Reflected XSS"
        self.description = "Reflected XSS for echo"

        # status
        self.status = False

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"(echo\s?['\"]?(.+?)?\$(.+?)?['\"]?(.+?)?;)"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

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
