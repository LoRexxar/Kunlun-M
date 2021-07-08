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


class CVI_30111():
    """
    rule class
    """

    def __init__(self):

        self.svid = 30111
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "addEventListener message param 可控"
        self.description = "addEventListener message param 可控, 可以通过windows.postMessage传递，有可能导致安全问题，这里主要假设为chrome ext contentjs场景"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['(addEventListener\\(\\s*[\'"]{1}message[\'"]{1}\\s*,\\s*function\\([^\\)]+\\))']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = r"addEventListener"

    def main(self, regex_string):
        """
        regex string input
        for param
        :return:
        """
        sql_sen = regex_string[0][1]
        reg = "((?<=\()\s*([\w_\.]+))"
        if re.search(reg, sql_sen, re.I):
            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
