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


class CVI_3011():
    """
    rule class
    """

    def __init__(self):

        self.svid = 3011
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "executeScript中参数拼接"
        self.description = "executeScript中code或者file出现参数拼接，可能导致安全问题"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "only-regex"
        self.match = ['(chrome\\.tabs\\.executeScript\\([^,]+,\\s*{[^}]*(\'|")?(code|file)(\'|")?\\s*:\\s*((`[^`]*\\${[^`]*`)|("[^"]*"\\s*\\+)|(\'[^\']*\'\\s*\\+)|\\w+))']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = ['JSON\\.stringify\\(']

        self.vul_function = r"executeScript"

    def main(self, regex_string):
        """
        regex string input
        for param statements
        :return:
        """
        def trim(data):
            result = []

            for i in data:
                if type(i) is tuple:
                    for j in i:
                        if j:
                            result.append(j.strip())

                    continue

                if i:
                    result.append(i.strip())

            return result

        sql_sen = regex_string[0][4]
        reg = "((?<=:)\s*([\w_\.]+))"
        if re.search(reg, sql_sen, re.I):
            p = re.compile(reg)
            match = p.findall(sql_sen)
            return trim(match)
        return None
