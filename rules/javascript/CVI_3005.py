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


class CVI_3005():
    """
    rule class
    """

    def __init__(self):

        self.svid = 3005
        self.language = "javascript"
        self.author = "LoRexxar"
        self.vulnerability = "HTML injection"
        self.description = "HTML injection可能会导致XSS漏洞"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"(\.innerHTML\s*=\s*([^;]+)\b)"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = r"innerHTML"

    def main(self, regex_string):
        """
        regex string input
        just for sql statements
        :return: 
        """
        def clean_string(match):
            result = []

            for i in match:
                m = i[0]

                if "\"" not in m and "'" not in m:
                    result.append(m.strip())

            return result
        sql_sen = regex_string[0][0]
        # reg = "[\w_.]+"
        reg = "((?<=\(|,|=|\+)\s*((\"[^\"]+?\")|('[^']+')|[\w_\.]+))"

        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return clean_string(match)

        # 从这个规则中测试一种新可能，新匹配属性，这应该是js才会出现的，所以暂时不改变规则结构
        return ["innerHTML"]
