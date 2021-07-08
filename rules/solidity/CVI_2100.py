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


class CVI_2100():
    """
    rule class
    """

    def __init__(self):

        self.svid = 2100
        self.language = "solidity"
        self.author = "Sissel"
        self.vulnerability = "address(0)"
        self.description = "含参数包含地址的函数开始处，应增加地址是否为0的校验，防止用户操作失误。"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "regex-return-regex"
        self.match = []

        # for solidity
        self.match_name = r"(\bfunction\s+[^\n]*?\(.*?address\s+([^, )]*)[^\n\r]*)"
        self.black_list = ['balanceOf', ';', '[]']

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = ['\\b(if|require)\\s*\\(=padding=\\s!=\\s(address\\(0\\)|0x0)\\)']

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
