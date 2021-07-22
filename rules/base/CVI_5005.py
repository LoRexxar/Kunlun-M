#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: CVI_5005.py
@time: 2021/7/16 17:57
@desc:

'''

from utils.api import *


class CVI_5005():
    """
    rule class
    """

    def __init__(self):
        self.svid = 5005
        self.language = "base"
        self.author = "LoRexxar"
        self.vulnerability = "密码文件泄露"
        self.description = "密码文件不应该被放在项目代码当中。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "file-path-regex-match"
        self.match = ['pass.txt', 'password.txt']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = []

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
