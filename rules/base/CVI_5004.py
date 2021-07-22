#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: CVI_5004.py
@time: 2021/7/16 17:47
@desc:

'''

from utils.api import *


class CVI_5004():
    """
    rule class
    """

    def __init__(self):
        self.svid = 5004
        self.language = "base"
        self.author = "LoRexxar"
        self.vulnerability = "git/svn文件泄露"
        self.description = "要检查开源项目的git/svn文件是否存在内网敏感信息"
        self.level = 2

        # status
        self.status = True

        # 部分配置
        self.match_mode = "file-path-regex-match"
        self.match = ['.git/config']

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
