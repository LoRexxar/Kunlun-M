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


class CVI_5003():
    """
    rule class
    """

    def __init__(self):
        self.svid = 5003
        self.language = "base"
        self.author = "LoRexxar"
        self.vulnerability = "配置文件泄露"
        self.description = "项目中的配置文件应该通过更安全的方式引入而不是直接暴露在代码仓库中。"
        self.level = 4

        # status
        self.status = True

        # 部分配置
        self.match_mode = "file-path-regex-match"
        self.match = ['settings.py', 'config.yaml', 'config.php']

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
