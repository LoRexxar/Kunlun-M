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


class CVI_4001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 4001
        self.language = "chromeext"
        self.author = "LoRexxar"
        self.vulnerability = "Manifest.json all_frames不正确的配置"
        self.description = "Manifest.json all_frames为ture时允许攻击者从隐蔽的frame触发规则"
        self.level = 3

        # status
        self.status = True

        # 部分配置
        self.match_mode = "special-crx-keyword-match"
        self.match = ['true']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = r"content_scripts.*.all_frames"

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
