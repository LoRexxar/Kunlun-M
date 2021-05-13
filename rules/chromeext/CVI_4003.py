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


class CVI_4003():
    """
    rule class
    """

    def __init__(self):

        self.svid = 4003
        self.language = "chromeext"
        self.author = "LoRexxar"
        self.vulnerability = "Manifest.json CSP Bypass"
        self.description = "Manifest.json CSP配置了不可信任的域导致可以被绕过"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "special-crx-keyword-match"
        self.match = ['ajax\\.googleapis\\.com', 'raw\\.githubusercontent\\.com', 'github\\.io', '\\*\\.s3\\.amazonaws\\.com', '\\*\\.cloudfront\\.com', '\\*\\.herokuapp\\.com', 'dl\\.dropboxusercontent\\.com', '\\*\\.appspot\\.com', '\\*\\.googleusercontent\\.com', 'cdn\\.jsdelivr\\.net', 'cdnjs\\.cloudflare\\.com', 'code\\.angularjs\\.org', 'd\\.yimg\\.com', 'www\\.linkedin\\.com', '\\*\\.wikipedia\\.org']

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = r"content-security-policy"

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
