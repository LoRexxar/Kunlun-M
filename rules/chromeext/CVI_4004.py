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

class CVI_4004(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 4004
        self.language = "chromeext"
        self.vulnerability = "Manifest.json permissions 要求权限过大"
        self.description = "Manifest.json permissions 要求权限过大"
        self.level = 3

        # 部分配置
        self.match_mode = "file-pattern"
        self.file_pattern = r"manifest.json$"
        self.match = ['bookmarks', 'history', 'topSites', 'tabs', 'webNavigation', 'contentSettings', 'debugger', 'pageCapture', 'proxy', 'devtools_page', 'http://\\*/\\*', 'https://\\*/\\*', '\\*://\\*/\\*', '<all_urls>', 'http://\\*/', 'https://\\*/', 'management', 'mdns', 'geolocation', 'clipboardRead', 'privacy', 'signedInDevices', 'ttsEngine']

        # for chrome ext
        self.keyword = r"permissions"

        # for regex
        self.unmatch = []

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
