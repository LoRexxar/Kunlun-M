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


class CVI_1001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1001
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "cURL SSRF"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        self.match = r"curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        just for curl
        :return: 
        """
        sql_sen = regex_string[0]
        reg = "\$[\w+\->]*"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
