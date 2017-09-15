# -*- coding: utf-8 -*-

"""
    CVI-1000
    ~~~~

    Reflected XSS

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from cobra.file import file_grep


class CVI_1001():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1000
        self.language = "PHP"
        self.author = "LoRexxxar"
        self.vulnerability = "SSRF"
        self.description = "cURL SSRF(description for vulnerabilty)"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "regex-param-controllable"
        self.match = "curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)"

    def main(self, target_file):
        """
        regular for Sensitivity Function
        :return: 
        """
        return file_grep(target_file, self.regexp)
