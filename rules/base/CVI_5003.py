# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

from utils.api import *

class CVI_5003(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 5003
        self.language = "base"
        self.vulnerability = "配置文件泄露"
        self.description = "项目中的配置文件应该通过更安全的方式引入而不是直接暴露在代码仓库中。"
        self.level = 4

        self.match_mode = "file-pattern"
        self.file_pattern = r'(settings\.py|config\.yaml|config\.php)$'
        self.match = None
        self.vul_function = []

        self.unmatch = []

    def main(self, regex_string, sink_args=None):
        pass
