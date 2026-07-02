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

class CVI_5004(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 5004
        self.language = "base"
        self.vulnerability = "git/svn文件泄露"
        self.description = "要检查开源项目的git/svn文件是否存在内网敏感信息"
        self.level = 2

        self.match_mode = "file-pattern"
        self.file_pattern = r'\.git/config$'
        self.match = None
        self.vul_function = []

        self.unmatch = []

    def main(self, regex_string):
        pass
