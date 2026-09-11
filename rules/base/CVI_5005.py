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

class CVI_5005(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 5005
        self.language = "base"
        self.vulnerability = "密码文件泄露"
        self.description = "密码文件不应该被放在项目代码当中。"
        self.level = 7

        self.match_mode = "file-pattern"
        self.file_pattern = r'(pass|password)\.txt$'
        self.match = None
        self.vul_function = []

        self.unmatch = []

    def main(self, regex_string, sink_args=None):
        pass
