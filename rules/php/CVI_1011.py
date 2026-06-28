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

class CVI_1011(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1011
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "system这类函数参数可控可能会导致远程命令执行"
        self.level = 10

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(system|passthru|exec|pcntl_exec|shell_exec|popen|proc_open|expect_popen|mb_send_mail|w32api_register_function|w32api_invoke_function|ssh2_exec)"

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
