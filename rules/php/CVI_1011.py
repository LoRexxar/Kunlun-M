# -*- coding: utf-8 -*-

"""
    CVI-1011
    ~~~~

    Remote command execute

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""


class CVI_1011():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1011
        self.language = "PHP"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "Remote command execute"

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "(system|passthru|exec|pcntl_exec|shell_exec|popen|proc_open|ob_start|expect_popen|mb_send_mail|w32api_register_function|w32api_invoke_function|ssh2_exec)"
        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
