# -*- coding: utf-8 -*-

"""
    Unrestricted File Upload
    ~~~~
    Detects move_uploaded_file where the destination path is user-controllable.
"""

from utils.api import *


class CVI_1016(SingleRuleMixin):
    """
    Unrestricted File Upload — move_uploaded_file 目标路径可控
    """

    def __init__(self):

        self.svid = 1016
        self.language = "php"
        self.author = "Kunlun-M"
        self.vulnerability = "Unrestricted File Upload"
        self.description = "move_uploaded_file的目标路径包含用户可控数据（如$_FILES['name']），可能导致任意文件上传。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"move_uploaded_file"

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
