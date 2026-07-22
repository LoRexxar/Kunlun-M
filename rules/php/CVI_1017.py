# -*- coding: utf-8 -*-

"""
    PHP Path Traversal / Arbitrary File Operations
    ~~~~
    Detects file operation functions where the path argument is user-controllable.
    Covers: copy, rename, unlink, mkdir, rmdir, file_put_contents,
    file_get_contents, fopen, readfile, file, move_uploaded_file (superset of CVI_1016),
    touch, chmod, chown, chgrp, link, symlink.
"""

from utils.api import *


class CVI_1017(SingleRuleMixin):
    """
    PHP Path Traversal / Arbitrary File Operations
    """

    def __init__(self):

        self.svid = 1017
        self.language = "php"
        self.author = "Kunlun-M"
        self.vulnerability = "Path Traversal"
        self.description = "文件操作函数（copy/rename/unlink/mkdir/file_put_contents等）的路径参数包含用户可控数据，可能导致路径遍历或任意文件操作。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"copy\s*\(|rename\s*\(|unlink\s*\(|mkdir\s*\(|rmdir\s*\(|file_put_contents\s*\(|file_get_contents\s*\(|fopen\s*\(|readfile\s*\(|file\s*\(|touch\s*\(|chmod\s*\(|chown\s*\(|link\s*\(|symlink\s*\("
        self.vul_function = ["mkdir", "rmdir", "unlink", "rename", "copy", "file_put_contents", "fopen", "chmod", "chown", "chgrp"]

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
