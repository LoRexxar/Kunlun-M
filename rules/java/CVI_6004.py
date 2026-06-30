# -*- coding: utf-8 -*-

"""
    Java Path Traversal Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6004(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6004
        self.language = "java"
        self.vulnerability = "Path Traversal"
        self.description = "通过AST分析检测File/FileInputStream等文件操作构造函数参数是否来自用户可控输入，追踪数据流以发现路径遍历漏洞。建议对文件路径进行normalize和getCanonicalPath校验。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"new\s+File\(|new\s+FileInputStream\(|new\s+FileOutputStream\(|new\s+FileReader\(|new\s+FileWriter\(|Files\.readAllBytes\(|Files\.readAllLines\(|Files\.lines\(|Files\.write\(|Files\.copy\(|Files\.move\(|new\s+RandomAccessFile\("

        # for regex
        self.unmatch = [r"normalize\(\)", r"getCanonicalPath"]

        self.vul_function = ["File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
                              "Files.readAllBytes", "Files.readAllLines", "Files.lines",
                              "Files.write", "Files.copy", "Files.move",
                              "RandomAccessFile"]

    def main(self, regex_string):
        """File 等构造函数已足够精确，不需要额外筛选"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除明显的安全写法
        if re.search(r'normalize\(\)|getCanonicalPath', regex_string):
            return False
        return None

