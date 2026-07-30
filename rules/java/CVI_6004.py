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

        self.vul_function = [
            # 构造函数: 图引擎中callee是短名(无use edge), 保持短名
            "File",
            "FileInputStream",
            "FileOutputStream",
            "FileReader",
            "FileWriter",
            # 静态方法: Files.xxx 是限定类名的半fullname
            "Files.readAllBytes",
            "Files.readAllLines",
            "Files.lines",
            "Files.write",
            "Files.copy",
            "Files.move",
            "RandomAccessFile",
            "File.delete",
        ]

    def main(self, regex_string, sink_args=None):
        """Graph-based: const path arg is hardcoded (safe)."""
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r'normalize\(\)|getCanonicalPath', regex_string):
            return False
        return None

