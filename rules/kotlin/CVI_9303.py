# -*- coding: utf-8 -*-

"""
    Kotlin 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9303(SingleRuleMixin):
    """
    Kotlin 路径遍历规则
    匹配 File, FileInputStream, FileOutputStream, Files.readAllBytes, Files.write 等
    """

    def __init__(self):
        self.svid = 9303
        self.language = "kotlin"
        self.vulnerability = "路径遍历"
        self.description = "使用了文件操作函数（File、FileInputStream、FileOutputStream、Files.readAllBytes、Files.write等），当文件路径来自用户输入时，可能导致路径遍历漏洞。攻击者可通过构造包含../的路径访问任意文件。建议对路径进行规范化处理并校验是否在允许的目录范围内。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:java\.io\.)?File\s*\(\s*\w+|(?:java\.io\.)?FileInputStream\s*\(\s*\w+|(?:java\.io\.)?FileOutputStream\s*\(\s*\w+|Files\s*\.\s*readAllBytes\s*\(\s*\w+|Files\s*\.\s*write\s*\(\s*\w+|File\s*\(\s*\w+|FileInputStream\s*\(\s*\w+|FileOutputStream\s*\(\s*\w+|BufferedReader\s*\(\s*FileReader|FileReader\s*\(\s*\w+|FileWriter\s*\(\s*\w+|Scanner\s*\(\s*File"

        self.vul_function = [
            "File", "FileInputStream", "FileOutputStream",
            "Files.readAllBytes", "Files.write",
            "FileReader", "FileWriter", "BufferedReader",
            "Scanner",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查文件操作是否使用了用户可控的路径参数，
        排除硬编码路径的安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 安全写法：使用了路径规范化 canoicalPath
        if re.search(r'\.\s*canonicalPath\b', regex_string):
            return False

        # 安全写法：使用了 toAbsolutePath 且有路径校验
        if re.search(r'toAbsolutePath\s*\(\)\s*\.\s*startsWith', regex_string):
            return False

        # 检测 ../ 路径穿越模式
        if re.search(r'\.\./', regex_string):
            return True

        # 检测文件操作函数与变量拼接
        file_patterns = [
            r'File\s*\(',
            r'FileInputStream\s*\(',
            r'FileOutputStream\s*\(',
            r'FileReader\s*\(',
            r'FileWriter\s*\(',
            r'Files\s*\.\s*readAllBytes\s*\(',
            r'Files\s*\.\s*write\s*\(',
        ]
        for pat in file_patterns:
            if re.search(pat, regex_string):
                # 排除纯硬编码路径
                if re.search(r'File(?:Input|Output)?(?:Stream|Reader|Writer)?\s*\(\s*"[^"]*"', regex_string):
                    # 如果只有硬编码字符串，排除
                    if re.match(r'.*\bFile(?:Input|Output)?(?:Stream|Reader|Writer)?\s*\(\s*"[^"]*"\s*\)\s*;', regex_string.strip()):
                        return False
                # 字符串拼接或模板变量
                if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
                    return True
                # 变量作为路径参数
                if re.search(r'File(?:Input|Output)?(?:Stream|Reader|Writer)?\s*\(\s*\w+', regex_string):
                    return True
                if re.search(r'Files\s*\.\s*(?:readAllBytes|write)\s*\(\s*\w+', regex_string):
                    return True

        return None
