# -*- coding: utf-8 -*-

"""
    Java Unrestricted File Upload Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

import re

from utils.api import *

class CVI_6069(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6069
        self.language = "java"
        self.vulnerability = "Unrestricted File Upload"
        self.description = "通过AST分析检测Part.write()/MultipartFile.write()/getSubmittedFileName()/transferTo()等文件上传sink的参数是否来自用户可控输入，追踪数据流以发现不安全文件上传漏洞。建议对上传文件名进行白名单校验、限制上传目录、检查文件内容和扩展名。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"write\(|getSubmittedFileName\(|transferTo\(|getOriginalFilename\("

        # for regex
        self.unmatch = [
            r"normalize\(\)",
            r"getCanonicalPath",
            r"whitelist",
            r"ALLOWED_EXTENSIONS",
            r"allowedExtensions",
        ]

        self.vul_function = [

            "Part.write",

            "Part.getSubmittedFileName",

            "MultipartFile.transferTo",

            "MultipartFile.getOriginalFilename",

        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: const filename/path is hardcoded (safe).
        """
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
        safe_patterns = [
            r"normalize\(\)", r"getCanonicalPath",
            r"whitelist", r"ALLOWED_EXTENSIONS", r"allowedExtensions",
        ]
        for safe_pat in safe_patterns:
            if re.search(safe_pat, regex_string):
                return False
        upload_patterns = [
            r"\.write\s*\(", r"\.getSubmittedFileName\s*\(",
            r"\.transferTo\s*\(", r"\.getOriginalFilename\s*\(",
        ]
        for pat in upload_patterns:
            if re.search(pat, regex_string):
                return True
        return None
