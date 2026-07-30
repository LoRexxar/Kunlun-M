# -*- coding: utf-8 -*-

"""
    Java Insecure File Upload Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6011(SingleRuleMixin):
    def __init__(self):
        self.svid = 6011
        self.language = "java"
        self.vulnerability = "Insecure File Upload"
        self.description = "用户可控的文件上传可能导致恶意文件上传攻击"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = r"transferTo\s*\(|\.getOriginalFilename\(\)|MultipartFile|\.transferTo\s*\("
        self.unmatch = [r"isValidExtension", r"checkFileType", r"MimeTypeUtils"]
        self.vul_function = ["MultipartFile.transferTo", "MultipartFile.getOriginalFilename", "MultipartFile.write"]

    def main(self, regex_string, sink_args=None):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有扩展名白名单校验的写法
        if re.search(r"ALLOWED_EXTENSIONS|allowedExtensions|isValidExtension|checkFileType|ImageIO\.read|MimeTypeUtils", regex_string, re.I):
            return False
        return None

