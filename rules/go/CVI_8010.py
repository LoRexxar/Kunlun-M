# -*- coding: utf-8 -*-

"""
    Go XXE规则
    ~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

import re
from utils.api import *


class CVI_8010(SingleRuleMixin):
    """
    Go XXE规则
    Go 的 encoding/xml 标准库不支持外部实体解析（没有 DTD 处理），
    因此 xml.Unmarshal / xml.NewDecoder 在 Go 中天然不受 XXE 影响。
    此规则仅在检测到非标准 XML 解析库（如 libxml2 Go binding）时报告。
    """

    def __init__(self):
        self.svid = 8010
        self.language = "go"
        self.vulnerability = "XXE"
        self.description = "使用了可能存在XXE风险的XML解析函数。Go标准库encoding/xml不受XXE影响，但第三方XML库（如基于libxml2的binding）可能存在风险。"
        self.level = 7

        self.match_mode = "function-param-regex"
        self.match = r"encoding/xml.*Unmarshal|xml\.Unmarshal|xml\.NewDecoder|xml\.Decoder"

        self.vul_function = ["xml.Unmarshal", "xml.NewDecoder", "xml.Decoder.Token"]

    def main(self, regex_string, sink_args=None):
        """
        Go encoding/xml is NOT vulnerable to XXE — the standard library
        does not process external entities or DTDs. Only report if a
        non-standard XML parser (e.g. libxml2 binding) is detected.
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # Go's encoding/xml is safe from XXE by design.
        # Only flag if using a non-standard XML library.
        # Standard library patterns are safe:
        safe_patterns = [
            r'encoding/xml',
            r'"xml"',
        ]
        is_stdlib = any(re.search(p, regex_string) for p in safe_patterns)

        # Non-standard XML parser (e.g. libxml2 Go bindings)
        dangerous_libs = [
            r'libxml2',
            r'github\.com/lestrrat-go/libxml2',
            r'github\.com/jbowtie/gokogiri',
        ]
        is_dangerous = any(re.search(p, regex_string) for p in dangerous_libs)

        if is_dangerous:
            return True

        # Standard library xml → safe from XXE
        return False
