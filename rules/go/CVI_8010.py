# -*- coding: utf-8 -*-

"""
    Go XXE规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_8010(SingleRuleMixin):
    """
    Go XXE规则
    匹配 encoding/xml 的 Unmarshal / NewDecoder 等
    """

    def __init__(self):
        self.svid = 8010
        self.language = "go"
        self.vulnerability = "XXE"
        self.description = "使用了XML解析函数（xml.Unmarshal、xml.NewDecoder等）解析外部输入，可能导致XXE（XML外部实体注入）漏洞。建议设置 xml.Decoder 的 Strict 为 true，并禁用外部实体解析（通过自定义 Entity 字段或使用 io.LimitReader 限制输入大小）。"
        self.level = 7

        self.match_mode = "function-param-regex"
        self.match = r"encoding/xml.*Unmarshal|xml\.Unmarshal|xml\.NewDecoder|xml\.Decoder"

        self.vul_function = ["xml.Unmarshal", "xml.NewDecoder", "xml.Decoder.Token"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查是否存在XML解析调用，且未设置安全选项（Strict、AutoClose等）。
        如果有安全配置包裹则返回 False，否则返回 True。
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 检查是否有安全配置包裹
        safe_patterns = [
            r'\.Strict\s*=\s*true',
            r'\.AutoClose\s*=',
            r'\.Entity\s*=',
        ]
        for pat in safe_patterns:
            if re.search(pat, regex_string):
                return False

        # 检查是否调用了危险的XML解析函数
        dangerous_patterns = [
            r'xml\.Unmarshal\s*\(',
            r'xml\.NewDecoder\s*\(',
            r'\.Token\s*\(',
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
