# -*- coding: utf-8 -*-

"""
    Node.js XXE 规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3107(SingleRuleMixin):
    """
    Node.js XXE/XML 注入规则
    匹配 xml2js.parseString、libxmljs.parseXml、fastXmlParser.parse 等XML解析
    """

    def __init__(self):
        self.svid = 3107
        self.language = "javascript"
        self.vulnerability = "XXE"
        self.description = "使用了XML解析函数（xml2js.parseString、libxmljs.parseXml等），如果解析了不受信任的XML数据且未禁用外部实体，可能导致XXE攻击。建议配置XML解析器禁用外部实体引用。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"parseString\s*\(|parseXml\s*\(|parseHtml\s*\(|parseXmlString\s*\("

        self.vul_function = [
            "parseString", "parseXml", "parseHtml", "parseXmlString",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：确认是 XML 解析相关调用
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        if re.search(r'(?:parseString|parseXml|parseHtml|parseXmlString)\s*\(', regex_string):
            return True

        return None
