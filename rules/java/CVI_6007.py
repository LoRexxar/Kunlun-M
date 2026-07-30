# -*- coding: utf-8 -*-

"""
    Java XXE Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6007(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6007
        self.language = "java"
        self.vulnerability = "XXE"
        self.description = "通过AST分析检测DocumentBuilderFactory/SAXParserFactory/XMLInputFactory等XML解析器是否未禁用外部实体，追踪数据流以发现XXE漏洞。建议设置disallow-doctype-decl或FEATURE_SECURE_PROCESSING。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.parse\s*\(|newSAXParser|parseText|SAXParser|SAXBuilder|SAXReader|DocumentBuilder|XMLReader|Digester"

        # for regex
        self.unmatch = [
            r"setFeature.*disallow-doctype-decl",
            r"FEATURE_SECURE_PROCESSING",
            r"setExpandEntityReferences\(false\)",
        ]

        # vul_function 使用限定名（Class.method），配合引擎 receiver type resolution
        # 消除宽泛短名（如 "parse"）导致的误报
        self.vul_function = [
            "Unmarshaller.unmarshal",
            "DocumentBuilder.parse",
            "SAXParser.parse",
            "XMLReader.parse",
            "SAXBuilder.build",
            "SAXReader.read",
            "Digester.parse",
            "XMLInputFactory.createXMLStreamReader",
            "XMLInputFactory.createXMLEventReader",
        ]

    def main(self, regex_string, sink_args=None):
        """XML 解析器工厂名已足够精确，不需要额外筛选"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除已禁用外部实体的写法
        if re.search(r'FEATURE_SECURE_PROCESSING|disallow-doctype-decl|setExpandEntityReferences\(false\)', regex_string):
            return False
        return None

