# -*- coding: utf-8 -*-

"""
    Java XXE Rule (AST-enhanced)
    ~~~~
    检测各种XML解析器未禁用外部实体导致的XML External Entity注入漏洞。
    覆盖: SAXParserFactory, XMLReaderFactory, SAXBuilder(JDOM2), SAXReader(DOM4J),
          DocumentHelper(DOM4J), DocumentBuilderFactory, TransformerFactory
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6070(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6070
        self.language = "java"
        self.vulnerability = "XXE"
        self.description = "通过AST分析检测各类XML解析器(SAXParserFactory/XMLReaderFactory/SAXBuilder/SAXReader/DocumentHelper/DocumentBuilderFactory/TransformerFactory)是否未禁用外部实体，追踪解析输入是否来自用户可控数据，以发现XXE漏洞。建议设置FEATURE_SECURE_PROCESSING、DISALLOW_DOCTYPE_DECL等安全特性。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"newSAXParser\s*\(|createXMLReader\s*\(|\.build\s*\(\s*new\s+StringReader|\.read\s*\(\s*new\s+StringReader|\.parseText\s*\(|\.parse\s*\(\s*new\s+InputSource|\.transform\s*\("

        # for regex
        self.unmatch = []

        self.vul_function = [

            "SAXParserFactory.newSAXParser",

            "XMLReaderFactory.createXMLReader",

            "groovy.xml.XmlSlurper.parseText",

            "SAXBuilder.build",

            "SAXReader.read",

            "DocumentBuilder.parse",

        ]

    def main(self, regex_string, sink_args=None):
        """二次筛选：排除已配置安全特性的XML解析器"""
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除已显式禁用外部实体的安全配置
        safe_features = [
            r"FEATURE_SECURE_PROCESSING",
            r"DISALLOW_DOCTYPE_DECL",
            r"EXTERNAL_GENERAL_ENTITIES.*false",
            r"EXTERNAL_PARAMETER_ENTITIES.*false",
            r"IS_SUPPORTING_EXTERNAL_ENTITIES.*false",
            r"setFeature.*external",
            r"setExpandEntityReferences.*false",
        ]
        for pat in safe_features:
            if re.search(pat, regex_string):
                return False
        return None
