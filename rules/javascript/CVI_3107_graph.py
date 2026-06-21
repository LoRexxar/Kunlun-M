# -*- coding: utf-8 -*-

"""
    Graph engine rule for XXE
    ~~~~
    Covers: parseString, parseXml, parseHtml, parseXmlString
"""

from utils.api import *


class CVI_3107_graph():
    """
    Graph engine rule: XXE via XML parsing functions
    """

    def __init__(self):
        self.svid = 3107
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "XXE"
        self.description = "使用了XML解析函数（xml2js.parseString、libxmljs.parseXml等），如果解析了不受信任的XML数据且未禁用外部实体，可能导致XXE攻击。建议配置XML解析器禁用外部实体引用。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"parseString|parseXml|parseHtml|parseXmlString"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["parseString", "parseXml", "parseHtml", "parseXmlString"]

    def main(self, regex_string):
        pass
