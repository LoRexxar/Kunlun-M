# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7011(SingleRuleMixin):
    """
    Python XXE (XML 外部实体注入)
    覆盖: xml.etree.ElementTree, lxml, xmltodict, defusedxml
    """
    def __init__(self):
        self.svid = 7011
        self.language = "python"
        self.vulnerability = "XXE"
        self.description = "XML解析操作可能存在XXE外部实体注入风险"
        self.level = 7
        self.match_mode = "function-param-regex"
        self.match = r"xml\.etree\.ElementTree\.parse|xml\.etree\.ElementTree\.fromstring|ET\.parse|ET\.fromstring|lxml\.etree\.parse|lxml\.etree\.fromstring|etree\.parse|etree\.fromstring|xmltodict\.parse|minidom\.parse|xml\.sax\.parse|xml\.dom\.minidom\.parse"

    def main(self, regex_string, sink_args=None):
        pass
