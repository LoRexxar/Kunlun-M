# -*- coding: utf-8 -*-

"""
    Graph engine rule for unsafe deserialization
    ~~~~
    Covers: unserialize, deserialize
"""

from utils.api import *


class CVI_3105_graph():
    """
    Graph engine rule: unsafe deserialization
    """

    def __init__(self):
        self.svid = 3105
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "不安全反序列化"
        self.description = "使用了不安全的反序列化函数（unserialize、node-serialize的deserialize等），可能导致远程代码执行。建议使用JSON.parse等安全的序列化方式，避免反序列化不受信任的数据。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"unserialize|deserialize"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["unserialize", "deserialize"]

    def main(self, regex_string, sink_args=None):
        pass
