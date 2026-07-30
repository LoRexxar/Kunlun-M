# -*- coding: utf-8 -*-

"""
    Graph engine rule for path traversal via fs functions
    ~~~~
    Covers: readFileSync, readFile, writeFileSync, writeFile, appendFileSync,
            appendFile, createReadStream, createWriteStream, openSync, open,
            unlinkSync, unlink, readdirSync, readdir, renameSync, rename
"""

from utils.api import *


class CVI_3101_graph():
    """
    Graph engine rule: path traversal via Node fs functions
    """

    def __init__(self):
        self.svid = 3101
        self.language = "javascript"
        self.author = "KunLun-M"
        self.vulnerability = "路径穿越"
        self.description = "使用了文件系统操作函数（fs.readFile、fs.writeFile、fs.readFileSync等）且路径参数可能受用户控制，可能导致路径穿越漏洞。建议对用户输入的路径进行规范化处理（path.resolve）并校验是否在允许的目录范围内。"
        self.level = 7

        # status
        self.status = True

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile|createReadStream|createWriteStream|openSync|open|unlinkSync|unlink|readdirSync|readdir|renameSync|rename"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = ["readFileSync", "readFile", "writeFileSync", "writeFile",
                             "appendFileSync", "appendFile", "createReadStream", "createWriteStream",
                             "openSync", "open", "unlinkSync", "unlink",
                             "readdirSync", "readdir", "renameSync", "rename"]

    def main(self, regex_string, sink_args=None):
        pass
