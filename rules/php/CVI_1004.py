# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *


class CVI_1004():
    """
    rule class
    """

    def __init__(self):

        self.svid = 1004
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SQLI"
        self.description = "SQL injection, 用户输入直接被拼接进Sql语句当中，有可能造成SQL注入漏洞。"
        self.level = 9

        # status
        self.status = True

        # 部分配置
        self.match_mode = "vustomize-match"
        # 兼容无分号的写法（例如某些模板/拼接场景），末尾分号改为可选
        self.match = r"([\"']+\s*(select|SELECT|insert|INSERT|update|UPDATE)\s+([^;]\s*)(.*)\$(.+?)['\"]+(.+?)?;?)"

        # for solidity
        self.match_name = None
        self.black_list = None

        # for chrome ext
        self.keyword = None

        # for regex
        self.unmatch = None

        self.vul_function = None

    def main(self, regex_string):
        """
        regex string input
        just for sql statements
        :return: 
        """
        sql_sen = regex_string[0][0]

        # 先定位 SQL 关键字，再向后截取“当前语句”的片段（到首个非字符串内分号为止）
        # 这样既能避免把 else 分支等后续代码误算进来，也能保留字符串拼接中的变量。
        # 例如：
        #   "SELECT ..." . $where . " ORDER BY " . $order . ";"
        # 会保留 $where/$order；而不会误带上后续语句中的 $plan 等变量。
        sql_start_match = re.search(r"(select|insert|update)\b", sql_sen, re.I)
        if sql_start_match:
            start = sql_start_match.start()
            quote_start = max(sql_sen.rfind('"', 0, start), sql_sen.rfind("'", 0, start))
            if quote_start != -1:
                start = quote_start
            sql_sen = sql_sen[start:]

            quote = None
            escaped = False
            stmt_end = None

            for index, char in enumerate(sql_sen):
                if quote:
                    if escaped:
                        escaped = False
                        continue
                    if char == '\\':
                        escaped = True
                        continue
                    if char == quote:
                        quote = None
                    continue

                if char in ("'", '"'):
                    quote = char
                    continue

                if char == ';':
                    stmt_end = index + 1
                    break

                # fallback: 没有分号时，遇到明显的语句边界也结束
                if sql_sen.startswith('} else', index) or sql_sen.startswith(' else ', index):
                    stmt_end = index
                    break
                if sql_sen.startswith('?>', index):
                    stmt_end = index
                    break

            if stmt_end is not None:
                sql_sen = sql_sen[:stmt_end]

        reg = r"\$\w+"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
