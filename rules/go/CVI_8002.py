# -*- coding: utf-8 -*-

"""
    Go SQL 注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8002(SingleRuleMixin):
    """
    Go SQL 注入规则
    匹配 db.Query/db.Exec/db.QueryRow/db.Prepare/tx.Exec/gorm.DB.Raw/gorm.DB.Where 等
    """

    def __init__(self):
        self.svid = 8002
        self.language = "go"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的数据库操作函数（db.Query、db.Exec、db.QueryRow、gorm.DB.Raw、gorm.DB.Where等），建议使用参数化查询（占位符?）替代字符串拼接。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.Query\s*\(|\.Exec\s*\(|\.QueryRow\s*\(|\.Prepare\s*\(|\.Raw\s*\(|\.Where\s*\(|\.Select\s*\(|\.Having\s*\("

        # for regex
        self.unmatch = [
            r"sql\.Named\(",
            r"\?\s*[,\"]",
            r"\$\d+",
        ]

        self.vul_function = [
            "db.Query", "db.Exec", "db.QueryRow", "db.Prepare",
            "tx.Exec", "tx.Query", "tx.QueryRow", "tx.Prepare",
            "gorm.DB.Raw", "gorm.DB.Where", "gorm.DB.Select", "gorm.DB.Having",
        ]

    def main(self, regex_string):
        """
        二次筛选：检查是否为参数化查询（占位符?或$1）。
        如果包含参数化查询特征，返回 False（安全）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 检查 unmatch 规则（参数化查询特征）
        for pattern in self.unmatch:
            if re.search(pattern, regex_string):
                return False
        if re.search(r'\.(Query|Exec|QueryRow|Raw|Where|Select|Having)\s*\(', regex_string):
            return True
        return None
