# -*- coding: utf-8 -*-

"""
    Kotlin SQL注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9301(SingleRuleMixin):
    """
    Kotlin SQL注入规则
    匹配 executeQuery, executeUpdate, execute, rawQuery, query 等
    覆盖 JDBC、Android Room、JetBrains Exposed 等 ORM/查询框架
    """

    def __init__(self):
        self.svid = 9301
        self.language = "kotlin"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能执行SQL查询的函数（executeQuery、executeUpdate、execute、rawQuery、query等），当查询参数来自用户输入且未经参数化处理时，可能导致SQL注入漏洞。建议使用预编译语句(PreparedStatement)或ORM框架的参数绑定机制。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"executeQuery\s*\(|executeUpdate\s*\(|\.execute\s*\(|rawQuery\s*\(|\.query\s*\(|execSQL\s*\("

        self.vul_function = [
            "executeQuery", "executeUpdate", "execute", "rawQuery",
            "query", "execSQL",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除使用了预编译语句或参数化查询的安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 安全写法：使用了预编译语句的 setString/setInt 等参数绑定
        if re.search(r'(?:setString|setInt|setLong|setFloat|setDouble|setBoolean|setObject|setNull|bindString|bindLong|bindArgument|bind\()\s*\(', regex_string):
            return False

        # 安全写法：Android Room 的 @Query 使用了 :param 参数绑定
        if re.search(r'@\s*Query\s*\(\s*"[^"]*:[\w]+', regex_string):
            return False

        # 安全写法：Exposed 框架使用参数化查询
        if re.search(r'\{\s*\w+\s*\}', regex_string):
            return False

        # 提取函数调用参数部分
        match = re.search(r'(?:executeQuery|executeUpdate|\.execute|rawQuery|\.query|execSQL)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 字符串拼接（+ 或字符串模板 $）— 必须在纯字面量检查之前
        if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
            return True

        # 纯字符串字面量（硬编码SQL）
        if re.match(r'^"[^"]*"$', args):
            return False

        # 包含变量作为参数
        if re.search(r'(?:executeQuery|executeUpdate|\.execute|rawQuery|\.query|execSQL)\s*\(\s*\w+', regex_string):
            return True

        return None
