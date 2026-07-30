# -*- coding: utf-8 -*-

"""
    C/C++ SQL注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_9008(SingleRuleMixin):
    """
    C/C++ SQL注入规则
    匹配 sqlite3_exec、sqlite3_prepare、mysql_query、mysql_real_query、PQexec、PQexecParams 等
    SQL执行函数，检测是否存在SQL注入风险。
    """

    def __init__(self):
        self.svid = 9008
        self.language = "c"
        self.vulnerability = "SQL注入"
        self.description = "使用了SQL执行函数（sqlite3_exec、sqlite3_prepare、mysql_query、mysql_real_query、PQexec、PQexecParams等），且SQL语句参数可能受用户控制，可能导致SQL注入漏洞。攻击者可利用此漏洞读取、修改或删除数据库中的数据。建议使用参数化查询（prepared statement），避免直接拼接SQL语句。"
        self.level = 8

        self.match_mode = "function-param-regex"
        self.match = r"\bsqlite3_exec\s*\(|\bsqlite3_prepare\s*\(|\bmysql_query\s*\(|\bmysql_real_query\s*\(|\bPQexec\s*\(|\bPQexecParams\s*\("

        self.vul_function = ["sqlite3_exec", "sqlite3_prepare", "mysql_query", "mysql_real_query", "PQexec", "PQexecParams"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除SQL语句参数是硬编码字符串字面量的情况。
        对于sqlite3_exec，SQL语句是第2个参数；其余函数SQL语句通常是第1或第2个参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:sqlite3_exec|sqlite3_prepare|mysql_query|mysql_real_query|PQexec|PQexecParams)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()
        arg_parts = self._split_args(args)

        if not arg_parts:
            return None

        # sqlite3_exec(db, sql, callback, ...) — SQL是第2个参数
        # sqlite3_prepare(db, sql, ...) — SQL是第2个参数
        # mysql_query(conn, sql) — SQL是第2个参数
        # mysql_real_query(conn, sql, len) — SQL是第2个参数
        # PQexec(conn, sql) — SQL是第2个参数
        # PQexecParams(conn, sql, ...) — SQL是第2个参数
        if re.search(r'(?:sqlite3_exec|sqlite3_prepare|mysql_query|mysql_real_query|PQexec|PQexecParams)\s*\(', regex_string):
            if len(arg_parts) >= 2:
                sql_arg = arg_parts[1].strip()
            else:
                return None
        else:
            return None

        # 如果SQL语句参数是硬编码字符串字面量，排除
        if re.match(r'^\"[^\"]*\"$', sql_arg):
            return False

        # 确认包含危险的SQL执行调用
        dangerous_patterns = [
            r"sqlite3_exec\s*\(",
            r"sqlite3_prepare\s*\(",
            r"mysql_query\s*\(",
            r"mysql_real_query\s*\(",
            r"PQexec\s*\(",
            r"PQexecParams\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_string = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_string:
                in_string = True
                current.append(ch)
            elif ch == '"' and in_string:
                in_string = False
                current.append(ch)
            elif in_string:
                current.append(ch)
            elif ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args
