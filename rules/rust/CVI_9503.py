# -*- coding: utf-8 -*-

"""
    Rust SQL注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9503(SingleRuleMixin):
    """
    Rust SQL注入规则
    匹配 execute, query, execute_async, query_async 等 SQL 执行调用
    （适用于 sqlx、tokio-postgres、diesel 等数据库 crate）。
    normalizer 中 sink callee name 为方法名（如 execute, query 等）。
    """

    def __init__(self):
        self.svid = 9503
        self.language = "rust"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能执行SQL语句的函数（execute、query、execute_async、query_async等），可能导致SQL注入漏洞。建议使用参数化查询（prepared statement）替代字符串拼接SQL。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        # 匹配 sqlx / tokio-postgres / diesel 的常见 SQL 执行方法
        self.match = (
            r"\bexecute\s*\("
            r"|\bquery\s*\("
            r"|\bexecute_async\s*\("
            r"|\bquery_async\s*\("
            r"|\bquery_one\s*\("
            r"|\bquery_optional\s*\("
            r"|\bexecute_unchecked\s*\("
        )

        self.vul_function = [
            "execute", "query", "execute_async", "query_async",
            "query_one", "query_optional", "execute_unchecked",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的SQL执行调用，
        排除纯硬编码SQL参数和明显的非数据库调用。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除明显的非数据库 execute/query 调用
        non_db_patterns = [
            r"std::process::Command.*\.execute",  # Command::new(...).execute() 不是 SQL
            r"\.spawn\s*\(",                       # 进程 spawn
            r"Option::execute",                    # Option 方法
        ]
        for pat in non_db_patterns:
            if re.search(pat, regex_string):
                return False

        # 提取函数调用参数部分
        match = re.search(
            r'(?:execute|query|execute_async|query_async|query_one|query_optional|execute_unchecked)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（硬编码SQL）
        # query("SELECT * FROM users")
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 检查是否为 .sqlx_query / client.execute 等数据库调用模式
        db_context_patterns = [
            r"\.execute\s*\(",
            r"\.query\s*\(",
            r"\.query_one\s*\(",
            r"\.query_optional\s*\(",
            r"\.execute_async\s*\(",
            r"\.query_async\s*\(",
            r"sqlx::",
            r"pg_?client",
            r"connection",
            r"pool",
        ]
        for pat in db_context_patterns:
            if re.search(pat, regex_string):
                return True

        # 没有明确数据库上下文时返回 None（不确定）
        return None
