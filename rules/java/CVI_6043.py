# -*- coding: utf-8 -*-
from utils.api import *

class CVI_6043(SingleRuleMixin):
    """
    JdbcTemplate SQL Injection — 检测 Spring JdbcTemplate 的 query/queryForObject/execute/update 
    方法参数是否来自用户可控输入的字符串拼接 SQL
    """
    def __init__(self):
        self.svid = 6043
        self.language = "java"
        self.vulnerability = "JdbcTemplate SQL Injection"
        self.description = "检测Spring JdbcTemplate的query/queryForObject等方法参数是否为用户可控的拼接SQL"
        self.level = 9
        self.match_mode = "function-param-regex"
        # 精确匹配 JdbcTemplate 方法名（避免匹配其他 query 调用）
        self.match = r"jdbcTemplate\.query\b|jdbcTemplate\.queryForObject|jdbcTemplate\.queryForList|jdbcTemplate\.queryForMap|jdbcTemplate\.queryForRowSet|jdbcTemplate\.execute\b|jdbcTemplate\.update\b"
        self.unmatch = []
        self.black_list = []
        # AST 搜索 sink 函数名
        self.vul_function = [
            "JdbcTemplate.query",
            "JdbcTemplate.queryForObject",
            "JdbcTemplate.queryForList",
            "JdbcTemplate.queryForMap",
            "JdbcTemplate.queryForRowSet",
            "JdbcTemplate.execute",
            "JdbcTemplate.update",
            "NamedParameterJdbcTemplate.query",
            "NamedParameterJdbcTemplate.queryForObject",
            "NamedParameterJdbcTemplate.queryForList",
            "NamedParameterJdbcTemplate.queryForMap",
            "NamedParameterJdbcTemplate.execute",
            "NamedParameterJdbcTemplate.update",
        ]

    def main(self, regex_string, sink_args=None):
        """二次筛选：确认是 JdbcTemplate 调用上下文"""
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 确认代码行包含 JdbcTemplate 相关调用
        if re.search(r'jdbcTemplate|JdbcTemplate', regex_string, re.I):
            return True
        # query/queryForObject 如果直接出现在代码行中也保留
        if re.search(r'\.query\(|\.queryForObject\(|\.queryForList\(|\.queryForMap\(|\.queryForRowSet\(', regex_string):
            return None  # 让 AST 分析判断
        return False
