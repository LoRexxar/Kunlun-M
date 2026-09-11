# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7002(SingleRuleMixin):
    """
    Python SQL 注入
    覆盖: cursor.execute, Django ORM raw/extra, SQLAlchemy, psycopg2 等
    """
    def __init__(self):
        self.svid = 7002
        self.language = "python"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的数据库操作函数"
        self.level = 7
        self.match_mode = "function-param-regex"
        self.match = r"cursor\.execute|connection\.execute|session\.execute|engine\.execute|db\.execute|\.raw\(|\.extra\(|RawSQL\(|cursor\.executemany|connection\.cursor|text\(|\.from_statement\("
        self.vul_function = ["execute", "cursor.execute", "raw", "extra"]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: detect parameterized queries.
        execute(sql, params) with 2+ args → safe (parameterized).
        """
        if sink_args:
            # 2+ args = parameterized query (second arg is params list/tuple)
            if len(sink_args) >= 2:
                return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        execute_match = re.search(
            r'(?:cursor|connection|conn|session|engine|db)\.execute\s*\((.+)', regex_string, re.I)
        if execute_match:
            args_str = execute_match.group(1).strip()
            depth = 0
            for i, ch in enumerate(args_str):
                if ch in '([{':
                    depth += 1
                elif ch in ')]}':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    second_arg = args_str[i+1:].strip()
                    if second_arg and second_arg != 'None':
                        return False
        return None
