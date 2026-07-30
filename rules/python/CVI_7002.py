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
        二次筛选：检测参数化查询和安全的ORM用法

        安全模式 (return False):
        - cursor.execute("SELECT ... WHERE id=%s", [user_id])  参数化
        - cursor.execute("SELECT ... WHERE id=%s", (user_id,))  元组参数化
        - cursor.execute(query, params)  有第二参数

        危险模式 (return None -> 继续分析):
        - cursor.execute("SELECT ... WHERE id=" + user_id)  字符串拼接
        - cursor.execute(query)  单参数，query可能拼接了用户输入
        - User.objects.raw("SELECT ... WHERE id='%s'" % username)  格式化字符串
        """
        if not regex_string:
            return None

        # 检测 cursor.execute/conn.execute 等是否有第二参数(参数化查询)
        execute_match = re.search(
            r'(?:cursor|connection|conn|session|engine|db)\.execute\s*\((.+)', regex_string, re.I)
        if execute_match:
            args_str = execute_match.group(1).strip()
            # 检查是否有逗号分隔的第二参数（参数化查询）
            # cursor.execute("SELECT ... %s", [var]) 或 cursor.execute("...", (var,))
            # 但要排除: cursor.execute("SELECT " + var) 这种字符串拼接只有一个参数的情况
            depth = 0
            for i, ch in enumerate(args_str):
                if ch in '([{':
                    depth += 1
                elif ch in ')]}':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    # 找到顶层逗号 → 有第二参数 → 参数化查询
                    # 但需要确认第二参数不是 None
                    second_arg = args_str[i+1:].strip()
                    if second_arg and second_arg != 'None':
                        return False

        # 检测 Django .raw() 是否使用格式化/拼接
        raw_match = re.search(r'\.raw\s*\((.+)\)', regex_string, re.I)
        if raw_match:
            raw_arg = raw_match.group(1).strip()
            # 检查是否有字符串拼接或格式化 (%s + 变量, f-string)
            if '%' in raw_arg and not re.search(r'%s.*\[', raw_arg):
                # % 格式化但不是参数化 → 危险
                return None
            if '+' in raw_arg and not raw_arg.startswith('"') and not raw_arg.startswith("'"):
                # 变量拼接 → 危险
                return None

        return None
