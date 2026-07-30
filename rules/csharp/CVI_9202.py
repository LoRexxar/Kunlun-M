# -*- coding: utf-8 -*-

"""
    C# SQL注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9202(SingleRuleMixin):
    """
    C# SQL注入规则
    匹配 SqlCommand.CommandText 属性赋值、ExecuteReader、ExecuteNonQuery、ExecuteScalar 等数据库操作
    注意：CommandText 是属性赋值（=），不是方法调用
    """

    def __init__(self):
        self.svid = 9202
        self.language = "csharp"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的数据库操作（SqlCommand.CommandText属性赋值、ExecuteReader、ExecuteNonQuery、ExecuteScalar等），且参数可能受用户控制。攻击者可注入恶意SQL语句获取、修改或删除数据库数据。建议使用参数化查询（如 SqlCommand.Parameters.AddWithValue）替代字符串拼接。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.CommandText\s*=|\.ExecuteReader\s*\(|\.ExecuteNonQuery\s*\(|\.ExecuteScalar\s*\("

        self.vul_function = ["CommandText", "ExecuteReader", "ExecuteNonQuery", "ExecuteScalar"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的SQL操作。
        排除 CommandText 赋值为纯硬编码字符串字面量的情况。
        """
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

        # 检查 CommandText 属性赋值
        cmdtext_match = re.search(r'\.CommandText\s*=\s*(.*)', regex_string)
        # 检查 Execute 方法调用
        exec_match = re.search(r'(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\((.*)\)', regex_string, re.DOTALL)

        if cmdtext_match:
            rhs = cmdtext_match.group(1).strip()
            # 如果 CommandText 赋值右侧是纯硬编码字符串字面量，排除
            if re.match(r'^"[^"]*"$', rhs) or re.match(r'^@"[^"]*"$', rhs):
                return False
            return True

        if exec_match:
            return True

        return None
