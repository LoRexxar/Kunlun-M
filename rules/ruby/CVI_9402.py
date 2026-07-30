# -*- coding: utf-8 -*-

"""
    Ruby SQL注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9402(SingleRuleMixin):
    """
    Ruby SQL注入规则
    匹配 ActiveRecord 的 execute、find_by_sql、where(字符串插值)、delete_all、update_all 等
    """

    def __init__(self):
        self.svid = 9402
        self.language = "ruby"
        self.vulnerability = "SQL注入"
        self.description = "使用了可能存在SQL注入风险的ActiveRecord数据库操作函数（execute、find_by_sql、where字符串插值、delete_all、update_all等），且参数可能受用户控制。攻击者可注入恶意SQL语句获取、修改或删除数据库数据。建议使用参数化查询（如 where('name = ?', params[:name])）替代字符串插值。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.execute\s*\(|find_by_sql\s*\(|\.where\s*\(.*#\{|delete_all\s*\(|update_all\s*\("

        self.vul_function = ["execute", "find_by_sql", "delete_all", "update_all"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯字符串字面量的情况。
        如果参数是纯硬编码字符串且不包含字符串插值，返回 False（安全）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(r'(?:execute|find_by_sql|delete_all|update_all)\s*\((.*)\)', regex_string, re.DOTALL)
        where_match = re.search(r'\.where\s*\((.*)\)', regex_string, re.DOTALL)

        args = None
        if match:
            args = match.group(1).strip()
        elif where_match:
            args = where_match.group(1).strip()

        if args is None:
            return None

        # 如果参数为空，排除
        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量且不包含字符串插值，排除
        if re.match(r'^["\'][^"\']*["\']$', args) and '#{}' not in args:
            return False

        # 如果是纯字符串字面量（不包含插值），排除
        if re.match(r'^["\'].*["\']$', args) and '#{' not in args:
            return False

        # 确认包含危险的SQL操作调用
        dangerous_patterns = [
            r"\.execute\s*\(",
            r"find_by_sql\s*\(",
            r"\.where\s*\(.*#\{",
            r"delete_all\s*\(",
            r"update_all\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
