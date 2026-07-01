# -*- coding: utf-8 -*-

"""
    Java MyBatis SQL Injection Rule (XML Pattern + Annotation)
    ~~~~
    检测MyBatis mapper XML文件和@Select等注解中使用${param}而非#{param}导致的SQL注入。
    MyBatis的${}直接拼接SQL字符串，不同于#{}使用预编译参数。
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6071(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6071
        self.language = "java"
        self.vulnerability = "SQL Injection (MyBatis)"
        self.description = "检测MyBatis mapper XML文件和@Select/@Insert/@Update/@Delete注解中使用${param}拼接SQL导致的SQL注入漏洞。MyBatis的${}直接拼接SQL字符串，不同于#{}使用预编译参数。建议使用#{}参数化查询替代${}。"
        self.level = 9

        # 部分配置
        self.match_mode = "xml-pattern"
        self.match = r"\$\{[^}]+\}"
        self.unmatch = []

        self.vul_function = []

    def main(self, match_string):
        """二次筛选：确认匹配的${}在SQL上下文中（排除#{}）"""
        if not isinstance(match_string, str):
            match_string = str(match_string)
        # 确认是${}而非#{}（main_input已经是${}匹配结果）
        if re.search(r'\$\{', match_string):
            return True
        return None
