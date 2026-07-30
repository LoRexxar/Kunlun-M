# -*- coding: utf-8 -*-

"""
    Java MyBatis SQL Injection Rule (Graph-Engine Enhanced)
    ~~~~
    检测 MyBatis 中用户可控数据流入 ${} 拼接导致的 SQL 注入。

    原理：MyBatis 的 ${} 直接拼接 SQL 字符串（不同于 #{} 预编译）。
    当 Mapper 方法被调用时，如果传入的 Example/Criteria 对象或 @Param 参数
    的值可以被用户控制，则构成 SQL 注入。

    检测方式：
      1. 通过图引擎污点追踪，检测用户输入是否到达 Mapper 方法的参数
      2. 关注 Mapper 接口中的 selectByExample/updateByExample/deleteByExample 等方法
      3. 关注 setOrderByClause 等 Example 方法的调用

    注意：本规则不再使用 file-pattern 纯正则模式。XML 中的 ${} 仍然存在，
    但只有当 Java 侧的用户输入能追溯到 Mapper 调用时才报告。

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
        self.description = "检测MyBatis中用户可控数据流入${}拼接导致的SQL注入。MyBatis的${}直接拼接SQL字符串，不同于#{}使用预编译参数。当Mapper方法的参数（如Example/Criteria对象）被用户输入控制时，构成SQL注入。"
        self.level = 9

        # 使用 function-param-regex 模式，走图引擎污点追踪
        self.match_mode = "function-param-regex"

        # 匹配 Mapper 接口中可能触发 ${} 拼接的方法调用
        # selectByExample / updateByExample / deleteByExample / countByExample
        # 这些方法接收 Example 参数，Example 内部的 orderByClause / criteria.condition
        # 会被 MyBatis 用 ${} 拼接进 SQL
        self.match = r"selectByExample|updateByExample|deleteByExample|countByExample|selectByExampleWithBLOBs|updateByExampleSelective|selectByExampleWithBLOBs"

        self.unmatch = []

        # 图引擎需要追踪的 sink 函数（限定到 Mapper 接口方法）
        # Example/Criteria 相关方法 — 这些 setter 控制 ${} 的值
        self.vul_function = [

            # MyBatis Generator Example 方法
            "setOrderByClause",
            "or",

            # MyBatis-Plus Wrapper 方法
            "apply",
            "last",
            "orderBy",

            # MyBatis @SelectProvider / @InsertProvider 等
            "@SelectProvider",
            "@InsertProvider",
            "@UpdateProvider",
            "@DeleteProvider",

        ]

    def main(self, regex_string):
        """二次筛选：排除明显的框架内部调用。

        主要排除：
        - import 语句
        - 注释行
        - 方法声明（非调用）
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        code = regex_string.strip()

        # 排除 import 语句
        if code.startswith("import "):
            return False

        # 排除方法声明（interface 中的方法定义不是调用）
        if re.search(r'(selectByExample|updateByExample|deleteByExample|countByExample)\s*\(', code):
            # 确认是方法调用而非定义 — 定义行不会在参数中有赋值
            if re.search(r'=\s*\w+\.(selectByExample|updateByExample|deleteByExample|countByExample)\s*\(', code):
                return None  # 调用：xxx.selectByExample(example)
            if re.search(r'\w+\.(selectByExample|updateByExample|deleteByExample|countByExample)\s*\(', code):
                return None  # 调用：mapper.selectByExample(example)

        # setOrderByClause 是关键的 ${} 控制点
        if re.search(r'setOrderByClause\s*\(', code):
            return None

        # MyBatis-Plus Wrapper apply/last/orderBy
        if re.search(r'\.(apply|last|orderBy)\s*\(', code):
            return None

        return False
