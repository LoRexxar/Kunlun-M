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

        # match: grep 正则，在源码中搜索潜在 sink 调用行
        # 之后图引擎对这些行做污点追踪，判断参数是否用户可控
        self.match = r"selectByExample|updateByExample|deleteByExample|countByExample|setOrderByClause|\.apply\(|\.last\(|\.orderBy\("

        self.unmatch = []

        # 图引擎需要追踪的 sink 函数
        self.vul_function = [
            # MyBatis Generator Example 方法
            "setOrderByClause",
            # MyBatis Mapper 方法
            "selectByExample",
            "updateByExample",
            "deleteByExample",
            "countByExample",
            # MyBatis-Plus Wrapper 方法
            "apply",
            "last",
        ]

    def main(self, regex_string, sink_args=None):
        """二次筛选：排除明显的框架内部调用。

        主要排除：
        - import 语句
        - 注释行
        - 方法声明（非调用）
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
