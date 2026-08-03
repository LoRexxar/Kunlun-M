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
        #
        # MyBatis SQL 注入的真正风险点是 ${} 拼接，而不是方法名。
        # selectByExample/countByExample/deleteByExample 等方法底层使用 #{}
        # 参数化查询，方法名本身不可能注入——将它们作为 sink 只会产生大量误报。
        # 真正危险的 sink：
        #   1. setOrderByClause(userInput) — Example.orderByClause 走 ${} 拼接
        #   2. MyBatis-Plus Wrapper.apply(userInput) / .last(userInput) — 直接拼 SQL 片段
        #   3. .orderBy(userInput) — QueryWrapper orderBy 拼接
        self.match = r"setOrderByClause|\.apply\(|\.last\(|\.orderBy\("

        self.unmatch = []

        # 图引擎需要追踪的 sink 函数
        self.vul_function = [
            # MyBatis Generator Example — orderByClause 走 ${} 拼接
            "setOrderByClause",
            # MyBatis-Plus Wrapper — 直接拼 SQL 片段
            "apply",
            "last",
        ]

    def main(self, regex_string, sink_args=None):
        """二次筛选：排除明显的框架内部调用。

        主要排除：
        - import 语句
        - 注释行
        - 方法声明（非调用）
        - BiFunction.apply() 等 Java 泛型方法（非 MyBatis-Plus Wrapper.apply）

        注意：不在 sink_args 中做 resolved_value 过滤。
        DFG 追溯可能将 request.getParameter("name") 中的参数名 "name"
        误认为变量的 resolved_value，导致真正的用户输入被当作常量跳过。
        图引擎 BFS 已做了充分的污点追踪，这里不再二次过滤。
        """
        if sink_args is None:
            # Non-graph path (source code regex matching)
            pass
        else:
            # Graph path: only filter out true string literals
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # Only skip if arg is a direct string literal, not a variable
                # whose resolved_value was traced through DFG.
                if arg0.get('label') == 'const':
                    return False
            # Check main_input (source line) for non-MyBatis apply patterns.
            # BiFunction.apply() / Function.apply() / custom class apply()
            # are not SQL injection points.
            code = str(regex_string).strip() if regex_string else ''
            sn_lower = code.lower()
            if 'apply' in sn_lower:
                if re.search(r'function\s*<.*>.*\.apply\s*\(|BiFunction.*\.apply\s*\(', code):
                    return False
                # redaction.apply / configDotXml.apply etc — custom class apply
                if re.search(r'\b(redaction|config|callback|handler|processor|consumer|provider|supplier|factory)\b.*\.apply\s*\(', code, re.I):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        code = regex_string.strip()

        # 排除 import 语句
        if code.startswith("import "):
            return False

        # setOrderByClause 是关键的 ${} 控制点
        if re.search(r'setOrderByClause\s*\(', code):
            return None

        # MyBatis-Plus Wrapper apply/last/orderBy
        if re.search(r'\.(apply|last|orderBy)\s*\(', code):
            # 排除 java.util.function.BiFunction.apply() / Function.apply()
            # 等非 MyBatis-Plus 的 apply 调用。
            # MyBatis-Plus 的 apply 出现在 QueryWrapper/LambdaQueryWrapper 链上，
            # 而泛型 apply 的 receiver 是 function/BiFunction 类型。
            if re.search(r'function\s*<.*>\s*.*\.apply\s*\(|BiFunction.*\.apply\s*\(', code):
                return False
            return None

        return False
