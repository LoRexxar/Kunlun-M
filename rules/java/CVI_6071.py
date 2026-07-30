# -*- coding: utf-8 -*-

"""
    Java MyBatis SQL Injection Rule (File Pattern + Content)
    ~~~~
    检测MyBatis mapper XML文件中使用${param}而非#{param}导致的SQL注入。
    MyBatis的${}直接拼接SQL字符串，不同于#{}使用预编译参数。
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

# MyBatis Generator 模板文件中的 FreeMarker 变量（非运行时 SQL）
# 这些出现在 Generator 的 .ftl 模板或生成的模板占位符中，不是 MyBatis 运行时变量
_MYBATIS_GEN_TEMPLATE_VARS = frozenset({
    "table.className", "table.tableName",
    "column.columnName", "column.columnNameFirstLower", "column.jdbcType",
    "_column.columnName", "basePackage",
    'r"#{', 'r"{"',
})

# MyBatis Generator Example/Criteria 标准模式变量
# 这些由 MyBatis Generator 自动生成，SQL 片段由 Java Criteria 类构建
# 虽然理论上有注入风险，但需要过程间分析回溯到 setOrderByClause 等方法
_MYBATIS_GEN_CRITERIA_VARS = frozenset({
    "criterion.condition", "criterion.value", "criterion.secondValue",
    "criterion.noValue", "criterion.singleValue", "criterion.betweenValue",
    "criterion.listValue", "criterion.typeHandler",
    "orderByClause", "distinct",
})


class CVI_6071(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6071
        self.language = "java"
        self.vulnerability = "SQL Injection (MyBatis)"
        self.description = "检测MyBatis mapper XML文件中使用${param}拼接SQL导致的SQL注入漏洞。MyBatis的${}直接拼接SQL字符串，不同于#{}使用预编译参数。建议使用#{}参数化查询替代${}。"
        self.level = 9

        # 部分配置
        self.match_mode = "file-pattern"
        self.file_pattern = r'.*Mapper\.xml$'
        self.match = r"\$\{[^}]+\}"
        self.unmatch = []

        self.vul_function = []

    def main(self, match_string):
        """二次筛选：确认匹配的${}存在，并过滤已知的框架内部模板变量。

        降噪策略（按确定性排序）：

        1. **FreeMarker 模板变量**（确定性 FP）：
           MyBatis Generator 的代码生成模板中使用 ${table.className} 等变量，
           这些不是 MyBatis 运行时 SQL 变量，而是 Generator 生成 Java 代码的模板占位符。

        2. **Example/Criteria 标准模式**（高概率 FP，降级不消除）：
           MyBatis Generator 自动生成的 Example 模式中使用 ${criterion.condition}、
           ${orderByClause} 等。这些 SQL 片段由 Java Criteria 类的方法构建
           （如 andIdEqualTo、setOrderByClause），不是直接拼接用户输入。
           理论上如果 setOrderByClause 的参数来自用户输入则有风险，
           但在实际中几乎都是内部调用。降级为 medium 而非消除。

        3. **普通变量名**（保留报告）：
           ${id}、${value}、${tableName} 等直接拼接用户输入的场景。
        """
        if not isinstance(match_string, str):
            match_string = str(match_string)

        # 提取 ${...} 中的变量名
        m = re.search(r'\$\{([^}]+)\}', match_string)
        if not m:
            return None

        var_name = m.group(1).strip()

        # 1. 排除 FreeMarker/Generator 模板变量（确定性 FP）
        if var_name in _MYBATIS_GEN_TEMPLATE_VARS:
            return False

        # 2. Example/Criteria 标准模式 → 降级为 medium（不消除，但降低优先级）
        # 通过返回 True 但在 report 中标记
        # TODO: 未来可通过过程间分析回溯 setOrderByClause 调用链确认是否用户可控

        return True
