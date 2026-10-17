# -*- coding: utf-8 -*-

"""
    Java SQL 构造器格式化拼接规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_6080(SingleRuleMixin):
    """
    Java 库边界 SQL 构造器注入（String.format / String.formatted 拼接 SQL 片段）

    CVE-2026-76904 (GHSA-mqjf-5f49-2fjh, AVD-2026-1908121, CVSS 9.8):
    GeoTools gt-jdbc-postgis FilterToSqlHelper.constructEquality 把
    OGC jsonArrayContains(col, pointer, value) 的 value 未经转义直接
    format 进 jsonb_path_exists 的 SQL 路径表达式（35.0 及以前），
    PostGIS 层可注入任意 SQL。污点边界是库的公共 API 参数
    （FilterToSql.encode(filter)——filter 来自 GeoServer OWS 请求）。
    """

    def __init__(self):
        self.svid = 6080
        self.language = "java"
        self.vulnerability = "SQL Injection"
        self.description = "通过 String.format / String.formatted 将非常量参数拼接进字符串模板，且模板携带 SQL 语义（比较/路径表达式/DDL/DML 片段）。若模板结果进入 SQL 执行（如 OGC Filter→SQL 编码器、动态 ORDER BY 拼接），可能造成 SQL 注入。库代码的污点边界是公共 API 参数，静态污点不可证时建议人工复核：改用参数化查询或对拼接值做转义。"
        self.level = 7

        self.match_mode = "function-param-regex"
        self.match = (
            r"\bString\s*\.\s*format\s*\("
            r"|\.\s*formatted\s*\("
        )

        self.vul_function = [
            "String.format",
        ]
        # bare method names on any receiver (Fix 33 Path C): Java 15+
        # "...".formatted(args) 的 callee 在图上是 bare 'formatted'。
        self.method_sinks = ["formatted"]

        # 库边界 sink：污点无法证到框架入口（OGC filter 参数来自
        # GeoServer OWS 请求层），presence + main() 模板过滤即报告。
        self.require_taint = False

    def main(self, regex_string, sink_args=None):
        """
        二次筛选。注意：java normalizer 不把字面量 receiver 计入
        sink_args -- 模板要从 sink 名（'"tpl".formatted'）解析，
        sink_args 全部是插值参数。
        """
        tpl = None
        if isinstance(regex_string, str):
            m = re.match(r"^(['\"])(.*)\1\s*\.\s*formatted", regex_string.strip())
            if m:
                tpl = m.group(2)
            else:
                m2 = re.search(r"String\s*\.\s*format\s*\(\s*(['\"])(.+?)\1\s*,", regex_string)
                if m2:
                    tpl = m2.group(2)
        if tpl is None and isinstance(regex_string, str):
            tpl = regex_string
        if not _has_sql_shape(str(tpl)):
            return False
        # Only report quoted string interpolation at comparison
        # positions (the == "%s" shape).  Numeric %d/%f branches have
        # no injection surface; path/key construction ("%s": [%s])
        # bypasses the quoted slot and is not reported here.  The
        # CVE-2026-76904 vulnerable template is exactly the quoted
        # %s slot in (@.%s == "%s").
        # %s slot must be quoted; tolerate backslash escapes between
        # operator and quote (graph sink names carry the source-code
        # escaping layer, e.g. == \\"%s\\").
        _q = re.search(r"(?:==|!=|>=|<=|>|<|\blike\b)\s*[\\]*([\"'])%s", str(tpl), re.I)
        if not _q:
            return False
            return False
        if sink_args is not None:
            if not sink_args:
                return False
            for a in sink_args:
                if not (a.get('label') == 'const' or a.get('type') in ('string', 'constant')):
                    return None
            return False
        return None

def _has_sql_shape(tpl):
    """模板是否携带 SQL 语义：比较表达式/路径表达式/常见 SQL 子句。"""
    t = tpl.lower()
    return bool(re.search(
        r'==|%s\s*(==|>=|<=|!=|like|in\b)|'
        r'\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bwhere\b|'
        r'jsonb_path|@>\s|::jsonb|\$\?|@\.|order\s+by|group\s+by|'
        r'and\s+%s|or\s+%s',
        t))
