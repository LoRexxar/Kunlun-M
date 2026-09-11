# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7010(SingleRuleMixin):
    """
    Python LDAP 注入
    覆盖: ldap3, python-ldap 的搜索操作
    """
    def __init__(self):
        self.svid = 7010
        self.language = "python"
        self.vulnerability = "LDAP注入"
        self.description = "LDAP搜索操作使用了可能可控的过滤条件，可能导致LDAP注入"
        self.level = 6
        self.match_mode = "function-param-regex"
        self.match = r"ldap\.search\(|connection\.search\(|conn\.search\(|ldap\.search_s\(|ldap\.search_ext\(|l\.search\(|l\.search_s\(|l\.search_ext\("
        self.vul_function = ["search", "search_s", "search_ext"]

    def main(self, regex_string, sink_args=None, context=None):
        """
        二次筛选：只保留 LDAP 搜索调用，过滤 re.search 等

        安全模式 (return False):
        - re.search(pattern, text)       正则搜索，非LDAP
        - self.re.search(...)            成员正则搜索，非LDAP

        危险模式 (return None):
        - conn.search(filter, ...)       LDAP 连接搜索
        - ldap.search(base, filter)      LDAP 模块搜索
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            # Check context for regex-based .search() calls (not LDAP)
            check_text = context or regex_string
            if check_text and isinstance(check_text, str):
                if re.search(r'\bre\.search\s*\(', check_text):
                    return False
                if re.search(r'\.re\.search\s*\(', check_text):
                    return False
                if re.search(r'\b\w+\.search\s*\(', check_text):
                    if not re.search(r'\b(ldap|conn|connection|l)\.search\s*\(', check_text):
                        return False
            return None

        if not regex_string:
            return None

        # 过滤 re.search — 正则搜索不是 LDAP
        # 覆盖模块调用 (re.search) 和成员调用 (self.re.search, compiled.search)
        if re.search(r'\bre\.search\s*\(', regex_string):
            return False
        # self.re.search(), pattern.search(), regex.search() — 正则方法调用
        if re.search(r'\.re\.search\s*\(|\.search\s*\(.*\.(search|match|findall|finditer|sub|split|fullmatch)\s*\(', regex_string):
            return False
        # 更宽泛: 任何 .search( 调用中，如果搜索对象是正则相关变量名
        if re.search(r'\b\w+\.search\s*\(', regex_string):
            # 排除 ldap.search(...) (合法 LDAP sink)
            if not re.search(r'\b(ldap|conn|connection|l)\.search\s*\(', regex_string):
                return False

        return None
