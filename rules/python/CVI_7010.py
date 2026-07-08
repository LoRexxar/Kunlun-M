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

    def main(self, regex_string):
        """
        二次筛选：只保留 LDAP 搜索调用，过滤 re.search 等

        安全模式 (return False):
        - re.search(pattern, text)       正则搜索，非LDAP
        - re.search_s / re.search_ext    正则模块无此方法（不会出现）

        危险模式 (return None):
        - conn.search(filter, ...)       LDAP 连接搜索
        - ldap.search(base, filter)      LDAP 模块搜索
        """
        if not regex_string:
            return None

        # 过滤 re.search — 正则搜索不是 LDAP
        if re.search(r'\bre\.search\s*\(', regex_string):
            return False

        return None
