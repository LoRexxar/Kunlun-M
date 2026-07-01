# -*- coding: utf-8 -*-

"""
    Java LDAP Injection Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6013(SingleRuleMixin):
    def __init__(self):
        self.svid = 6013
        self.language = "java"
        self.vulnerability = "LDAP Injection"
        self.description = "用户输入拼接到LDAP查询中可能导致LDAP注入攻击"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = "search"
        self.unmatch = [r"encodeForLDAP", r"escapeLDAPSearchFilter", r"LdapEncoder"]
        self.vul_function = ["DirContext.search", "LdapContext.search"]

    def main(self, regex_string):
        """二次筛选：只保留 DirContext/LdapContext 上下文"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        if not re.search(r'DirContext|LdapContext|InitialDirContext|InitialLdapContext|ldap', code, re.I):
            return False
        return None
