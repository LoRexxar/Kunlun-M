# -*- coding: utf-8 -*-

"""
    Java Jackson 不安全配置检测规则
    ~~~~
    检测 Jackson ObjectMapper 启用了 enableDefaultTyping，
    这会允许多态反序列化，可能导致远程代码执行。
    
    同类漏洞：CVE-2017-7525, CVE-2017-15095, CVE-2018-5968,
    CVE-2019-12086, CVE-2019-12384, CVE-2019-12814 等。
"""

from utils.api import *

class CVI_6047(SingleRuleMixin):
    def __init__(self):
        self.svid = 6047
        self.language = "java"
        self.vulnerability = "Jackson Unsafe Polymorphic Deserialization"
        self.description = "Jackson ObjectMapper启用了enableDefaultTyping，允许多态反序列化，可能导致远程代码执行"
        self.level = 6

        self.match_mode = "function-param-regex"
        self.match = "enableDefaultTyping"
        self.vul_function = ["ObjectMapper.enableDefaultTyping"]
        self.is_config_vuln = True

    def main(self, regex_string):
        """二次筛选：确认是 enableDefaultTyping 调用"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        if not re.search(r'enableDefaultTyping', code):
            return False
        return None
