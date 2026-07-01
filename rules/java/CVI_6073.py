# -*- coding: utf-8 -*-

"""
    Java SSTI (Server-Side Template Injection) Rule
    ~~~~
    检测Velocity/Freemarker等模板引擎将用户输入作为模板内容直接求值导致的SSTI漏洞。
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6073(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6073
        self.language = "java"
        self.vulnerability = "SSTI (Server-Side Template Injection)"
        self.description = "通过AST分析检测Velocity.evaluate()/Freemarker Template.process()/VelocityEngine.evaluate()等方法将用户可控输入作为模板内容直接求值导致的SSTI漏洞。攻击者可注入恶意模板表达式执行任意代码。建议使用安全的模板渲染方式，避免直接执行用户输入。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r'Velocity\.evaluate\s*\(|Velocity\.merge\s*\(|VelocityEngine\.evaluate\s*\(|\.process\s*\(\s*rootMap|new\s+Template\s*\(\s*["\x27][^"\x27]*["\x27],\s*new\s+StringReader'

        # for regex
        self.unmatch = []

        self.vul_function = [
            "evaluate",
            "merge",
            "Template.process",
        ]

    def main(self, regex_string):
        """二次筛选：确认模板内容来自用户输入"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除使用安全配置的写法
        if re.search(r'setSafeMode|setAllowInline|SandboxConfiguration|safeMode|strictMode', regex_string):
            return False
        return None
