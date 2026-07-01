# -*- coding: utf-8 -*-

"""
    Java Fastjson 不安全配置检测规则
    ~~~~
    检测 fastjson 中启用了 setAutoTypeSupport(true) 的不安全配置，
    这会允许任意类的反序列化，绕过 AutoType 安全检查。
    
    使用 config_vuln_args 声明危险参数值模式：
    当 AST 分析发现 sink 的参数为字面量 true 时，标记为漏洞。
"""

from utils.api import *

class CVI_6045(SingleRuleMixin):
    def __init__(self):
        self.svid = 6045
        self.language = "java"
        self.vulnerability = "Fastjson Unsafe Configuration"
        self.description = "Fastjson启用了setAutoTypeSupport(true)，允许任意类反序列化，可能绕过AutoType安全检查导致远程代码执行"
        self.level = 3

        self.match_mode = "java-function-param-regex"
        self.match = "setAutoTypeSupport"
        self.vul_function = ["ParserConfig.setAutoTypeSupport"]
        self.is_config_vuln = True

        # 危险配置参数声明：当参数值匹配这些正则时，视为漏洞（配置型漏洞）
        # 不依赖外部输入可控性，调用本身 + 危险参数值 = 漏洞
        self.config_vuln_args = [r'^true$']

    def main(self, regex_string):
        """二次筛选：只有参数为 true 时才继续 AST 分析"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        if not re.search(r'setAutoTypeSupport\s*\(\s*true\s*\)', code, re.I):
            return False
        return None
