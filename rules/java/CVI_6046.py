# -*- coding: utf-8 -*-

"""
    Java Log4j JNDI 注入检测规则（数据流分析）
    ~~~~
    检测 Log4j 日志方法调用（logger.error/info/debug/warn/trace）中
    参数是否用户可控。可控的用户输入通过 Log4j lookup 机制触发 JNDI 注入。
    
    配合 CVI-6017（检测硬编码 jndi 特征）使用，本规则从数据流角度检测。
"""

from utils.api import *

class CVI_6046(SingleRuleMixin):
    def __init__(self):
        self.svid = 6046
        self.language = "java"
        self.vulnerability = "Log4j JNDI Injection (Dataflow)"
        self.description = "Log4j日志方法调用了用户可控的参数，可能通过JNDI Lookup机制触发远程代码执行（Log4Shell CVE-2021-44228）"
        self.level = 10

        self.match_mode = "function-param-regex"
        # 匹配 logger.error/info/debug/warn/trace/fatal 调用
        self.match = r'(?<!\w)(?:error|info|debug|warn|trace|fatal)\s*\('
        self.vul_function = [
            "Logger.error",
            "Logger.info",
            "Logger.debug",
            "Logger.warn",
            "Logger.trace",
            "Logger.fatal",
        ]

    def main(self, regex_string):
        """二次筛选：排除非 logger 调用，只保留日志上下文"""
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        # 必须是 logger/Logger/LOG/log 的方法调用
        if not re.search(r'(?i)(?:logger|log|LOG)\s*\.\s*(?:error|info|debug|warn|trace|fatal)\s*\(', code):
            return False
        return None
