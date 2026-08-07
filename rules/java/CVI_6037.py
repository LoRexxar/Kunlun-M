# -*- coding: utf-8 -*-

"""
    Java Fastjson Deserialization Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6037(SingleRuleMixin):
    def __init__(self):
        self.svid = 6037
        self.language = "java"
        self.vulnerability = "Fastjson Deserialization"
        self.description = "Fastjson反序列化用户可控JSON可能导致远程代码执行"
        self.level = 4

        self.match_mode = "function-param-regex"
        self.match = "parseObject|parse"
        self.unmatch = [r"SafeMode", r"autoTypeFilter", r"ParserConfig.getGlobalInstance\\(\\).setAutoTypeSupport"]
        self.vul_function = ["JSON.parseObject", "JSON.parse", "JSON.parseArray"]

    def main(self, regex_string, sink_args=None, context=None, **kwargs):
        """二次筛选：只保留 JSON/Fastjson 上下文
        
        parseArray(text, Class) 和 parseObject(text, Class) 指定了
        目标类型，不存在 autoType 多态反序列化风险，应跳过。
        危险的是无类型参数的 parse(text) / parseObject(text)。
        """
        code = regex_string.strip() if isinstance(regex_string, str) else str(regex_string)
        full_text = code
        if context and isinstance(context, str):
            full_text = code + ' ' + context

        # Typed deserialization: parse(Array|Object)(text, Xxx.class)
        # → no autoType risk, skip regardless of graph/regex mode
        if re.search(r'parse(?:Object|Array)\s*\([^)]+,\s*\w+\.class\s*\)', full_text):
            return False

        # SafeMode / autoType filtering configured
        if re.search(r'SafeMode|autoTypeFilter|ParserConfig\.getGlobalInstance\(\)\.setAutoTypeSupport', full_text, re.I):
            return False

        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not re.search(r'JSON|json|fastjson|alibaba', code, re.I):
            return False
        return None
