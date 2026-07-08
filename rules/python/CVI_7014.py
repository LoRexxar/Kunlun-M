# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7014(SingleRuleMixin):
    """
    Python 表达式注入
    覆盖: f-string 格式化滥用, format_map, string.Template
    """
    def __init__(self):
        self.svid = 7014
        self.language = "python"
        self.vulnerability = "表达式注入"
        self.description = "用户输入可能被用于字符串格式化，存在格式化字符串攻击风险"
        self.level = 5
        self.match_mode = "function-param-regex"
        self.match = r"\.format_map|\.format\(|string\.Template|\.substitute\(|\.safe_substitute\("
        self.vul_function = ["format_map", "format", "Template", "substitute", "safe_substitute"]

    def main(self, regex_string):
        """
        二次筛选：过滤 str.format() 常规用法，只保留高风险场景

        安全模式 (return False):
        - "literal {}".format(...)          硬编码模板
        - logger.info("msg %s", x)          日志格式化（不涉及 format）
        - tpl.format(**kwargs)             Template 对象的 format 可能安全

        危险模式 (return None):
        - user_controlled.format(**user_dict)  用户可控模板
        - tpl.format_map(mapping)              format_map 更危险
        - Template(user_input).substitute(...)  直接注入模板
        """
        if not regex_string:
            return None

        # 过滤纯字面量字符串的 .format() — 无用户输入参与
        # "literal {}".format(x) → 硬编码模板字符串，不构成注入
        if re.match(r'^\s*["\'][^"\']*["\']\s*\.\s*format', regex_string):
            return False

        return None
