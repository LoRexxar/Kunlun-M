# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7008(SingleRuleMixin):
    """
    Python XSS (跨站脚本)
    覆盖: Flask/Django 中不转义输出, safe filter, Markup, HttpResponse 直接拼接
    """
    def __init__(self):
        self.svid = 7008
        self.language = "python"
        self.vulnerability = "XSS"
        self.description = "可能存在XSS跨站脚本风险: 未转义的用户输入直接输出到响应"
        self.level = 5
        self.match_mode = "function-param-regex"
        # jsonify/Response 已移除：Flask jsonify 和 DRF Response 返回 application/json，
        # 浏览器不解析为 HTML，无 XSS 风险
        self.match = r"HttpResponse\(|make_response\(|Markup\(|mark_safe\(|\.safe"
        self.vul_function = ["HttpResponse", "make_response", "Markup", "mark_safe"]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: filter static response strings.
        HttpResponse("ok") → False (const)
        HttpResponse(user_input) → None (variable)
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        resp_match = re.search(
            r'(?:HttpResponse|make_response|Response)\s*\(\s*(.+)', regex_string, re.I)
        if resp_match:
            arg = resp_match.group(1).strip()
            if re.match(r'^[\'"][^\'"]*[\'"]\s*\)', arg):
                return False
        return None
