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
        # jsonify 已移除：Flask jsonify 返回 application/json，浏览器不解析为 HTML，无 XSS 风险
        self.match = r"HttpResponse\(|make_response\(|Markup\(|mark_safe\(|\.safe|Response\("
        self.vul_function = ["HttpResponse", "make_response", "Markup", "mark_safe", "Response"]

    def main(self, regex_string):
        """
        二次筛选：过滤纯静态响应

        安全模式 (return False):
        - HttpResponse("static content")  纯静态
        - HttpResponse('ok')  硬编码
        - jsonify({"key": "value"})  硬编码字典

        危险模式 (return None):
        - HttpResponse("<div>%s</div>" % comment)  格式化
        - HttpResponse(user_input)  变量
        - mark_safe(value)  变量
        """
        if not regex_string:
            return None

        # HttpResponse/make_response 纯字符串字面量
        resp_match = re.search(
            r'(?:HttpResponse|make_response|Response)\s*\(\s*(.+)', regex_string, re.I)
        if resp_match:
            arg = resp_match.group(1).strip()
            # 纯字符串
            if re.match(r'^[\'"][^\'"]*[\'"]\s*\)', arg):
                return False

        return None
