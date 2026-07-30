# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7006(SingleRuleMixin):
    """
    Python SSTI (服务端模板注入)
    覆盖: Flask render_template_string, Jinja2 Template, Django template, Mako, Tornado
    """
    def __init__(self):
        self.svid = 7006
        self.language = "python"
        self.vulnerability = "SSTI"
        self.description = "使用了可能存在模板注入风险的渲染函数"
        self.level = 8
        self.match_mode = "function-param-regex"
        self.match = r"render_template_string|Template\(|jinja2\.Environment|TemplateResponse|render_to_response|mark_safe|Markup\(|mako\.template\.Template|tornado\.template\.Template"
        self.vul_function = ["render_template_string", "Template", "Environment", "TemplateResponse", "render_to_response", "mark_safe", "Markup"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：过滤纯静态模板字符串

        安全模式 (return False):
        - Template("static string")  纯静态
        - render_template_string("<h1>Hello</h1>")  无变量插值

        危险模式 (return None):
        - Template("Hello " + name)  变量拼接
        - render_template_string(user_input)  变量参数
        - Template(f"Hello {name}")  f-string插值
        """
        if not regex_string:
            return None

        # 检查 Template/render_template_string 的参数
        template_match = re.search(
            r'(?:Template|render_template_string|Markup)\s*\(\s*(.+)', regex_string, re.I)
        if not template_match:
            return None

        arg = template_match.group(1).strip()

        # 纯字符串字面量（无拼接、无变量）
        # "static string" 或 'static string'
        if re.match(r'^[\'\"][^\'\"]*[\'\"]\s*(?:\)|,|$)', arg):
            return False

        # render_template("template.html", ...) 是安全的（模板文件名，不是内容）
        if re.match(r'^[\'\"][\w/\-\.]+\.html[\'\"]', arg):
            return False

        return None
