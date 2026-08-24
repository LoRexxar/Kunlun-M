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
        self.match = r"render_template_string|jinja2\.Template\(|Environment\(|mako\.template\.Template|tornado\.template\.Template|TemplateResponse|render_to_response|mark_safe|Markup\("
        self.vul_function = ["render_template_string", "Environment", "TemplateResponse", "render_to_response", "mark_safe", "Markup"]

    def main(self, regex_string, sink_args=None, context=None):
        """
        Graph-based filtering: filter static template strings.
        Also filter render_template() with hardcoded template name.
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False

            # render_template("hardcoded.html", form=form) — template name
            # is hardcoded; context vars auto-escaped by Jinja2
            if context:
                import re as _re
                tmpl_quote = _re.compile(r'(?:render_template|render_to_response|render_to_string)\s*\(\s*[\'"]')
                if tmpl_quote.search(context):
                    return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        template_match = re.search(
            r'(?:Template|render_template_string|Markup)\s*\(\s*(.+)', regex_string, re.I)
        if not template_match:
            if re.search(r'render_template\s*\(\s*[\'"]', regex_string):
                return False
            return None
        arg = template_match.group(1).strip()
        if re.match(r'^[\'"][^\'"]*[\'"]\s*(?:\)|,|$)', arg):
            return False
        if re.match(r'^[\'"][\w/\-\.]+\.html[\'"]', arg):
            return False
        return None
