# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7006(SingleRuleMixin):
    """
    Python SSTI (服务端模板注入)
    覆盖: Flask render_template_string, Jinja2 Template, Django template, Mako, Tornado
    
    NOTE: render_template() is NOT SSTI — it loads a template file by name.
    If the template name is user-controlled, that's path traversal (CVI-9403/7005),
    not template injection. SSTI requires user-controlled template CONTENT.
    """
    def __init__(self):
        self.svid = 7006
        self.language = "python"
        self.vulnerability = "SSTI"
        self.description = "使用了可能存在模板注入风险的渲染函数"
        self.level = 8
        self.match_mode = "function-param-regex"
        self.match = r"render_template_string|jinja2\.Template\(|Environment\(|mako\.template\.Template|tornado\.template\.Template|TemplateResponse|mark_safe|Markup\("
        self.vul_function = ["render_template_string", "Environment", "TemplateResponse",
                              "render_to_response", "mark_safe", "Markup"]

    def main(self, regex_string, sink_args=None, context=None):
        """
        Graph-based filtering.
        
        render_template("name.html", ...) — always safe from SSTI because
        arg0 is a FILE PATH, not template content. Template content comes from
        the file itself, not from the caller. Exclude via context check.
        
        render_template_string(CONTENT) — dangerous, keep checking.
        """
        if sink_args:
            # render_template with any args → NOT SSTI (template name, not content)
            if context:
                import re as _re
                # render_template (not _string) → exclude entirely
                if _re.search(r'\brender_template\b\s*\(', context) and \
                   not _re.search(r'\brender_template_string\b', context):
                    return False
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # Hardcoded template name (const/string/constant) → safe
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                # Resolved to a known value → safe
                if arg0.get('resolved_value', ''):
                    return False
                # Single-quoted string in name field
                arg_name = arg0.get('name', '')
                if arg_name and arg_name.startswith(("'", '"')) and arg_name.endswith(("'", '"')):
                    return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        # render_template (not _string) with any template name → not SSTI
        if re.search(r'\brender_template\s*\(\s*[\'"]', regex_string) and \
           not re.search(r'render_template_string', regex_string):
            return False
        template_match = re.search(
            r'(?:Template|render_template_string|Markup)\s*\(\s*(.+)', regex_string, re.I)
        if not template_match:
            return None
        arg = template_match.group(1).strip()
        if re.match(r'^[\'"][^\'"]*[\'"]\s*(?:\)|,|$)', arg):
            return False
        if re.match(r'^[\'"][\w/\-\.]+\.html[\'"]', arg):
            return False
        return None
