# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7009(SingleRuleMixin):
    """
    Python 开放重定向
    覆盖: Flask redirect, Django HttpResponseRedirect, redirect, RedirectResponse
    """
    def __init__(self):
        self.svid = 7009
        self.language = "python"
        self.vulnerability = "开放重定向"
        self.description = "使用了可能存在开放重定向风险的跳转函数"
        self.level = 4
        self.match_mode = "function-param-regex"
        self.match = r"redirect\(|HttpResponseRedirect\(|RedirectResponse\(|Redirect\(|flask\.redirect|django\.http\.HttpResponseRedirect"
        self.vul_function = ["redirect", "HttpResponseRedirect", "RedirectResponse", "Redirect"]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: filter hardcoded URL redirects.
        redirect('/home') → False (const)
        redirect(url_for(...)) → False (operator with callee 'url_for')
        redirect(request.url) → False (PRG self-redirect)
        redirect(form.instance) → False (Model.get_absolute_url() returns safe internal path)
        redirect(url) → None (variable)
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # const/string literal → hardcoded path, safe
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                # resolved_value → identifier with const assignment
                if arg0.get('resolved_value', ''):
                    return False
                # operator (function call) → check callee name
                if arg0.get('label') == 'operator':
                    arg_name = arg0.get('name', '').lower()
                    if 'url_for' in arg_name or 'reverse' in arg_name:
                        return False
                # member/property: request.url / request.path / request.full_path → PRG self-redirect
                if arg0.get('type') == 'property' and arg0.get('name', '').lower() in ('url', 'path', 'full_path'):
                    return False
                # identifier → check if name suggests model instance
                # (e.g. form.instance) which calls get_absolute_url() internally
                if arg0.get('label') == 'identifier':
                    arg_name = arg0.get('name', '').lower()
                    if '.instance' in arg_name or '.obj' in arg_name:
                        return False
            return None

        # Regex fallback
        if not regex_string:
            return None
        redirect_match = re.search(
            r'(?:redirect|HttpResponseRedirect|RedirectResponse|Redirect)\s*\(\s*(.+)', regex_string, re.I)
        if redirect_match:
            arg = redirect_match.group(1).strip()
            if re.match(r'^[\'"][^\'"]*[\'"]\s*\)', arg):
                return False
            if re.match(r'^url_for\s*\(', arg):
                return False
            if re.match(r'^request\.url\s*\)', arg):
                return False
        return None