# -*- coding: utf-8 -*-

"""
    Java Open Redirect Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6015(SingleRuleMixin):
    def __init__(self):
        self.svid = 6015
        self.language = "java"
        self.vulnerability = "Open Redirect"
        self.description = "用户可控的重定向URL可能导致开放重定向攻击，包括sendRedirect、ModelAndView redirect、setHeader(Location)等方式"
        self.level = 2

        self.match_mode = "function-param-regex"
        self.match = r'\.sendRedirect\s*\(|redirect:|\.setHeader\s*\(\s*["\x27]Location'
        self.unmatch = [r"isValidRedirect", r"whitelist", r"allowedDomains"]
        self.vul_function = [
            "HttpServletResponse.sendRedirect", "HttpServletResponse.setHeader",
            # ModelAndView构造函数: 图引擎callee是短名(无use edge), 保持短名
            "ModelAndView",
        ]

    def main(self, regex_string, sink_args=None, context=None, **kwargs):
        """
        Graph-based filtering:
        - sendRedirect with const/hardcoded arg → False (safe)
        - setHeader with non-Location header → False
        - ModelAndView without redirect: prefix → False
        - Redirect var built from config/static method base → False (FP)
        """
        # Build context text
        full_text = ''
        if isinstance(regex_string, str):
            full_text = regex_string
        if context and isinstance(context, str):
            full_text = full_text + ' ' + context

        if sink_args:
            sn_lower = regex_string.lower() if isinstance(regex_string, str) else str(regex_string).lower()

            # sendRedirect: check if arg is hardcoded
            if 'sendredirect' in sn_lower:
                if len(sink_args) >= 1:
                    arg0 = sink_args[0]
                    # const/string literal → hardcoded path, safe
                    # Note: only check direct const, not resolved_value,
                    # because resolved_value may be overwritten in a branch
                    if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                        return False

                    # Check context for config-based redirect: pattern is
                    # varName = SomeConfig.getXxx() + ... + userInput
                    # This means the redirect base URL is config-controlled,
                    # and user input is only in query params → not open redirect
                    arg0_name = arg0.get('name', '')
                    if arg0_name and full_text:
                        import re as _re
                        # Look for: [Type] varName = Something.getMethod(...) + ...
                        # This means the redirect base URL is config-controlled,
                        # and user input is only in query params → not open redirect
                        config_concat = _re.search(
                            arg0_name + r'\s*=\s*\w+\.\w+\([^)]*\)\s*\+',
                            full_text
                        )
                        if config_concat:
                            return False

            # setHeader: check arg[0] for header name
            if 'setheader' in sn_lower and 'sendredirect' not in sn_lower:
                arg0 = sink_args[0]
                header_val = arg0.get('resolved_value', '')
                if not header_val:
                    if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                        header_val = arg0.get('name', '')
                if header_val:
                    header_name = header_val.strip('"').strip("'")
                    if header_name.lower() != 'location':
                            return False
            # ModelAndView: only a redirect if view name starts with "redirect:"
            if 'modelandview' in sn_lower:
                if len(sink_args) >= 1:
                    arg0 = sink_args[0]
                    rv = arg0.get('resolved_value', '')
                    if rv:
                        if 'redirect:' not in rv:
                            return False
                    elif arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                        name = arg0.get('name', '')
                        if 'redirect:' not in str(name):
                            return False
            return None

        # Regex fallback (source-line based)
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        if re.search(r"isUrlAllowed|ALLOWED_HOSTS|allowedHosts|whitelist|urlWhitelist|isValidRedirect", regex_string, re.I):
            return False
        if re.search(r"Content-Disposition", regex_string):
            return False
        if "ModelAndView" in regex_string:
            if re.search(r"redirect:|RedirectView|setViewName\s*\(\s*\"redirect:", regex_string):
                return None
            return False
        return None
