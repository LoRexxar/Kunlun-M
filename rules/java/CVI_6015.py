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

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: for setHeader, only "Location" header is Open Redirect.
        setHeader("Content-Disposition", ...) is file download, not redirect.
        sendRedirect is always redirect (no filtering needed).

        sink_args: list of {name, type, label, vid} from graph arg nodes.
        """
        if sink_args:
            sn_lower = regex_string.lower()
            # setHeader: check arg[0] for header name
            if 'setheader' in sn_lower and 'sendredirect' not in sn_lower:
                if sink_args:
                    arg0 = sink_args[0]
                    # const/string node → arg0['name'] is the literal value
                    if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                        header_name = arg0.get('name', '').strip('"').strip("'")
                        if header_name.lower() != 'location':
                            return False
                    # identifier node → header name is a variable (unknown), let through.
            return None

        # Regex fallback (source-line based)
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有白名单校验的写法
        if re.search(r"isUrlAllowed|ALLOWED_HOSTS|allowedHosts|whitelist|urlWhitelist|isValidRedirect", regex_string, re.I):
            return False
        # Content-Disposition 不是 URL 重定向
        if re.search(r"Content-Disposition", regex_string):
            return False
        # ModelAndView 无参构造 + 随后 setViewName("redirect:...") 模式:
        if "ModelAndView" in regex_string:
            if re.search(r"redirect:|RedirectView|setViewName\s*\(\s*\"redirect:", regex_string):
                return None
            return False
        return None
