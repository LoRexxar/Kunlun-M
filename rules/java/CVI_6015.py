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

    def main(self, regex_string):
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # 排除有白名单校验的写法
        if re.search(r"isUrlAllowed|ALLOWED_HOSTS|allowedHosts|whitelist|urlWhitelist|isValidRedirect", regex_string, re.I):
            return False
        # Content-Disposition 不是 URL 重定向
        if re.search(r"Content-Disposition", regex_string):
            return False
        return None
