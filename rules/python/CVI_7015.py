# -*- coding: utf-8 -*-
from utils.api import *

class CVI_7015(SingleRuleMixin):
    """
    Python Web 框架不安全API
    覆盖: Django force_text/force_str 危险用法, Flask send_file/after_request
    """
    def __init__(self):
        self.svid = 7015
        self.language = "python"
        self.vulnerability = "不安全API调用"
        self.description = "使用了框架中可能存在安全风险的API"
        self.level = 5
        self.match_mode = "function-param-regex"
        self.match = r"force_text|force_str|smart_str|avoid_ahead|send_file|send_from_directory|serve|@csrf_exempt|csrf_exempt|@login_not_required|ALLOWED_HOSTS|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS"

    def main(self, regex_string, sink_args=None):
        pass
