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
        self.match = r"send_file|send_from_directory|serve|@csrf_exempt|csrf_exempt|@login_not_required|ALLOWED_HOSTS|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS"

    def main(self, regex_string, sink_args=None):
        sn = str(regex_string).lower() if regex_string else ''
        # send_file with function-return argument: content object, not path
        if 'send_file' in sn:
            if sink_args and len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False  # hardcoded path
                if arg0.get('resolved_value', ''):
                    return False
                if arg0.get('is_func_return'):
                    return False
        return None
