# -*- coding: utf-8 -*-
from utils.api import *
import re

class CVI_6023(SingleRuleMixin):
    def __init__(self):
        self.svid = 6023
        self.language = "java"
        self.vulnerability = "ProcessBuilder Command Injection"
        self.description = "请求参数直接传入ProcessBuilder构建命令，存在命令注入风险"
        self.level = 9
        # Graph engine: function-param-controllable + vul_function
        self.match_mode = "function-param-regex"
        self.match = r"new\s+ProcessBuilder"
        self.unmatch = []
        self.black_list = []

        # Graph engine: identify ProcessBuilder as sink
        self.vul_function = ["ProcessBuilder"]

    def main(self, regex_string, sink_args=None):
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        # Validate: source line should contain ProcessBuilder constructor
        # with padding= parameter pattern (specific injection vector)
        if not re.search(r'ProcessBuilder', regex_string):
            return False
        # The original regex-return-regex rule required padding= pattern.
        # Keep that check as main() validation.
        # If no padding=, let CVI-6038 (generic ProcessBuilder) handle it.
        if re.search(r'=padding=', regex_string):
            return None  # specific padding= case → this rule reports
        # No padding= → defer to CVI-6038
        return False
