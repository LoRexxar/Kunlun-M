# -*- coding: utf-8 -*-

"""
    PHP preg_replace Code Execution (ReDoS)
    ~~~~
    Detects preg_replace with /e modifier where the pattern or replacement
    is user-controllable. The /e modifier causes preg_replace to evaluate
    the replacement string as PHP code.
    Also flags potential ReDoS when user input flows into the regex pattern.
"""

from utils.api import *


class CVI_1018(SingleRuleMixin):
    """
    PHP preg_replace Code Execution (ReDoS)
    """

    def __init__(self):

        self.svid = 1018
        self.language = "php"
        self.author = "Kunlun-M"
        self.vulnerability = "preg_replace Code Execution"
        self.description = "preg_replace的/e修饰符会将替换字符串作为PHP代码执行，如果正则模式或替换参数包含用户可控数据，可能导致远程代码执行。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"preg_replace\s*\("

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        pass
