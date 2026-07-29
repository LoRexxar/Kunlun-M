# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_1009(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1009
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "参数可控会导致远程命令执行"
        self.level = 10

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(array_map|create_function|call_user_func|call_user_func_array|assert|eval|dl|register_tick_function|register_shutdown_function)"

    def main(self, regex_string):
        """
        regex string input
        :regex_string: regex match string
        :return:
        """
        # assert() in PHP 8.0+ no longer evaluates string arguments as code.
        # Skip assert() calls that are instanceof/null checks (type assertions).
        if regex_string and regex_string.lstrip().startswith('assert'):
            stripped = regex_string.lstrip()
            # Type assertion patterns: assert($x instanceof Y), assert(null !== $x)
            if 'instanceof' in stripped or 'null' in stripped.lower():
                return False
        return None
