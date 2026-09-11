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

class CVI_1001(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1001
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "cURL的函数相应函数可控，可能会造成SSRF漏洞。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)"

        self.vul_function = "curl_setopt"

    def main(self, regex_string, sink_args=None):
        """
        regex string input
        just for curl
        :return: 
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        sql_sen = regex_string[0]
        reg = r"\$[\w+\->]*"
        if re.search(reg, sql_sen, re.I):

            p = re.compile(reg)
            match = p.findall(sql_sen)
            return match
        return None
