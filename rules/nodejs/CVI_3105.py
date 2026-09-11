# -*- coding: utf-8 -*-

"""
    Node.js 不安全反序列化规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3105(SingleRuleMixin):
    """
    Node.js 不安全反序列化规则
    匹配 serialize/unserialize、node-serialize、funcstream 等不安全反序列化
    """

    def __init__(self):
        self.svid = 3105
        self.language = "javascript"
        self.vulnerability = "不安全反序列化"
        self.description = "使用了不安全的反序列化函数（unserialize、node-serialize的deserialize等），可能导致远程代码执行。建议使用JSON.parse等安全的序列化方式，避免反序列化不受信任的数据。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\bunserialize\s*\(|\.deserialize\s*\(|\.unserialize\s*\("

        self.vul_function = [
            "unserialize", "deserialize",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：所有 unserialize/deserialize 调用都标记为危险
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

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        if re.search(r'(?:unserialize|deserialize)\s*\(', regex_string):
            return True

        return None
