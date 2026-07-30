# -*- coding: utf-8 -*-

"""
    kotlin 模板注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9312(SingleRuleMixin):
    """
    kotlin 模板注入规则
    """

    def __init__(self):
        self.svid = 9312
        self.language = "kotlin"
        self.vulnerability = "模板注入"
        self.description = "使用Thymeleaf或FreeMarker动态渲染用户输入可能导致服务器端模板注入。建议避免动态模板处理。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"TemplateEngine\.process\s*\(|FreeMarkerTemplateUtils|template\.process\s*\("

        self.vul_function = [
        "TemplateEngine.process", "FreeMarkerTemplateUtils", "template.process"
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        args = regex_string.strip()

        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        return True

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号和字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        current = []
        for ch in args_str:
            if ch == '"' and not in_single and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif in_single or in_double:
                current.append(ch)
            elif ch == '(':
                depth += 1
                current.append(ch)
            elif ch == ')':
                depth -= 1
                current.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(current))
                current = []
            else:
                current.append(ch)
        if current:
            args.append(''.join(current))
        return args
