# -*- coding: utf-8 -*-

"""
    Ruby 代码注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9404(SingleRuleMixin):
    """
    Ruby 代码注入规则
    匹配 eval、instance_eval、class_eval、send 等动态代码执行函数
    """

    def __init__(self):
        self.svid = 9404
        self.language = "ruby"
        self.vulnerability = "代码注入"
        self.description = "使用了可能存在代码注入风险的动态执行函数（eval、instance_eval、class_eval、send等），且参数可能受用户控制。攻击者可注入任意Ruby代码导致远程代码执行。建议避免使用eval，对于send应限制允许的方法名白名单。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\beval\s*\(|instance_eval\s*\(|class_eval\s*\(|\.send\s*\("

        self.vul_function = ["eval", "instance_eval", "class_eval", "send"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        如果所有参数都是硬编码字符串（如 eval("1+1")），返回 False（安全）。
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

        # 提取函数调用参数部分
        match = re.search(r'(?:eval|instance_eval|class_eval|send)\s*\((.*)\)', regex_string, re.DOTALL)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量（单引号或双引号包裹），排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 确认包含危险的代码执行调用
        dangerous_patterns = [
            r"\beval\s*\(",
            r"instance_eval\s*\(",
            r"class_eval\s*\(",
            r"\.send\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
