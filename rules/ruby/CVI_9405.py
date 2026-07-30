# -*- coding: utf-8 -*-

"""
    Ruby 反序列化规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9405(SingleRuleMixin):
    """
    Ruby 反序列化规则
    匹配 Marshal.load、Marshal.restore、YAML.load、Psych.load 等反序列化函数
    """

    def __init__(self):
        self.svid = 9405
        self.language = "ruby"
        self.vulnerability = "反序列化"
        self.description = "使用了可能存在反序列化风险的函数（Marshal.load、Marshal.restore、YAML.load、Psych.load等），且参数可能受用户控制。攻击者可构造恶意序列化数据导致远程代码执行。建议使用 YAML.safe_load 替代 YAML.load，使用 YAML.load_stream 并验证类型，或避免反序列化不受信任的数据。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Marshal\.load\s*\(|Marshal\.restore\s*\(|YAML\.load\s*\(|Psych\.load\s*\("

        self.vul_function = ["load", "restore"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        如果参数是纯硬编码字符串（如 Marshal.load("...")），返回 False（安全）。
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
        match = re.search(r'(?:Marshal|YAML|Psych)\.(?:load|restore)\s*\((.*)\)', regex_string, re.DOTALL)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 如果参数是纯硬编码字符串字面量，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 确认包含危险的反序列化调用
        dangerous_patterns = [
            r"Marshal\.load\s*\(",
            r"Marshal\.restore\s*\(",
            r"YAML\.load\s*\(",
            r"Psych\.load\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
