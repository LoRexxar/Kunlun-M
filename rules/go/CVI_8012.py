# -*- coding: utf-8 -*-

"""
    Go 任意文件写入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *


class CVI_8012(SingleRuleMixin):
    """
    Go 任意文件写入规则
    匹配 os.WriteFile / ioutil.WriteFile / os.Create / os.OpenFile 等
    """

    def __init__(self):
        self.svid = 8012
        self.language = "go"
        self.vulnerability = "任意文件写入"
        self.description = "使用了文件写入函数（os.WriteFile、ioutil.WriteFile、os.Create、os.OpenFile等），可能导致任意文件写入漏洞。建议对文件路径参数进行严格校验（白名单目录、路径规范化后检查是否在允许范围内），避免将用户输入直接作为文件路径。"
        self.level = 8

        self.match_mode = "function-param-regex"
        self.match = r"os\.WriteFile\s*\(|ioutil\.WriteFile\s*\(|os\.Create\s*\(|os\.OpenFile\s*\("

        self.vul_function = ["os.WriteFile", "ioutil.WriteFile", "os.Create", "os.OpenFile"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否为危险的文件写入调用，
        排除文件路径是硬编码字符串字面量的情况。
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

        match = re.search(
            r'(?:os\.WriteFile|ioutil\.WriteFile|os\.Create|os\.OpenFile)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 第一个参数为文件路径，检查是否为硬编码字符串字面量
        first_arg_match = re.match(r'^"([^"]*)"', args)
        if first_arg_match:
            # 路径是硬编码字符串，排除
            return False

        # 确认包含危险的文件写入调用
        dangerous_patterns = [
            r"os\.WriteFile\s*\(",
            r"ioutil\.WriteFile\s*\(",
            r"os\.Create\s*\(",
            r"os\.OpenFile\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
