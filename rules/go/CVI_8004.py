# -*- coding: utf-8 -*-

"""
    Go 文件操作规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8004(SingleRuleMixin):
    """
    Go 文件操作规则
    匹配 os.Open/os.Create/os.WriteFile/os.ReadFile/ioutil.ReadFile/ioutil.WriteFile
    os.Remove/os.RemoveAll 等文件操作函数
    """

    def __init__(self):
        self.svid = 8004
        self.language = "go"
        self.vulnerability = "文件操作"
        self.description = "使用了文件操作函数（os.Open、os.Create、os.WriteFile、os.ReadFile、ioutil.ReadFile、ioutil.WriteFile、os.Remove、os.RemoveAll等），如果文件路径来自用户输入，可能导致任意文件读写删除等安全问题。建议对文件路径进行严格校验和白名单限制。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"os\.Open\s*\(|os\.Create\s*\(|os\.WriteFile\s*\(|os\.ReadFile\s*\(|ioutil\.ReadFile\s*\(|ioutil\.WriteFile\s*\(|os\.Remove\s*\(|os\.RemoveAll\s*\(|os\.OpenFile\s*\(|os\.Mkdir\s*\(|os\.MkdirAll\s*\(|os\.CreateTemp\s*\(|os\.ReadDir\s*\("

        self.vul_function = [
            "os.Open", "os.Create", "os.WriteFile", "os.ReadFile",
            "ioutil.ReadFile", "ioutil.WriteFile",
            "os.Remove", "os.RemoveAll", "os.OpenFile",
            "os.Mkdir", "os.MkdirAll", "os.CreateTemp", "os.ReadDir",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查文件路径是否为硬编码，排除安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数
        match = re.search(r'(?:os\.\w+|ioutil\.\w+)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量硬编码路径
        # os.Open("/etc/passwd") -> 硬编码，但仍可能是敏感文件访问
        # os.Open("config.yaml") -> 硬编码配置文件，通常安全
        if re.match(r'^"[^"]*"$', args):
            return False

        # 确认包含危险的文件操作调用
        dangerous_patterns = [
            r"os\.Open\s*\(",
            r"os\.Create\s*\(",
            r"os\.WriteFile\s*\(",
            r"os\.ReadFile\s*\(",
            r"ioutil\.ReadFile\s*\(",
            r"ioutil\.WriteFile\s*\(",
            r"os\.Remove\s*\(",
            r"os\.RemoveAll\s*\(",
            r"os\.OpenFile\s*\(",
            r"os\.Mkdir\s*\(",
            r"os\.MkdirAll\s*\(",
            r"os\.CreateTemp\s*\(",
            r"os\.ReadDir\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
