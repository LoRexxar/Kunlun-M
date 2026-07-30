# -*- coding: utf-8 -*-

"""
    Go 路径穿越规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8006(SingleRuleMixin):
    """
    Go 路径穿越规则
    匹配 filepath.Join 与用户输入拼接、os.Open 路径拼接等
    检测 ../ 等路径穿越模式
    """

    def __init__(self):
        self.svid = 8006
        self.language = "go"
        self.vulnerability = "路径穿越"
        self.description = "文件路径拼接可能来自用户输入，存在路径穿越(Path Traversal)风险。攻击者可能通过构造包含../的路径访问任意文件。建议使用filepath.Clean清理路径，并校验最终路径是否在允许的目录范围内。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"filepath\.Join\s*\(|path\.Join\s*\(|os\.Open\s*\(|os\.ReadFile\s*\(|ioutil\.ReadFile\s*\(|os\.Stat\s*\("

        self.vul_function = [
            "filepath.Join", "path.Join",
            "os.Open", "os.ReadFile", "ioutil.ReadFile", "os.Stat",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查是否使用 filepath.Clean 或有路径校验，
        标记存在路径穿越风险的代码。
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

        # 安全写法：使用了 filepath.Clean 清理路径
        if re.search(r'filepath\.Clean\s*\(', regex_string):
            return False

        # 检测 ../ 路径穿越模式
        if re.search(r'\.\./', regex_string):
            return True

        # 检测 filepath.Join 与变量拼接（用户输入可能包含 ../）
        if re.search(r'filepath\.Join\s*\(.*\w+.*\)', regex_string):
            # 排除纯硬编码路径
            if not re.search(r'filepath\.Join\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)', regex_string):
                return True

        # 检测 path.Join 与变量拼接
        if re.search(r'path\.Join\s*\(.*\w+.*\)', regex_string):
            if not re.search(r'path\.Join\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)', regex_string):
                return True

        # 检测 os.Open 等函数与变量拼接
        if re.search(r'(?:os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Stat)\s*\(\s*\w+', regex_string):
            return True

        return None
