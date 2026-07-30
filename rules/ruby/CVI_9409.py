# -*- coding: utf-8 -*-

"""
    ruby 日志注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9409(SingleRuleMixin):
    """
    ruby 日志注入规则
    """

    def __init__(self):
        self.svid = 9409
        self.language = "ruby"
        self.vulnerability = "日志注入"
        self.description = "将未经验证的用户输入写入日志可能导致信息泄露或日志注入攻击。攻击者可伪造日志条目、注入恶意内容或遮蔽真实攻击痕迹。建议对日志输出进行过滤和编码。"
        self.level = 8
        self.status = False  # 禁用：日志注入在web扫描场景中不构成实际威胁

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"logger\.\w+\s*\(|Rails\.logger\.\w+\(|Logger\.new.*info|Logger\.new.*warn|Logger\.new.*error|Logger\.new.*debug|Log\.info|Log\.warn|Log\.error"

        self.vul_function = [
        "logger.info", "logger.warn", "logger.error", "logger.debug",
        "Rails.logger.info", "Rails.logger.warn", "Rails.logger.error", "Rails.logger.debug",
        "Logger.new"
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
