# -*- coding: utf-8 -*-

"""
    Ruby 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9403(SingleRuleMixin):
    """
    Ruby 路径遍历规则
    匹配 File.read、File.open、File.write、File.delete、IO.read、Dir.glob 等文件/目录操作函数
    """

    def __init__(self):
        self.svid = 9403
        self.language = "ruby"
        self.vulnerability = "路径遍历"
        self.description = "使用了可能存在路径遍历风险的文件操作函数（File.read、File.open、File.write、File.delete、IO.read、Dir.glob等），且路径参数可能受用户控制。攻击者可利用 ../ 序列访问预期目录之外的文件。建议对用户输入进行路径规范化校验（File.expand_path），限制在安全目录内。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"File\.read\s*\(|File\.open\s*\(|File\.write\s*\(|File\.delete\s*\(|IO\.read\s*\(|Dir\.glob\s*\("

        # vul_function intentionally empty: match regex already requires
        # File./IO./Dir. prefix. Using bare "delete"/"read"/"open"/"write"
        # as vul_function would false-match cookies.delete, Hash.delete etc.
        self.vul_function = []

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除框架安全机制和硬编码路径。
        Rails 框架内部用 File.read/open 进行 CSRF token、session、
        flash、cache 等操作，路径由框架控制不是用户输入。
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
                # Framework-generated paths: variable names containing
                # csrf/session/flash/cache/tmp/pid → server-controlled, not user input
                arg_name = arg0.get('name', '').lower()
                _fw_prefixes = ('csrf', 'session', 'flash', 'cache', 'tmp',
                                'pid', 'secret_key', 'token_path', 'cookie')
                if any(p in arg_name for p in _fw_prefixes):
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # Framework security mechanism patterns in source context
        _fw_context = [
            r'csrf', r'session\s*[:.]', r'flash\s*[:.]', r'cache\s*[:.]',
            r'secret_key_base', r'verify_csrf_token', r'form_authenticity_token',
            r'cookie\s*[:.]', r'\btmp[\-/]',
        ]
        for pat in _fw_context:
            if re.search(pat, regex_string, re.I):
                return False

        # 提取函数调用参数部分
        match = re.search(r'(?:File|IO|Dir)\.(?:read|open|write|delete|glob)\s*\((.*)\)', regex_string, re.DOTALL)
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 提取路径参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            path_arg = arg_parts[0].strip()
        else:
            return None

        # 如果路径参数是纯硬编码字符串字面量，排除
        if re.match(r'^["\'][^"\']*["\']$', path_arg):
            return False

        # 确认包含危险的文件操作调用
        dangerous_patterns = [
            r"File\.read\s*\(",
            r"File\.open\s*\(",
            r"File\.write\s*\(",
            r"File\.delete\s*\(",
            r"IO\.read\s*\(",
            r"Dir\.glob\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None

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
