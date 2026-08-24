# -*- coding: utf-8 -*-

"""
    typescript 开放重定向规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9710(SingleRuleMixin):
    """
    typescript 开放重定向规则
    """

    def __init__(self):
        self.svid = 9710
        self.language = "typescript"
        self.vulnerability = "开放重定向"
        self.description = "使用未验证的用户输入作为重定向目标可能导致开放重定向漏洞。建议验证URL的域名白名单。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"redirect\s*\(|res\.redirect\s*\(|response\.redirect\s*\(|ctx\.redirect\s*\("

        self.vul_function = [
        "redirect", "res.redirect", "response.redirect", "ctx.redirect"
        ]

    def main(self, regex_string, sink_args=None, context=None):
        """
        二次筛选：
        - 硬编码字符串字面量 → safe
        - 相对路径重定向（./ prefix, relativeRoot）→ safe
        - redirect('/') — safe (same origin)
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            # Check context for relative path patterns
            if context:
                _ctx = context.lower() if isinstance(context, str) else str(context).lower()
                # relativeRoot, normalize(, ./ prefix → relative redirect
                if 'relativeroot' in _ctx or 'relative' in _ctx:
                    return False
            return None

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        args = regex_string.strip()

        if not args:
            return False

        # Hardcoded string literal → safe
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # Relative path redirect → safe (can't redirect to external domain)
        if re.search(r'\./|relativeRoot|relative_root|normalize\(', args):
            return False
        # redirect("/") — same origin
        if re.match(r'^["\']\/["\']$', args):
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
