# -*- coding: utf-8 -*-

"""
    Go XSS 规则 - fmt.Fprintf
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8008(SingleRuleMixin):
    """
    检测 fmt.Fprintf 写入 http.ResponseWriter 的 XSS 漏洞
    """

    def __init__(self):
        self.svid = 8008
        self.language = "go"
        self.vulnerability = "XSS"
        self.description = "通过fmt.Fprintf直接向ResponseWriter写入未转义内容，可能导致跨站脚本攻击(XSS)。建议使用html/template包的自动转义功能，或对输出内容进行HTML转义。"
        self.level = 5

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"fmt\.Fprintf\s*\("

        self.vul_function = [
            "fmt.Fprintf",
        ]

    def main(self, regex_string, sink_args=None):
        """
        精确筛选 fmt.Fprintf 调用是否可能引发 XSS。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        if not re.search(r'fmt\.Fprintf\s*\(', regex_string):
            return None

        # 1. 检查安全过滤函数包裹
        safe_wrappers = [
            r'html\.EscapeString\s*\(',
            r'template\.HTMLEscapeString\s*\(',
            r'template\.HTMLEscape\s*\(',
            r'template\.JSEscapeString\s*\(',
            r'template\.JSEscape\s*\(',
        ]
        for pat in safe_wrappers:
            if re.search(pat, regex_string):
                return False

        # 2. 解析 fmt.Fprintf 的参数列表
        match = re.search(r'fmt\.Fprintf\s*\(', regex_string)
        if not match:
            return None

        start = match.end()
        depth = 1
        pos = start
        while pos < len(regex_string) and depth > 0:
            ch = regex_string[pos]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            pos += 1

        args_str = regex_string[start:pos - 1].strip()

        # 3. 拆分参数
        args = self._split_args(args_str)

        # 4. 如果只有1个参数（fmt.Fprintf(w)），不关注
        if len(args) <= 1:
            return None

        # 5. 检查 format string 参数（第二个参数）
        fmt_arg = args[1].strip()

        # 5a. format string 是变量（非字符串字面量）→ 可控，XSS 风险
        if not fmt_arg.startswith('"') and not fmt_arg.startswith('`') and not fmt_arg.startswith("'"):
            return True

        # 5b. format string 是字符串字面量
        # 非字符串格式化动词（数字/布尔等），不会输出 HTML
        safe_verbs = {r'%d', r'%f', r'%t', r'%b', r'%o', r'%c', r'%U',
                      r'%e', r'%E', r'%g', r'%G', r'%p'}

        # 提取所有格式化动词
        format_verbs = re.findall(r'%[#0\- +]*\d*(?:\.\d+)?[defbgopctUEGTvxXqsrwk]', fmt_arg)

        if not format_verbs:
            # 没有格式化动词，format string 是纯字面量
            # 检查是否包含变量拼接的 HTML 内容
            return False

        # 检查是否只包含安全（非字符串）格式化动词
        has_string_verb = False
        for verb in format_verbs:
            verb_type = verb[-1]
            if verb_type in ('s', 'v', 'q', 'r', 'w', 'k', 'x', 'X'):
                has_string_verb = True
                break

        if has_string_verb:
            return True

        return False

    def _split_args(self, args_str):
        """按逗号拆分参数列表，正确处理嵌套括号和字符串。"""
        args = []
        depth = 0
        current = []
        in_string = False
        string_char = None
        i = 0

        while i < len(args_str):
            ch = args_str[i]

            if in_string:
                current.append(ch)
                if ch == '\\':
                    # 转义字符，跳过下一个字符
                    if i + 1 < len(args_str):
                        i += 1
                        current.append(args_str[i])
                elif ch == string_char:
                    in_string = False
                i += 1
                continue

            if ch in ('"', "'", '`'):
                in_string = True
                string_char = ch
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

            i += 1

        if current:
            args.append(''.join(current))

        return args
