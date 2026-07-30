# -*- coding: utf-8 -*-

"""
    TypeScript XSS（跨站脚本攻击）规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9701(SingleRuleMixin):
    """
    TypeScript XSS（跨站脚本攻击）规则
    匹配 innerHTML、outerHTML 属性赋值，document.write、insertAdjacentHTML 等危险 DOM 操作
    注意：innerHTML/outerHTML 是属性赋值（=），不是方法调用
          document.write 的 callee 在 normalizer 中为 write
          insertAdjacentHTML 的 callee 在 normalizer 中为 insertAdjacentHTML
    """

    def __init__(self):
        self.svid = 9701
        self.language = "typescript"
        self.vulnerability = "XSS"
        self.description = "使用了可能存在XSS（跨站脚本攻击）风险的DOM操作（innerHTML赋值、outerHTML赋值、document.write、document.writeln、insertAdjacentHTML等），且内容可能受用户控制。攻击者可注入恶意JavaScript代码在受害者浏览器中执行。建议使用 textContent 代替 innerHTML，使用 createElement 代替字符串拼接DOM，对动态内容进行 HTML 转义（如 DOMPurify）。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\("

        self.vul_function = ["innerHTML", "outerHTML", "write", "writeln", "insertAdjacentHTML"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的XSS操作，
        排除硬编码字符串参数的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 处理属性赋值（innerHTML, outerHTML）
        prop_match = re.search(r'\.(innerHTML|outerHTML)\s*=\s*(.*)', regex_string)
        if prop_match:
            rhs = prop_match.group(2).strip()
            # 移除尾部分号
            rhs = rhs.rstrip(';').strip()
            # 如果赋值右侧是纯硬编码字符串字面量，排除
            if re.match(r'^\"[^\"]*\"$', rhs) or re.match(r"^'[^']*'$", rhs) or re.match(r'^`[^`]*`$', rhs):
                return False
            return True

        # 处理 document.write / document.writeln
        write_match = re.search(r'document\.write(?:ln)?\s*\((.*)\)', regex_string, re.DOTALL)
        if write_match:
            args = write_match.group(1).strip()
            if not args:
                return False
            # 如果参数是纯硬编码字符串字面量，排除
            if re.match(r'^\"[^\"]*\"$', args) or re.match(r"^'[^']*'$", args) or re.match(r'^`[^`]*`$', args):
                return False
            return True

        # 处理 insertAdjacentHTML
        adj_match = re.search(r'\.insertAdjacentHTML\s*\((.*)\)', regex_string, re.DOTALL)
        if adj_match:
            args = adj_match.group(1).strip()
            if not args:
                return False
            arg_parts = self._split_args(args)
            # insertAdjacentHTML 的第二个参数是插入的 HTML 内容
            if len(arg_parts) >= 2:
                html_arg = arg_parts[1].strip()
                if re.match(r'^\"[^\"]*\"$', html_arg) or re.match(r"^'[^']*'$", html_arg) or re.match(r'^`[^`]*`$', html_arg):
                    return False
            return True

        return None

    def _split_args(self, args_str):
        """简单按逗号分割参数，处理嵌套括号、字符串和模板字符串"""
        args = []
        depth = 0
        in_single = False
        in_double = False
        in_template = False
        current = []
        i = 0
        while i < len(args_str):
            ch = args_str[i]
            # 处理模板字符串中的 ${} 表达式
            if in_template and ch == '$' and i + 1 < len(args_str) and args_str[i + 1] == '{':
                depth += 1
                current.append('${')
                i += 2
                continue
            if ch == '"' and not in_single and not in_template and depth == 0:
                in_double = not in_double
                current.append(ch)
            elif ch == "'" and not in_double and not in_template and depth == 0:
                in_single = not in_single
                current.append(ch)
            elif ch == '`' and not in_single and not in_double and depth == 0:
                in_template = not in_template
                current.append(ch)
            elif in_single or in_double or in_template:
                current.append(ch)
            elif ch == '(' or ch == '{' or ch == '[':
                depth += 1
                current.append(ch)
            elif ch == ')' or ch == '}' or ch == ']':
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
