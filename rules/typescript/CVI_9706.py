# -*- coding: utf-8 -*-

"""
    TypeScript 原型污染规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9706(SingleRuleMixin):
    """
    TypeScript 原型污染规则
    匹配 Object.assign、lodash.merge、_.merge、deepmerge 等深度合并函数
    注意：callee 在 normalizer 中为方法名（如 assign、merge），不含对象前缀
          Object.assign 虽然不会直接修改原型，但深度合并函数会
          lodash < 4.17.12 的 merge/mergeWith/extend 等存在原型污染漏洞
    """

    def __init__(self):
        self.svid = 9706
        self.language = "typescript"
        self.vulnerability = "原型污染"
        self.description = "使用了可能存在原型污染风险的深度合并函数（Object.assign、lodash.merge、_.merge、_.extend、_.defaultsDeep、deepmerge等），且合并的源数据可能受用户控制。攻击者可利用此漏洞修改 Object.prototype，影响所有对象的行为，导致权限绕过或拒绝服务。建议使用 Object.assign（不递归）替代 lodash.merge，或升级 lodash 至 4.17.12+，使用 Map 代替普通对象存储用户输入。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Object\.assign\s*\(|lodash\.merge(?:With|All)?\s*\(|_\.(?:merge|mergeWith|mergeAll|extend|extendDeep|defaultsDeep)\s*\(|deepmerge\s*\(|(?<![.\w])merge\s*\("

        self.vul_function = ["assign", "merge", "mergeWith", "mergeAll", "extend", "extendDeep",
                             "defaultsDeep", "deepmerge"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的原型污染调用。
        Object.assign 不递归合并，风险较低但仍然标记。
        深度合并函数（merge/extend/defaultsDeep）递归合并，原型污染风险高。
        排除所有参数都是硬编码字面量的情况。
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
        match = re.search(
            r'(?:Object\.assign|lodash\.merge(?:With|All)?|'
            r'_\.(?:merge|mergeWith|mergeAll|extend|extendDeep|defaultsDeep)|'
            r'deepmerge|(?<![.\w])merge)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 分割参数
        arg_parts = self._split_args(args)

        # 检查是否所有参数都是硬编码字面量
        all_literal = True
        for arg in arg_parts:
            arg = arg.strip()
            if not arg:
                continue
            if not (re.match(r'^\"[^\"]*\"$', arg) or
                    re.match(r"^'[^']*'$", arg) or
                    re.match(r'^`[^`]*`$', arg) or
                    re.match(r'^\d+$', arg)):
                all_literal = False
                break

        if all_literal:
            return False

        # 确认包含危险的原型污染相关调用
        dangerous_patterns = [
            r"Object\.assign\s*\(",
            r"lodash\.merge\s*\(",
            r"lodash\.mergeWith\s*\(",
            r"lodash\.mergeAll\s*\(",
            r"_\.merge\s*\(",
            r"_\.mergeWith\s*\(",
            r"_\.extend\s*\(",
            r"_\.extendDeep\s*\(",
            r"_\.defaultsDeep\s*\(",
            r"deepmerge\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
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
            elif ch in ('(', '{', '['):
                depth += 1
                current.append(ch)
            elif ch in (')', '}', ']'):
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
