# -*- coding: utf-8 -*-

"""
    TypeScript 代码注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9707(SingleRuleMixin):
    """
    TypeScript 代码注入规则
    匹配 eval、Function 构造函数、vm 模块的 runInContext/runInNewContext/runInThisContext 等动态代码执行函数
    注意：callee 在 normalizer 中为方法名（如 eval、Function、runInContext），不含对象前缀
          new Function 是构造函数调用，callee 为 Function
          vm.runInContext 的 callee 为 runInContext
    """

    def __init__(self):
        self.svid = 9707
        self.language = "typescript"
        self.vulnerability = "代码注入"
        self.description = "使用了可能存在代码注入风险的动态代码执行函数（eval、new Function、vm.runInContext、vm.runInNewContext、vm.runInThisContext、vm.compileFunction等），且参数可能受用户控制。攻击者可注入并执行任意JavaScript代码，导致服务器被完全控制。建议避免使用 eval 和 Function 构造函数，使用 vm2 或 isolated-vm 的沙箱执行不受信代码，限制 vm 沙箱的上下文和超时时间。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:new\s+)?Function\s*\(\s*[\"']|(?<![.\w])eval\s*\(|vm\.(?:runInContext|runInNewContext|runInThisContext|runInVm|compileFunction|createScript|createContext)\s*\("

        self.vul_function = ["eval", "Function", "runInContext", "runInNewContext",
                             "runInThisContext", "compileFunction", "createScript", "createContext"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的代码注入调用，
        排除硬编码字符串参数的情况。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 处理 eval(...)
        eval_match = re.search(r'(?<![.\w])eval\s*\((.*)\)', regex_string, re.DOTALL)
        if eval_match:
            args = eval_match.group(1).strip()
            if not args:
                return False
            if re.match(r'^\"[^\"]*\"$', args) or re.match(r"^'[^']*'$", args) or re.match(r'^`[^`]*`$', args):
                return False
            return True

        # 处理 new Function(...) / Function(...)
        func_match = re.search(r'(?:new\s+)?Function\s*\((.*)\)', regex_string, re.DOTALL)
        if func_match:
            args = func_match.group(1).strip()
            if not args:
                return False
            # Function 构造函数的参数是函数体，通常不为空
            arg_parts = self._split_args(args)
            all_literal = True
            for arg in arg_parts:
                arg = arg.strip()
                if not arg:
                    continue
                if not (re.match(r'^\"[^\"]*\"$', arg) or
                        re.match(r"^'[^']*'$", arg) or
                        re.match(r'^`[^`]*`$', arg)):
                    all_literal = False
                    break
            if all_literal:
                return False
            return True

        # 处理 vm 模块方法
        vm_match = re.search(
            r'vm\.(?:runInContext|runInNewContext|runInThisContext|runInVm|compileFunction|createScript|createContext)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if vm_match:
            args = vm_match.group(1).strip()
            if not args:
                return False
            # vm 方法的第一个参数通常是代码字符串
            arg_parts = self._split_args(args)
            if len(arg_parts) >= 1:
                code_arg = arg_parts[0].strip()
                if re.match(r'^\"[^\"]*\"$', code_arg) or re.match(r"^'[^']*'$", code_arg) or re.match(r'^`[^`]*`$', code_arg):
                    return False
            return True

        # 确认包含危险的代码执行调用
        dangerous_patterns = [
            r"(?<![.\w])eval\s*\(",
            r"(?:new\s+)?Function\s*\(",
            r"vm\.runInContext\s*\(",
            r"vm\.runInNewContext\s*\(",
            r"vm\.runInThisContext\s*\(",
            r"vm\.runInVm\s*\(",
            r"vm\.compileFunction\s*\(",
            r"vm\.createScript\s*\(",
            r"vm\.createContext\s*\(",
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
