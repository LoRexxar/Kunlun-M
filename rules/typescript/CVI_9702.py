# -*- coding: utf-8 -*-

"""
    TypeScript 命令注入规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9702(SingleRuleMixin):
    """
    TypeScript 命令注入规则
    匹配 child_process 模块的 exec、execSync、spawn、spawnSync、execFile、execFileSync 等命令执行函数
    注意：callee 在 normalizer 中为方法名（如 exec、spawn），不含对象前缀
          使用方式包括 child_process.exec() 和解构后直接 exec() 两种
    """

    def __init__(self):
        self.svid = 9702
        self.language = "typescript"
        self.vulnerability = "命令注入"
        self.description = "使用了可能存在命令注入风险的函数（child_process.exec、child_process.execSync、child_process.spawn、child_process.spawnSync、child_process.execFile、child_process.execFileSync等），且参数可能受用户控制。攻击者可注入任意系统命令导致服务器被完全控制。建议使用 spawn 且传递参数数组而非拼接命令字符串，避免直接将用户输入拼接到 shell 命令中。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\("

        self.vul_function = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除所有参数都是硬编码字符串字面量的情况。
        如果所有参数都是硬编码字符串（如 exec('echo hello')），返回 False（安全）。
        对于 spawn/execFile 类函数，第一个参数（命令名）为硬编码是正常的，
        重点关注后续参数（命令参数数组或选项对象）中是否包含变量。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 判断是 exec 类还是 spawn 类
        is_exec_style = bool(re.search(r'(?:child_process\.)?(?:exec|execSync)\s*\(', regex_string))
        is_spawn_style = bool(re.search(r'(?:child_process\.)?(?:spawn|spawnSync|execFile|execFileSync)\s*\(', regex_string))

        arg_parts = self._split_args(args)

        if is_exec_style:
            # exec/execSync 的第一个参数是完整的命令字符串
            # 如果命令字符串是纯硬编码字面量，排除
            if len(arg_parts) >= 1:
                cmd_arg = arg_parts[0].strip()
                if re.match(r'^\"[^\"]*\"$', cmd_arg) or re.match(r"^'[^']*'$", cmd_arg) or re.match(r'^`[^`]*`$', cmd_arg):
                    return False
            return True

        elif is_spawn_style:
            # spawn/execFile 的参数为 (command, args[], options?)
            # command 是硬编码通常安全，但 args 数组中包含变量则危险
            if len(arg_parts) >= 1:
                cmd_arg = arg_parts[0].strip()
                # 命令本身是硬编码，检查是否有第二个参数（参数数组）
                if len(arg_parts) >= 2:
                    args_param = arg_parts[1].strip()
                    # 如果第二个参数是空数组字面量，安全
                    if re.match(r'^\[\s*\]$', args_param):
                        return False
                    # 如果第二个参数是纯字面量数组（如 ['ls', '-la']），安全
                    if re.match(r'^\[[^\[\]]*\]$', args_param):
                        return False
                # 只有命令名，没有额外参数，安全
                if len(arg_parts) == 1:
                    return False
            return True

        # 确认包含危险的命令执行调用
        dangerous_patterns = [
            r"(?:child_process\.)?exec\s*\(",
            r"(?:child_process\.)?execSync\s*\(",
            r"(?:child_process\.)?spawn\s*\(",
            r"(?:child_process\.)?spawnSync\s*\(",
            r"(?:child_process\.)?execFile\s*\(",
            r"(?:child_process\.)?execFileSync\s*\(",
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
