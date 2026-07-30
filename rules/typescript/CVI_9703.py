# -*- coding: utf-8 -*-

"""
    TypeScript 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9703(SingleRuleMixin):
    """
    TypeScript 路径遍历规则
    匹配 fs 模块的 readFile、writeFile、unlink、rename、createReadStream、createWriteStream 等文件操作函数
    注意：callee 在 normalizer 中为方法名（如 readFile、writeFile），不含对象前缀
          使用方式包括 fs.readFile() 和解构后直接 readFile() 两种
    """

    def __init__(self):
        self.svid = 9703
        self.language = "typescript"
        self.vulnerability = "路径遍历"
        self.description = "使用了可能存在路径遍历风险的文件操作函数（fs.readFile、fs.writeFile、fs.unlink、fs.rename、fs.createReadStream、fs.createWriteStream等），且路径参数可能受用户控制。攻击者可利用 ../ 序列访问预期目录之外的文件，导致敏感信息泄露或文件篡改。建议使用 path.resolve() + path.normalize() 对路径进行规范化校验，限制文件操作在安全目录内，使用白名单验证文件名。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|rename|renameSync|createReadStream|createWriteStream|appendFile|appendFileSync|exists|existsSync|rmdir|rmdirSync|mkdir|mkdirSync|readdir|readdirSync|stat|statSync)\s*\("

        self.vul_function = ["readFile", "readFileSync", "writeFile", "writeFileSync",
                             "unlink", "unlinkSync", "rename", "renameSync",
                             "createReadStream", "createWriteStream",
                             "appendFile", "appendFileSync", "exists", "existsSync",
                             "rmdir", "rmdirSync", "mkdir", "mkdirSync",
                             "readdir", "readdirSync", "stat", "statSync"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的路径遍历调用，
        排除硬编码路径参数（如 fs.readFile('/etc/passwd')）。
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
            r'(?:fs\.)?(?:readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|'
            r'rename|renameSync|createReadStream|createWriteStream|appendFile|appendFileSync|'
            r'exists|existsSync|rmdir|rmdirSync|mkdir|mkdirSync|readdir|readdirSync|'
            r'stat|statSync)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
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

        # 如果路径参数是纯硬编码字符串字面量（不含模板字符串变量），排除
        if re.match(r'^\"[^\"]*\"$', path_arg) or re.match(r"^'[^']*'$", path_arg):
            return False
        # 模板字符串中不包含 ${} 变量引用才是安全的
        if re.match(r'^`[^`]*`$', path_arg):
            return False

        # 确认包含危险的文件操作调用
        dangerous_patterns = [
            r"fs\.readFile\s*\(",
            r"fs\.readFileSync\s*\(",
            r"fs\.writeFile\s*\(",
            r"fs\.writeFileSync\s*\(",
            r"fs\.unlink\s*\(",
            r"fs\.unlinkSync\s*\(",
            r"fs\.rename\s*\(",
            r"fs\.renameSync\s*\(",
            r"fs\.createReadStream\s*\(",
            r"fs\.createWriteStream\s*\(",
            r"fs\.appendFile\s*\(",
            r"fs\.appendFileSync\s*\(",
            r"fs\.exists\s*\(",
            r"fs\.existsSync\s*\(",
            r"fs\.rmdir\s*\(",
            r"fs\.mkdir\s*\(",
            r"fs\.readdir\s*\(",
            r"fs\.stat\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        # 对于解构导入（无 fs. 前缀），也标记为潜在风险
        fs_funcs = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync',
                    'unlink', 'unlinkSync', 'rename', 'renameSync',
                    'createReadStream', 'createWriteStream',
                    'appendFile', 'appendFileSync', 'exists', 'existsSync',
                    'rmdir', 'rmdirSync', 'mkdir', 'mkdirSync',
                    'readdir', 'readdirSync', 'stat', 'statSync']
        for func in fs_funcs:
            if re.search(r'(?<![.\w])' + re.escape(func) + r'\s*\(', regex_string):
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
