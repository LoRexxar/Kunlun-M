# -*- coding: utf-8 -*-

"""
    TypeScript SSRF（服务端请求伪造）规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9704(SingleRuleMixin):
    """
    TypeScript SSRF（服务端请求伪造）规则
    匹配 fetch、http.get、http.request、axios.get、axios.post 等网络请求函数
    注意：callee 在 normalizer 中为方法名（如 fetch、get、request、post），不含对象前缀
          fetch 是全局函数，http/axios 方法需带前缀匹配
    """

    def __init__(self):
        self.svid = 9704
        self.language = "typescript"
        self.vulnerability = "SSRF"
        self.description = "使用了可能存在SSRF（服务端请求伪造）风险的网络请求函数（fetch、http.get、http.request、axios.get、axios.post等），且URL参数可能受用户控制。攻击者可利用此漏洞访问内网资源、云元数据服务（如169.254.169.254）或进行端口探测。建议对URL参数进行白名单校验，禁止请求内网地址和敏感元数据端点，限制允许的协议和端口范围。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:http|https)\.(?:get|request)\s*\(|axios\.(?:get|post|put|delete|patch|request)\s*\(|(?<![.\w])fetch\s*\("

        self.vul_function = ["fetch", "get", "request", "post", "put", "delete", "patch"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的SSRF调用，
        排除硬编码URL参数（如 fetch('https://api.example.com/health')）。
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
        # fetch(...)
        fetch_match = re.search(r'(?<![.\w])fetch\s*\((.*)\)', regex_string, re.DOTALL)
        # http.get(...) / http.request(...)
        http_match = re.search(r'(?:http|https)\.(?:get|request)\s*\((.*)\)', regex_string, re.DOTALL)
        # axios.get(...) / axios.post(...) etc.
        axios_match = re.search(r'axios\.(?:get|post|put|delete|patch|request)\s*\((.*)\)', regex_string, re.DOTALL)

        args = None
        if fetch_match:
            args = fetch_match.group(1).strip()
        elif http_match:
            args = http_match.group(1).strip()
        elif axios_match:
            args = axios_match.group(1).strip()

        if args is None:
            return None

        # 如果参数为空，排除
        if not args:
            return False

        # 提取URL参数（第一个参数）
        arg_parts = self._split_args(args)
        if len(arg_parts) >= 1:
            url_arg = arg_parts[0].strip()
        else:
            return None

        # 如果URL参数是纯硬编码字符串字面量（不含模板变量），排除
        if re.match(r'^\"[^\"]*\"$', url_arg) or re.match(r"^'[^']*'$", url_arg):
            return False
        if re.match(r'^`[^`]*`$', url_arg):
            return False

        # 确认包含危险的网络请求调用
        dangerous_patterns = [
            r"(?:http|https)\.get\s*\(",
            r"(?:http|https)\.request\s*\(",
            r"axios\.get\s*\(",
            r"axios\.post\s*\(",
            r"axios\.put\s*\(",
            r"axios\.delete\s*\(",
            r"axios\.patch\s*\(",
            r"axios\.request\s*\(",
            r"(?<![.\w])fetch\s*\(",
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
