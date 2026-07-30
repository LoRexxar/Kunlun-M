# -*- coding: utf-8 -*-

"""
    C# SSRF规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9204(SingleRuleMixin):
    """
    C# SSRF（服务端请求伪造）规则
    匹配 HttpClient.GetStringAsync、WebRequest.Create、HttpWebRequest 等网络请求函数
    """

    def __init__(self):
        self.svid = 9204
        self.language = "csharp"
        self.vulnerability = "SSRF"
        self.description = "使用了可能存在SSRF（服务端请求伪造）风险的网络请求函数（HttpClient.GetStringAsync、WebRequest.Create、HttpWebRequest等），且URL参数可能受用户控制。攻击者可利用此漏洞访问内网资源、云元数据服务等。建议对URL参数进行白名单校验，禁止请求内网地址和敏感元数据端点。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:HttpClient|_httpClient|_client)\.(?:GetStringAsync|GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\(|WebRequest\.Create\s*\(|HttpWebRequest\s*\(|(?:new\s+)?HttpClient\s*\("

        self.vul_function = ["GetStringAsync", "GetAsync", "PostAsync", "PutAsync",
                             "DeleteAsync", "SendAsync", "Create", "HttpWebRequest"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的SSRF调用，
        排除硬编码URL参数（如 HttpClient.GetStringAsync("https://api.example.com/health")）。
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
            r'(?:HttpClient|_httpClient|_client)\.(?:GetStringAsync|GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync)\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        webreq_match = re.search(r'WebRequest\.Create\s*\((.*)\)', regex_string, re.DOTALL)

        args = None
        if match:
            args = match.group(1).strip()
        elif webreq_match:
            args = webreq_match.group(1).strip()

        if args is None:
            # HttpWebRequest 构造函数本身不携带URL参数（通过 .Method/.RequestUri 赋值），
            # 直接标记为潜在风险
            if re.search(r'HttpWebRequest', regex_string):
                return True
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

        # 如果URL参数是纯硬编码字符串字面量，排除
        if re.match(r'^"[^"]*"$', url_arg) or re.match(r'^@"[^"]*"$', url_arg):
            return False

        # 确认包含危险的网络请求调用
        dangerous_patterns = [
            r"HttpClient\.GetStringAsync\s*\(",
            r"HttpClient\.GetAsync\s*\(",
            r"HttpClient\.PostAsync\s*\(",
            r"HttpClient\.PutAsync\s*\(",
            r"HttpClient\.DeleteAsync\s*\(",
            r"HttpClient\.SendAsync\s*\(",
            r"WebRequest\.Create\s*\(",
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
