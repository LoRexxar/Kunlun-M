# -*- coding: utf-8 -*-

"""
    TypeScript 反序列化漏洞规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9708(SingleRuleMixin):
    """
    TypeScript 反序列化漏洞规则
    匹配 unserialize、serialize.unserialize（node-serialize）以及特定场景下危险使用的 JSON.parse
    注意：callee 在 normalizer 中为方法名（如 unserialize、parse），不含对象前缀
          JSON.parse 本身在大多数情况下是安全的，但在特定场景下（如解析不受信的复杂嵌套对象、
          配合 __proto__ 污染）可能存在风险
          node-serialize 的 unserialize 存在远程代码执行漏洞（CVE-2017-5941）
    """

    def __init__(self):
        self.svid = 9708
        self.language = "typescript"
        self.vulnerability = "反序列化"
        self.description = "使用了可能存在反序列化漏洞的函数（node-serialize 的 unserialize、serialize.unserialize）或特定场景下不安全的 JSON.parse。node-serialize 的 unserialize 可导致远程代码执行（RCE，CVE-2017-5941）。JSON.parse 在解析包含 __proto__ 的不受信数据时可能导致原型污染。建议避免使用 node-serialize，使用 JSON.parse 时配合 schema 验证（如 zod/joi）对输入数据进行白名单校验。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(?:serialize\.)?unserialize\s*\(|JSON\.parse\s*\("

        self.vul_function = ["unserialize", "JSON.parse"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的反序列化调用。
        unserialize 总是危险的（可直接 RCE），标记为 True。
        JSON.parse 在参数为硬编码字符串时排除（安全），其他情况标记为潜在风险。
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

        # 处理 unserialize (node-serialize)
        unserialize_match = re.search(r'(?:serialize\.)?unserialize\s*\((.*)\)', regex_string, re.DOTALL)
        if unserialize_match:
            args = unserialize_match.group(1).strip()
            if not args:
                return False
            # unserialize 参数不应为硬编码（但即使硬编码也不代表安全）
            # unserialize 始终标记为危险
            return True

        # 处理 JSON.parse
        json_match = re.search(r'JSON\.parse\s*\((.*)\)', regex_string, re.DOTALL)
        if json_match:
            args = json_match.group(1).strip()
            if not args:
                return False
            # 如果参数是纯硬编码字符串字面量（不含模板变量），排除
            if re.match(r'^\"[^\"]*\"$', args) or re.match(r"^'[^']*'$", args):
                return False
            if re.match(r'^`[^`]*`$', args):
                return False
            # JSON.parse 的参数包含变量，标记为潜在风险
            # 实际风险取决于调用上下文和输入验证
            return True

        return None
