# -*- coding: utf-8 -*-

"""
    Node.js 命令注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3100(SingleRuleMixin):
    """
    Node.js 命令注入规则
    匹配 child_process.exec/execSync/execFile/spawn 等命令执行函数
    """

    def __init__(self):
        self.svid = 3100
        self.language = "javascript"
        self.vulnerability = "命令注入"
        self.description = "使用了可能执行系统命令的函数（child_process.exec、child_process.execSync、child_process.spawn等），可能导致命令注入漏洞。建议对用户输入进行严格校验和转义，避免将用户输入直接传递给命令执行函数。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"exec\s*\(|execSync\s*\(|execFile\s*\(|execFileSync\s*\(|spawn\s*\(|spawnSync\s*\(|fork\s*\("

        self.vul_function = [
            "exec", "execSync", "execFile", "execFileSync",
            "spawn", "spawnSync", "fork",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除硬编码命令字符串，排除非 child_process 的 exec 调用
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

        # 排除明显的非命令执行 exec 调用
        # RegExp.prototype.exec, document.execCommand 等
        non_cmd_patterns = [
            r"\.exec\s*\(",           # obj.exec() — 但 child_process 也通过 .exec 调用
            r"execCommand\s*\(",
            r"execute\s*\(",
        ]

        # 检查是否有 child_process 相关的导入或调用模式
        has_cp_context = bool(re.search(
            r'child_process|require\s*\(\s*["\']child_process["\']\s*\)',
            regex_string
        ))

        # 纯字符串字面量参数（硬编码命令）
        match = re.search(r'(?:exec|execSync|execFile|spawn)\s*\((.*)\)', regex_string)
        if match:
            args = match.group(1).strip()
            # exec("ls -la") — 硬编码命令，排除
            if re.match(r'^["\'][^"\']*["\'](?:\s*,\s*["\'][^"\']*["\'])*$', args):
                return False

        # 如果有明确的 child_process 上下文，保留
        if has_cp_context:
            return True

        # spawn/spawnSync/fork 几乎只用于 child_process
        if re.search(r'(?:spawn|spawnSync|fork|execFile|execFileSync)\s*\(', regex_string):
            return True

        # 对于 exec/execSync，如果出现在 require('child_process') 同一文件中，保留
        # 否则可能是 RegExp.exec 等，需要更多上下文判断
        return None
