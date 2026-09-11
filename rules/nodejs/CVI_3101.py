# -*- coding: utf-8 -*-

"""
    Node.js 路径穿越规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_3101(SingleRuleMixin):
    """
    Node.js 路径穿越规则
    匹配 fs 文件系统操作函数，用户可控路径可能导致路径穿越
    """

    def __init__(self):
        self.svid = 3101
        self.language = "javascript"
        self.vulnerability = "路径穿越"
        self.description = "使用了文件系统操作函数（fs.readFile、fs.writeFile、fs.readFileSync等）且路径参数可能受用户控制，可能导致路径穿越漏洞。建议对用户输入的路径进行规范化处理（path.resolve）并校验是否在允许的目录范围内。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"readFileSync\s*\(|readFile\s*\(|writeFileSync\s*\(|writeFile\s*\(|appendFileSync\s*\(|appendFile\s*\(|createReadStream\s*\(|createWriteStream\s*\(|openSync\s*\(|open\s*\(|unlinkSync\s*\(|unlink\s*\(|readdirSync\s*\(|readdir\s*\(|renameSync\s*\(|rename\s*\("

        self.vul_function = [
            "readFileSync", "readFile", "writeFileSync", "writeFile",
            "appendFileSync", "appendFile", "createReadStream", "createWriteStream",
            "openSync", "open", "unlinkSync", "unlink",
            "readdirSync", "readdir", "renameSync", "rename",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：排除纯硬编码路径
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

        # 检查是否有 fs 相关上下文
        has_fs_context = bool(re.search(
            r'fs\.|require\s*\(\s*["\']fs["\']\s*\)|require\s*\(\s*["\']fs/promises["\']\s*\)|promises\.',
            regex_string
        ))

        if not has_fs_context:
            return None

        # 排除纯硬编码路径
        match = re.search(
            r'(?:readFileSync|readFile|writeFileSync|writeFile|appendFileSync|appendFile|'
            r'createReadStream|createWriteStream|openSync|open|unlinkSync|unlink|'
            r'readdirSync|readdir|renameSync|rename)\s*\((.*)\)',
            regex_string
        )
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量路径（硬编码）
            if re.match(r'^["\'][^"\']*["\'](?:\s*,.*)?$', args):
                return False

        return True
