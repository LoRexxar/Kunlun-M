# -*- coding: utf-8 -*-

"""
    Lua 文件操作规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9603(SingleRuleMixin):
    """
    Lua 文件操作规则
    匹配 io.open / io.read / io.write / io.lines / io.close / os.rename / os.remove 等
    注意: Lua 中 sink callee name 在 normalizer 中是方法名，如 open, read, write, lines, close, rename, remove
    """

    def __init__(self):
        self.svid = 9603
        self.language = "lua"
        self.vulnerability = "文件操作"
        self.description = "使用了文件操作函数（io.open、io.read、io.write、io.lines、os.rename、os.remove等），如果路径参数包含用户输入，可能导致任意文件读取、写入或删除。建议对文件路径进行严格的白名单校验，避免路径穿越攻击。"
        self.level = 6

        # 部分配置
        self.match_mode = "function-param-regex"
        # sink callee name 在 normalizer 中是方法名
        self.match = r"\bopen\s*\(|\bread\s*\(|\bwrite\s*\(|\blines\s*\(|\bclose\s*\(|\brename\s*\(|\bremove\s*\("

        self.vul_function = [
            "io.open", "io.read", "io.write", "io.lines", "io.close",
            "os.rename", "os.remove",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的文件操作调用，
        排除硬编码路径和安全的写法。
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
        match = re.search(r'(?:open|read|write|lines|close|rename|remove)\s*\((.*)\)', regex_string)
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（双引号或单引号包裹的硬编码路径）
        # io.open("config.lua") -> 硬编码，排除
        if re.match(r'^["\'][^"\']*["\']$', args):
            return False

        # 检测路径穿越模式
        if re.search(r'\.\./', args):
            return True

        # 包含字符串拼接（.. 是 Lua 的字符串连接符）
        if re.search(r'\.\.', args):
            return True

        # 包含变量引用（说明路径可能来自用户输入）
        if re.search(r'\b[a-zA-Z_]\w*\b', args):
            return True

        return None
