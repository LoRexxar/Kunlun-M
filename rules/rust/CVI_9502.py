# -*- coding: utf-8 -*-

"""
    Rust 路径遍历规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9502(SingleRuleMixin):
    """
    Rust 路径遍历规则
    匹配 fs::read_to_string, fs::write, fs::remove_file, fs::copy,
    std::fs::*, File::open 等文件操作调用。
    normalizer 中 sink callee name 为方法名（如 read_to_string, write, open 等）。
    """

    def __init__(self):
        self.svid = 9502
        self.language = "rust"
        self.vulnerability = "路径遍历"
        self.description = "使用了可能进行文件路径操作的函数（fs::read_to_string、fs::write、fs::remove_file、fs::copy、File::open等），可能导致路径遍历漏洞。建议对用户输入的文件路径进行规范化校验，限制可访问的目录范围。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = (
            r"\bread_to_string\s*\("
            r"|\bwrite\s*\("
            r"|\bremove_file\s*\("
            r"|\bcopy\s*\("
            r"|\bread_dir\s*\("
            r"|\bcreate_dir\s*\("
            r"|\bremove_dir_all\s*\("
            r"|\brename\s*\("
            r"|\bmetadata\s*\("
            r"|\bFile\s*::\s*open\s*\("
            r"|\bfs\s*::\s*(?:read_to_string|write|remove_file|copy|read_dir|create_dir|remove_dir_all|rename|metadata|canonicalize|read_link)\s*\("
        )

        self.vul_function = [
            "fs::read_to_string", "fs::write", "fs::remove_file", "fs::copy",
            "fs::read_dir", "fs::create_dir", "fs::remove_dir_all", "fs::rename",
            "fs::metadata", "fs::canonicalize", "fs::read_link",
            "File::open",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的文件路径操作调用，
        排除硬编码路径参数。
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

        # 提取文件操作函数的参数部分
        match = re.search(
            r'(?:read_to_string|write|remove_file|copy|read_dir|create_dir|remove_dir_all|rename|metadata|canonicalize|read_link|File::open)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（硬编码路径）
        # fs::read_to_string("config.toml")
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含文件路径操作调用
        dangerous_patterns = [
            r"read_to_string\s*\(",
            r"(?:std::)?fs::(?:read_to_string|write|remove_file|copy|read_dir|create_dir|remove_dir_all|rename|metadata|canonicalize|read_link)\s*\(",
            r"File::open\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
