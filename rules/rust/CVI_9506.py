# -*- coding: utf-8 -*-

"""
    Rust 反序列化规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9506(SingleRuleMixin):
    """
    Rust 反序列化规则
    匹配 serde_json::from_str, bincode::deserialize, from_reader 等反序列化调用。
    反序列化不受信任的数据可能导致远程代码执行或拒绝服务漏洞。
    normalizer 中 sink callee name 为方法名（如 from_str, deserialize, from_reader 等）。
    """

    def __init__(self):
        self.svid = 9506
        self.language = "rust"
        self.vulnerability = "反序列化"
        self.description = "使用了可能进行反序列化的函数（serde_json::from_str、bincode::deserialize、from_reader等），如果反序列化不受信任的数据可能导致远程代码执行或拒绝服务漏洞。建议对反序列化输入进行校验，或使用安全的反序列化方式。"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = (
            r"\bfrom_str\s*\("
            r"|\bfrom_reader\s*\("
            r"|\bfrom_slice\s*\("
            r"|\bdeserialize\s*\("
            r"|\bdeserialize_from\s*\("
            r"|\bload\s*\("
            r"|\bserde_json\s*::\s*(?:from_str|from_reader|from_slice|from_value)\s*\("
            r"|\bbincode\s*::\s*(?:deserialize|deserialize_from)\s*\("
            r"|\bson\s*::\s*from.*\s*\("
        )

        self.vul_function = [
            "serde_json::from_str", "serde_json::from_reader", "serde_json::from_slice",
            "serde_json::from_value",
            "bincode::deserialize", "bincode::deserialize_from",
            "from_str", "from_reader", "from_slice", "deserialize", "deserialize_from",
        ]

    def main(self, regex_string):
        """
        二次筛选：检查匹配到的代码行是否真正属于危险的 deserialization 调用，
        排除硬编码数据参数。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除常见的非反序列化 from_str 调用
        non_deser_patterns = [
            r"str::from_str",           # FromStr trait 通常是安全的
            r"std::str::FromStr",       # 同上
            r"String::from_str",        # 字符串转换
            r"char::from_str",          # 字符转换
            r"Number::from_str",        # 数字转换
            r"DateTime::from_str",      # 时间转换（chrono）
            r"Uuid::from_str",          # UUID 解析
            r"parse\s*::<",             # .parse::<Type>() 是安全的 FromStr 调用
        ]
        for pat in non_deser_patterns:
            if re.search(pat, regex_string):
                return False

        # 提取函数调用参数部分
        match = re.search(
            r'(?:from_str|from_reader|from_slice|deserialize|deserialize_from|load)\s*\((.*)\)',
            regex_string
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 纯字符串字面量（硬编码数据）
        # serde_json::from_str("{\"key\": \"value\"}")
        if re.match(r'^\"[^\"]*\"(?:\s*,\s*\"[^\"]*\")*$', args):
            return False

        # 确认包含危险的反序列化调用
        dangerous_patterns = [
            r"serde_json::(?:from_str|from_reader|from_slice|from_value)\s*\(",
            r"bincode::(?:deserialize|deserialize_from)\s*\(",
            r"\.from_str\s*\(",
            r"\.from_reader\s*\(",
            r"\.from_slice\s*\(",
            r"\.deserialize\s*\(",
            r"\.deserialize_from\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
