# -*- coding: utf-8 -*-

"""
    Go 不安全反序列化规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

import re
from utils.api import *

class CVI_8007(SingleRuleMixin):
    """
    Go 不安全反序列化规则
    Go 的 json/xml/yaml/toml.Unmarshal 到 struct 是类型安全的——
    只填充结构体字段，不执行任意代码。
    只有以下场景是真正危险的：
    1. json.Unmarshal/data 到 interface{}（无类型约束，可嵌入任意数据）
    2. gob.NewDecoder/Decode（gob 协议可触发方法调用）
    """

    def __init__(self):
        self.svid = 8007
        self.language = "go"
        self.vulnerability = "不安全反序列化"
        self.description = "使用了可能不安全的反序列化操作（json.Unmarshal到interface{}、gob.NewDecoder等），如果反序列化的数据来自不可信来源，可能导致安全风险。建议将数据反序列化到明确的结构体类型，避免使用interface{}。"
        self.level = 6

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"json\.Unmarshal\s*\(|json\.NewDecoder\s*\(|yaml\.Unmarshal\s*\(|yaml\.NewDecoder\s*\(|xml\.Unmarshal\s*\(|xml\.NewDecoder\s*\(|toml\.Decode\s*\(|toml\.NewDecoder\s*\(|gob\.NewDecoder\s*\(|gob\.NewEncoder\s*\(|encoding/gob|gopkg\.in/yaml|github\.com/BurntSushi/toml"

        self.vul_function = [
            "json.Unmarshal", "json.NewDecoder",
            "yaml.Unmarshal", "yaml.NewDecoder",
            "xml.Unmarshal", "xml.NewDecoder",
            "toml.Decode", "toml.NewDecoder",
            "gob.NewDecoder",
        ]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：只有反序列化到 interface{} 或使用 gob 协议时才是真正危险的。
        json/xml/yaml/toml Unmarshal 到 struct 是类型安全的。
        """
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            # Fall through to regex check

        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # DANGEROUS: json.Unmarshal to interface{}
        if re.search(r'json\.Unmarshal\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        # DANGEROUS: map[string]interface{} (untyped map)
        if re.search(r'map\[string\]interface\s*\{\s*\}', regex_string):
            return True

        # DANGEROUS: yaml/xml Unmarshal to interface{}
        if re.search(r'(?:yaml|xml)\.Unmarshal\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        # DANGEROUS: toml.Decode to interface{}
        if re.search(r'toml\.Decode\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        # DANGEROUS: gob uses its own wire protocol that can trigger method calls
        if re.search(r'gob\.New(?:De|En)coder\s*\(', regex_string):
            return True
        if re.search(r'encoding/gob', regex_string):
            return True

        # SAFE: json/xml/yaml/toml Unmarshal to struct (type-safe, no code exec)
        # Decode to typed struct is safe (e.g. gin's jsonBinding.Bind)
        if re.search(r'\bDecode\s*\(', regex_string):
            return False

        # SAFE: Unmarshal/Decode without interface{} target
        return False
