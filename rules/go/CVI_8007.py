# -*- coding: utf-8 -*-

"""
    Go 不安全反序列化规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_8007(SingleRuleMixin):
    """
    Go 不安全反序列化规则
    匹配 json.Unmarshal 到 interface{}、yaml.Unmarshal、xml.NewDecoder、
    toml.Decode、gob.NewDecoder 等不安全的反序列化操作
    """

    def __init__(self):
        self.svid = 8007
        self.language = "go"
        self.vulnerability = "不安全反序列化"
        self.description = "使用了可能不安全的反序列化操作（json.Unmarshal到interface{}、yaml.Unmarshal、xml.NewDecoder、toml.Decode、gob.NewDecoder等），如果反序列化的数据来自不可信来源，可能导致安全风险。建议将数据反序列化到明确的结构体类型，避免使用interface{}。"
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

    def main(self, regex_string):
        """
        二次筛选：检查反序列化目标是否为interface{}等不安全类型，
        排除反序列化到明确结构体的安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 检测 json.Unmarshal 到 interface{} 或 map[string]interface{}
        if re.search(r'json\.Unmarshal\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        if re.search(r'map\[string\]interface\s*\{\s*\}', regex_string):
            return True

        # 检测 json.NewDecoder 后接 .Decode() 到 interface{}
        # 注意：json.NewDecoder().Decode() 到明确结构体是安全的（如 gin 的 binding）
        # 只有到 interface{} 才危险，但这里我们无法从 regex_string 判断目标类型，
        # 暂时不标记 json.NewDecoder，依赖后续 taint analysis 判断
        # if re.search(r'json\.NewDecoder\s*\(', regex_string):
        #     return True

        # 检测 yaml.Unmarshal/xml.Unmarshal 到 interface{}
        if re.search(r'(?:yaml|xml)\.Unmarshal\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        # 检测 toml.Decode 到 interface{}
        if re.search(r'toml\.Decode\s*\([^)]*interface\s*\{\s*\}', regex_string):
            return True

        # 检测 gob.NewDecoder
        if re.search(r'gob\.NewDecoder\s*\(', regex_string):
            return True

        # 通用匹配：只要有反序列化调用就标记（可能需要人工审查）
        if re.search(r'(?:json|yaml|xml|toml)\.Unmarshal\s*\(', regex_string):
            return True

        # Decode 到类型化结构体是安全的（如 gin 的 jsonBinding.Bind）
        if re.search(r'\bDecode\s*\(', regex_string):
            return False

        return None
