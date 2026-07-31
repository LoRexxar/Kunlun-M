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

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查反序列化目标是否为interface{}等不安全类型，
        排除反序列化到明确结构体的安全写法。
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

        # 只有 gob.NewDecoder 是不安全的（gob 使用 gob 协议，可触发任意方法调用）
        if re.search(r'gob\.NewDecoder\s*\(', regex_string):
            return True

        # json/yaml/xml/toml Unmarshal 到 interface{} 的已在上面单独检测；
        # Unmarshal 到明确 struct 是类型安全的，不再标记为漏洞。
        # Decode 到类型化结构体是安全的（如 gin 的 jsonBinding.Bind）
        if re.search(r'\bDecode\s*\(', regex_string):
            return False

        return None
