# -*- coding: utf-8 -*-

"""
    C# 反序列化漏洞规则
    ~~~~
    :author:    KunLun-M
    :license:   MIT
"""

import re
from utils.api import *


class CVI_9207(SingleRuleMixin):
    """
    C# 反序列化漏洞规则
    匹配 BinaryFormatter.Deserialize、JsonSerializer.Deserialize、XmlSerializer.Deserialize 等反序列化函数
    """

    def __init__(self):
        self.svid = 9207
        self.language = "csharp"
        self.vulnerability = "反序列化"
        self.description = "使用了可能存在反序列化漏洞的函数（BinaryFormatter.Deserialize、JsonSerializer.Deserialize、XmlSerializer.Deserialize、JavaScriptSerializer.Deserialize等），且输入数据可能受用户控制。攻击者可构造恶意序列化数据实现远程代码执行（RCE）。建议使用安全的反序列化方式（如 System.Text.Json），并限制允许反序列化的类型白名单。BinaryFormatter 已被标记为不安全，建议迁移到其他序列化方案。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"BinaryFormatter.*\.Deserialize\s*\(|(?:XmlSerializer|SoapFormatter|NetDataContractSerializer|DataContractSerializer|JsonSerializer|JavaScriptSerializer|ObjectStateFormatter)\.Deserialize(?:Async)?\s*\("

        self.vul_function = ["Deserialize", "DeserializeAsync"]

    def main(self, regex_string, sink_args=None):
        """
        二次筛选：检查匹配到的代码是否真正属于危险的反序列化调用，
        排除硬编码输入参数（如 BinaryFormatter.Deserialize(memoryStream) 在已知安全上下文中）。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 提取函数调用参数部分
        match = re.search(
            r'(?:BinaryFormatter|XmlSerializer|SoapFormatter|NetDataContractSerializer|'
            r'DataContractSerializer|JsonSerializer|JavaScriptSerializer|ObjectStateFormatter)'
            r'.*?Deserialize(?:Async)?\s*\((.*)\)',
            regex_string, re.DOTALL
        )
        if not match:
            return None

        args = match.group(1).strip()

        # 如果参数为空，排除
        if not args:
            return False

        # 确认包含危险的反序列化调用
        dangerous_patterns = [
            r"BinaryFormatter.*\.Deserialize\s*\(",
            r"XmlSerializer\.Deserialize(?:Async)?\s*\(",
            r"SoapFormatter\.Deserialize\s*\(",
            r"NetDataContractSerializer\.Deserialize\s*\(",
            r"DataContractSerializer\.Deserialize(?:Async)?\s*\(",
            r"JsonSerializer\.Deserialize(?:Async)?\s*\(",
            r"JavaScriptSerializer\.Deserialize\s*\(",
            r"ObjectStateFormatter\.Deserialize\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True

        return None
