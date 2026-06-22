# -*- coding: utf-8 -*-

"""
    Kotlin 代码注入规则
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re
from utils.api import *

class CVI_9306(SingleRuleMixin):
    """
    Kotlin 代码注入规则
    匹配 Class.forName, ClassLoader.loadClass, DEXClassLoader 等动态类加载
    """

    def __init__(self):
        self.svid = 9306
        self.language = "kotlin"
        self.vulnerability = "代码注入"
        self.description = "使用了动态类加载函数（Class.forName、ClassLoader.loadClass、DEXClassLoader、PathClassLoader等），当类名来自用户输入时，可能导致任意代码执行漏洞。攻击者可能通过加载恶意类来执行任意代码。建议对类名进行严格的白名单校验，避免从用户输入中直接获取类名。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"Class\s*\.\s*forName\s*\(\s*\w+|ClassLoader\s*\.\s*loadClass\s*\(\s*\w+|\.loadClass\s*\(\s*\w+|DEXClassLoader\s*\(\s*\w+|PathClassLoader\s*\(\s*\w+|DexClassLoader\s*\(\s*\w+|\.newInstance\s*\(\s*\)|defineClass\s*\(\s*\w+"

        self.vul_function = [
            "Class.forName", "ClassLoader.loadClass", "loadClass",
            "DEXClassLoader", "DexClassLoader", "PathClassLoader",
            "newInstance", "defineClass",
        ]

    def main(self, regex_string):
        """
        二次筛选：排除硬编码类名的安全写法。
        """
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 确认包含动态类加载上下文
        has_load_context = bool(re.search(
            r'Class\s*\.\s*forName|loadClass|DEXClassLoader|DexClassLoader|PathClassLoader|defineClass',
            regex_string
        ))

        if not has_load_context:
            return None

        # 提取函数调用参数部分
        match = re.search(
            r'(?:Class\s*\.\s*forName|loadClass|DEXClassLoader|DexClassLoader|PathClassLoader|defineClass)\s*\((.*?)\)',
            regex_string
        )
        if match:
            args = match.group(1).strip()
            # 纯字符串字面量类名（硬编码）
            if re.match(r'^"[^"]*"$', args):
                return False

        # 字符串拼接或模板变量作为类名
        if re.search(r'"\s*\+\s*\w+', regex_string) or re.search(r'\$\w+', regex_string):
            return True

        # 变量作为类名参数
        if re.search(r'(?:Class\s*\.\s*forName|loadClass|DEXClassLoader|DexClassLoader|PathClassLoader|defineClass)\s*\(\s*\w+', regex_string):
            return True

        return None
