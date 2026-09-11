# -*- coding: utf-8 -*-

"""
    Java SQL Injection Rule (AST-enhanced)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

import re

from utils.api import *

class CVI_6001(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6001
        self.language = "java"
        self.vulnerability = "SQL Injection"
        self.description = "通过AST分析检测Statement的executeQuery/executeUpdate/execute等方法参数是否来自用户可控输入，追踪数据流以发现SQL注入漏洞。建议使用PreparedStatement进行参数化查询。"
        self.level = 8

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "createStatement|executeQuery|executeUpdate|execute|addBatch"

        # for regex
        self.unmatch = [
            r"PreparedStatement",
            r"prepareStatement",
            r"@Query",
            r"\.newCall\s*\(",      # OkHttp: client.newCall(request).execute()
            r"HttpResponse",       # Apache HttpClient: response.execute()
            r"CloseableHttpClient",  # Apache HttpClient context
            r"DefaultHttpClient",    # Apache HttpClient context
        ]

        self.vul_function = [

            "Statement.executeQuery",

            "Statement.executeUpdate",

            "Statement.addBatch",

        ]

    def main(self, regex_string, sink_args=None):
        """
        Graph-based filtering: the graph's find_sinks already resolves
        receiver type via use edges (Path 2), so PreparedStatement vs
        Statement is handled at sink-name matching level.
        
        Here we check sink_args for additional context: if the SQL
        query arg is a hardcoded const string, it's not injectable.
        """
        if sink_args:
            # executeQuery("SELECT ...") with const string → not injectable
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        # Regex fallback: filter safe APIs
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)
        safe_patterns = [
            r"PreparedStatement", r"prepareStatement", r"@Query",
            r"\.newCall\s*\(", r"HttpResponse\.execute",
            r"CloseableHttpClient", r"DefaultHttpClient",
        ]
        for safe_pat in safe_patterns:
            if re.search(safe_pat, regex_string):
                return False
        dangerous_patterns = [
            r"createStatement\s*\(\s*\)",
            r"executeQuery\s*\(", r"executeUpdate\s*\(",
            r"execute\s*\(", r"addBatch\s*\(",
        ]
        for pat in dangerous_patterns:
            if re.search(pat, regex_string):
                return True
        return None
