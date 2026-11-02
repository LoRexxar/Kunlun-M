# -*- coding: utf-8 -*-

"""
    Java Insecure Deserialization (function-param-controllable)
    ~~~~
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_6035(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6035
        self.language = "java"
        self.vulnerability = "Insecure Deserialization (function-param-controllable)"
        self.description = "通过AST分析检测readObject()的ObjectInputStream数据源是否来自用户可控输入，可能导致远程代码执行。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = "readObject|readParams"

        # for solidity
        self.black_list = []

        # for regex
        self.unmatch = []
        self.vul_function = [
            "ObjectInputStream.readObject",

            # Fix 53 (CVE-2026-15564, WFLY-22156): IIOP value-type
            # deserialization of untyped EJB method parameters.
            # SkeletonStrategy.readParams unmarshals CORBA input-stream
            # bytes into Java objects BEFORE authentication in the
            # vulnerable EjbCorbaServant._invoke (pre-auth deserialization).
            "SkeletonStrategy.readParams",
        ]

    def main(self, regex_string, sink_args=None):
        pass
