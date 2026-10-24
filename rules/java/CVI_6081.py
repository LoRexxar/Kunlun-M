#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
<<Description:>>
Jolokia/JMX MBean 配置注入检测。
通过 Jolokia HTTP 桥（/api/jolokia/）或 JMX console 可以远程 exec MBean 方法并
传入任意参数（CVE-2026-42588：BrokerView.addNetworkConnector(String) → VM transport
brokerConfig → Spring ResourceXmlApplicationContext 任意 XML 加载 → RCE）。

图引擎模式下：
- Fix 45 将 *MBean 实现类的方法 String 参数标注为 taint_type=source
- 本规则 sink 覆盖「URI/配置 → 组件加载」类调用：BrokerFactory.createBroker、
  BrokerService.addNetworkConnector/addConnector（ActiveMQ）、以及通用的
  Spring XML 加载 ResourceXmlApplicationContext
"""
import re

from utils.api import *


class CVI_6081(SingleRuleMixin):
    def __init__(self):
        super().__init__()
        self.svid = 6081
        self.language = "java"
        self.author = "LoRexxar"
        self.vulnerability = "Jolokia/JMX MBean Config Injection"
        self.description = (
            "MBean 方法参数可经 Jolokia/JMX 远程 exec 控制，进入配置/URI 加载类调用"
            "（如 BrokerFactory.createBroker、BrokerService.addNetworkConnector）造成"
            "任意配置加载（Spring XML bean 实例化 → RCE）。"
            "CVE-2026-42588 (ActiveMQ) 同模式。"
        )
        self.level = 9

        self.match_mode = "function-param-regex"
        self.match = (
            r"\bBrokerFactory\s*\.\s*createBroker\s*\("
            r"|\baddNetworkConnector\s*\("
            r"|\bResourceXmlApplicationContext\s*\("
        )

        self.vul_function = [
            "BrokerFactory.createBroker",
            "BrokerService.addNetworkConnector",
            "BrokerService.addConnector",
            "ResourceXmlApplicationContext.ResourceXmlApplicationContext",
        ]

        # 图引擎走正常 taint 链：Fix 45 已把 *MBean 实现类的方法 String 参数
        # 标注为 source，sink 可控性由 parameters_back 判定。
        # 不设 require_taint=False（presence 模式会让全部调用点误报）、
        # 不设 method_sinks（receiver-agnostic 泛匹配噪音）。
        self.require_taint = True

    def main(self, regex_string, sink_args=None):
        """二次筛选：确认为目标调用形态。"""
        if not isinstance(regex_string, str):
            regex_string = str(regex_string)

        # 排除测试代码场景
        if re.search(r'\btest\w*\s*\(', regex_string[:200], re.I):
            pass  # 测试内调用形态仍保留（由 taint 判定把关）

        # BrokerFactory.createBroker / addNetworkConnector / ResourceXmlApplicationContext
        if re.search(r"BrokerFactory\s*\.\s*createBroker\s*\(", regex_string):
            return True
        if re.search(r"\baddNetworkConnector\s*\(", regex_string):
            # graph path: sink_args 里有 const 则为配置内固定调用（如内部初始化）
            if sink_args:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
            return True
        if re.search(r"ResourceXmlApplicationContext\s*\(", regex_string):
            return True
        return None
