# -*- coding: utf-8 -*-

"""
    Java Insecure Reflection Rule (AST-enhanced)
    ~~~~
"""

from utils.api import *

class CVI_6018(SingleRuleMixin):
    def __init__(self):
        self.svid = 6018
        self.language = "java"
        self.vulnerability = "Insecure Reflection"
        self.description = "用户可控的反射调用可能导致绕过安全检查或代码执行"
        self.level = 3

        self.match_mode = "function-param-regex"
        self.match = "forName|newInstance|getDeclaredMethod|getMethod"
        self.vul_function = [
            "Class.forName", "Class.getDeclaredMethod", "Class.getMethod",
            # Fix 135b (CVE-2026-90436, Apache Axis1): class-load /
            # reflective-instantiation wrappers on the sink path.
            # ClassUtils.forName is the common static wrapper (Axis
            # org.apache.axis.utils.ClassUtils.forName and the
            # commons-lang ClassUtils.forName both delegate straight to
            # Class.forName); newInstance completes the reflection
            # instantiation family (Constructor.newInstance receiver is
            # resolved via java typed-receiver lookup, Fix 135c).
            "ClassUtils.forName",
            "Class.newInstance", "Constructor.newInstance",
        ]

    def main(self, regex_string, sink_args=None):
        """过滤编译器反射获取类型名的场景（非用户输入）"""
        if sink_args:
            # Graph path: const arg is hardcoded → safe
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
            return None

        if regex_string and re.search(r'MirroredTypeException|getQualifiedName|getTypeMirror', regex_string):
            return False
        return None
