# -*- coding: utf-8 -*-

"""
    Java SSTI (Server-Side Template Injection) Rule
    ~~~~
    检测Velocity/Freemarker等模板引擎将用户输入作为模板内容直接求值导致的SSTI漏洞。
    :author:    KunLun-M
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
"""

import re

from utils.api import *

class CVI_6073(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):
        self.svid = 6073
        self.language = "java"
        self.vulnerability = "SSTI (Server-Side Template Injection)"
        self.description = "通过AST分析检测Velocity.evaluate()/Freemarker Template.process()/VelocityEngine.evaluate()等方法将用户可控输入作为模板内容直接求值导致的SSTI漏洞。攻击者可注入恶意模板表达式执行任意代码。建议使用安全的模板渲染方式，避免直接执行用户输入。"
        self.level = 9

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r'Velocity\.evaluate\s*\(|Velocity\.merge\s*\(|VelocityEngine\.evaluate\s*\(|\.process\s*\(\s*rootMap|new\s+Template\s*\(\s*["\x27][^"\x27]*["\x27],\s*new\s+StringReader|FlexibleStringExpander\.expandString\s*\(|executeMacro\s*\(|GroovyUtil\.eval\s*\(|FreeMarkerWorker\.renderTemplate(FromString)?\s*\('

        # for regex
        self.unmatch = []

        self.vul_function = [

            "VelocityEngine.evaluate",

            "VelocityEngine.merge",

            "Template.process",

            "FreeMarkerTemplate.process",

            # Fix 153 (CVE-2026-82910/82912/82960 Apache OFBiz 24.09 SSTI
            # family): OFBiz evaluates attacker-influenced strings as
            # template/script code at three boundaries:
            #  - FlexibleStringExpander.expandString(template, ctx, ...) —
            #    STATIC form, arg0 IS the FTL template being evaluated
            #    (service IN attrs bodyText/subject, CVE-2026-82912);
            #  - MacroScreenRenderer.executeMacro(writer, macroString) —
            #    arg1 is an FTL macro string assembled from unescaped link
            #    parameter values (CVE-2026-82910);
            #  - GroovyUtil.eval(expr, ctx) — form-field use-when/ignore-when
            #    expressions with ${param} interpolated into the Groovy
            #    source (CVE-2026-82960).
            "FlexibleStringExpander.expandString",

            "MacroScreenRenderer.executeMacro",

            "GroovyUtil.eval",

            # Fix 153b (CVE-2026-85627): FreeMarkerWorker evaluates a
            # caller-supplied template string / template location —
            # arg1 of renderTemplateFromString is the template text,
            # arg0 of renderTemplate is the template location or text.
            "FreeMarkerWorker.renderTemplateFromString",

            "FreeMarkerWorker.renderTemplate",

        ]

    def main(self, regex_string, sink_args=None):
        """二次筛选：确认模板内容来自用户输入"""
        if sink_args:
            # Fix 153 (OFBiz SSTI family): instance-form
            # ``fse.expandString(context)`` — arg0 is the Map context, the
            # FTL template lives inside the FlexibleStringExpander object
            # itself (parsed at construction from widget XML), so this call
            # form is NOT the SSTI boundary; context-derived taint flowing
            # OUT of it is modeled by the Fix 137c passthrough and caught
            # at the downstream evaluator (executeMacro / GroovyUtil.eval /
            # static expandString).  Only the static form
            # ``FlexibleStringExpander.expandString(template, ctx, ...)``
            # evaluates a caller-supplied template string (arg0).
            if ('.expandString(' in regex_string
                    and 'FlexibleStringExpander.expandString(' not in regex_string):
                return False
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
        # 排除使用安全配置的写法
        if re.search(r'setSafeMode|setAllowInline|SandboxConfiguration|safeMode|strictMode', regex_string):
            return False
        return None
