# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

from utils.api import *

class CVI_1002(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1002
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "SSRF"
        self.description = "file_get_contents函数的参数可控，可能会导致SSRF漏洞"
        self.level = 7

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"file_get_contents"
        self.vul_function = ["file_get_contents"]

    def main(self, regex_string, sink_args=None, context=None):
        """
        Graph-based filtering: skip file_get_contents where the path
        argument comes from a sanitizer/safe function or is built from
        local system paths (sys_get_temp_dir, __DIR__, etc.).
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # const/string literal → hardcoded path, safe
                if arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant'):
                    return False
                if arg0.get('resolved_value', ''):
                    return False
                # If arg comes from a safe callee (canonicalize, normalize,
                # sanitize, etc.), the return value is sanitized.
                if arg0.get('is_func_return'):
                    callee = arg0.get('return_callee', '')
                    safe_callees = ('canonicalize', 'normalize', 'sanitize',
                                    'realpath', 'realpathSync')
                    if callee in safe_callees:
                        return False

        # Context-based filtering: check if the path argument is built from
        # local system functions (sys_get_temp_dir, __DIR__, dirname, etc.)
        # rather than user-controlled input. Also check for security
        # validation functions called before the sink (exitOnEvilScanId, etc.).
        if context and isinstance(context, str):
            import re
            # Pattern: $var = sys_get_temp_dir() . '/' . $something;
            #         file_get_contents($var)
            # If the variable assignment uses sys_get_temp_dir, the path
            # is a local filesystem path, not a user-controlled URL → not SSRF.
            if re.search(r'sys_get_temp_dir', context, re.IGNORECASE):
                return False
            # Pattern: file_get_contents is guarded by a validation function
            # called on the same variable (e.g. exitOnEvilScanId($scanId)
            # before $progressPath = sys_get_temp_dir() . '/' . $scanId)
            safe_guards = (
                'exitOnEvil', 'validate_scan_id', 'check_scan_id',
                'is_valid_scan', 'verify_scan',
            )
            for guard in safe_guards:
                if guard.lower() in context.lower():
                    return False

        return None
