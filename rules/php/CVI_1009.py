# -*- coding: utf-8 -*-

"""
    auto rule template
    ~~~~
    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved
"""

from utils.api import *

class CVI_1009(SingleRuleMixin):
    """
    rule class
    """

    def __init__(self):

        self.svid = 1009
        self.language = "php"
        self.author = "LoRexxar/wufeifei"
        self.vulnerability = "RCE"
        self.description = "参数可控会导致远程命令执行"
        self.level = 10

        # 部分配置
        self.match_mode = "function-param-regex"
        self.match = r"(array_map|create_function|call_user_func|call_user_func_array|assert|eval|dl|register_tick_function|register_shutdown_function)"

    def main(self, regex_string, sink_args=None):
        """
        Graph-based: check if assert() arg is a safe expression (instanceof, comparison).
        assert($a instanceof B) → False (type check)
        assert($a == $b) → False (comparison)

        Also checks array_map/call_user_func first arg (callback): if the
        callback is a known safe function in builtin_knowledge (e.g.
        htmlspecialchars, intval, strip_tags), the call sanitizes data.
        """
        if sink_args:
            if len(sink_args) >= 1:
                arg0 = sink_args[0]
                # For array_map / call_user_func: arg0 is the callback.
                # If it's a builtin_knowledge safe function, the call sanitizes data.
                sn = str(regex_string).lower() if regex_string else ''
                if 'array_map' in sn or 'call_user_func' in sn or 'call_user_func_array' in sn:
                    cb_name = arg0.get('name', '')
                    cb_callee = arg0.get('return_callee', '')
                    try:
                        from core.core_engine.php.builtin_knowledge import KNOWLEDGE
                        for candidate in (cb_name, cb_callee):
                            entry = KNOWLEDGE.get(candidate)
                            if entry and entry.get('safe'):
                                return False
                    except Exception:
                        pass
                # operator arg → check callee/op name
                if arg0.get('label') == 'operator':
                    arg_name = arg0.get('name', '').lower()
                    if 'instanceof' in arg_name:
                        return False
                    # boolean/comparison operators — assert(bool expr) is not RCE
                    if arg_name in ('==', '===', '!=', '!==', '<', '>', '<=', '>=', 'bool_expression',
                                    '||', '&&', '!', 'and', 'or'):
                        return False
                # const arg → static string, check content
                val = arg0.get('resolved_value', '') or ''
                if not val and (arg0.get('label') == 'const' or arg0.get('type') in ('string', 'constant')):
                    val = arg0.get('name', '')
                if val and ('instanceof' in val.lower() or 'null' in val.lower()):
                    return False
            return None

        # Regex fallback
        if regex_string:
            stripped = regex_string.lstrip().lstrip('\\')
            # array_map with safe callback: array_map(htmlspecialchars..., ...)
            # or array_map(hsc..., ...) — callback sanitizes data
            if 'array_map' in stripped:
                try:
                    from core.core_engine.php.builtin_knowledge import KNOWLEDGE
                    m = re.search(r'array_map\s*\(\s*(\w+)', stripped)
                    if m:
                        cb = m.group(1)
                        entry = KNOWLEDGE.get(cb)
                        if entry and entry.get('safe'):
                            return False
                except Exception:
                    pass
            if stripped.startswith('assert'):
                if 'instanceof' in stripped or 'null' in stripped.lower():
                    return False
                # assert($a == $b) comparison pattern
                if re.search(r'assert\s*\([^)]*(?:==|===|!=|!==|<=|>=)\s*', stripped):
                    return False
        if regex_string:
            stripped2 = regex_string.lstrip().lstrip('\\')
            if stripped2.startswith('is_a'):
                return False
        return None
