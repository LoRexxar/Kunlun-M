# -*- coding: utf-8 -*-

"""
    utils
    ~~~~~

    Core utility functions.

    :license:   MIT, see LICENSE for more details.
"""
from collections import namedtuple

SinkName = namedtuple('SinkName', ['class_', 'method'])


def parse_sink_names(match_string):
    """
    解析规则 match 字符串为 SinkName 列表。
    支持 '|' 分隔的多个 sink，以及 '::' 或 '.' 分隔的 类名.方法名。

    示例:
        "system|exec"               -> [SinkName(None, 'system'), SinkName(None, 'exec')]
        "Class::method"             -> [SinkName('Class', 'method')]
        "os.system|subprocess.call" -> [SinkName('os', 'system'), SinkName('subprocess', 'call')]

    :param match_string: 规则中的 match 字段值
    :return: list of SinkName
    """
    if not isinstance(match_string, str):
        return []

    # 去掉外层的分组括号（PHP 规则 match 常为 "(system|exec|passthru)" 格式）
    match_string = match_string.strip()
    if match_string.startswith('(') and match_string.endswith(')'):
        match_string = match_string[1:-1]

    # 去掉正则转义字符（Go 规则的 match 常为 "exec\\.Command|os\\.StartProcess"）
    # 只保留 \s, \*, \(, \) 等正则元字符的转义，去掉 \. 的转义
    import re
    match_string = re.sub(r'\\(.)', lambda m: m.group(1) if m.group(1) not in ('s', '*', '(', ')', '[', ']', '{', '}', '+', '?', '|', '^', '$') else m.group(0), match_string)

    raw_names = match_string.split('|')
    result = []
    for name in raw_names:
        name = name.strip()
        if not name:
            continue

        for sep in ['::', '.']:
            if sep in name:
                parts = name.split(sep, 1)
                cls = parts[0].strip()
                method = parts[1].strip()
                if cls and method:
                    result.append(SinkName(class_=cls, method=method))
                    break
        else:
            result.append(SinkName(class_=None, method=name))

    return result
