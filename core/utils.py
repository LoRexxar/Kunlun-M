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

    兼容三种格式：
    1. 纯函数名（PHP）:       "system|exec"               -> [SinkName(None, 'system'), SinkName(None, 'exec')]
    2. 限定名（Go/Java）:      "Class::method"              -> [SinkName('Class', 'method')]
    3. 正则模式（JS/C/Python）: "exec\\s*\\(|vm\\.runInContext\\s*\\(" -> [SinkName(None, 'exec'), SinkName('vm', 'runInContext')]

    :param match_string: 规则中的 match 字段值
    :return: list of SinkName
    """
    if not isinstance(match_string, str):
        return []

    import re

    # 去掉外层的分组括号（PHP 规则 match 常为 "(system|exec|passthru)" 格式）
    match_string = match_string.strip()
    if match_string.startswith('(') and match_string.endswith(')'):
        match_string = match_string[1:-1]

    # 处理正则转义序列，保留类方法分隔符的 '.'
    # 1) 转义的点 \. → DOT_PLACEHOLDER（保留为类方法分隔符）
    match_string = match_string.replace(r'\.', '<<<DOT>>>')

    # 2) 去掉所有其他转义序列（\s, \(, \), \b, \w 等）
    match_string = re.sub(r'\\.', '', match_string)

    # 3) 恢复点
    match_string = match_string.replace('<<<DOT>>>', '.')

    # 去掉非标识符字符（保留字母、数字、下划线、点、冒号）
    # 这样 "exec\s*\(" → "exec"，"vm\.runInContext\s*\(" → "vm.runInContext"
    raw_names = match_string.split('|')
    result = []
    for name in raw_names:
        name = name.strip()
        if not name:
            continue
        # 只保留标识符字符和点
        cleaned = re.sub(r'[^a-zA-Z0-9_.]', '', name)
        if not cleaned:
            continue

        for sep in ['::', '.']:
            if sep in cleaned:
                parts = cleaned.split(sep, 1)
                cls = parts[0].strip()
                method = parts[1].strip()
                if cls and method:
                    result.append(SinkName(class_=cls, method=method))
                    break
        else:
            result.append(SinkName(class_=None, method=cleaned))

    return result
