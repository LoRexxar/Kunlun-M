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
        "(system|exec|passthru)"    -> [SinkName(None, 'system'), SinkName(None, 'exec'), SinkName(None, 'passthru')]
        "(mysqli_query|pg_query)\\s?\\(]" -> [SinkName(None, 'mysqli_query'), SinkName(None, 'pg_query')]

    :param match_string: 规则中的 match 字段值
    :return: list of SinkName
    """
    import re
    if not isinstance(match_string, str):
        return []

    match_string = match_string.strip()

    # 1. 先去掉正则断言（lookbehind/lookahead），它们不影响 sink 名称匹配。
    #    必须在外层括号处理之前，否则 (?<!...) 的括号会被外层规则误匹配。
    #    (?<!...) 和 (?<=...) 是零宽断言，(?=...) 和 (?!...) 同理。
    match_string = re.sub(r'\(\?[<!]=?[^)]*\)', '', match_string)
    match_string = re.sub(r'\(\?[!=][^)]*\)', '', match_string)

    # 2. 去掉外层分组括号 "(a|b|c)..." → "a|b|c..."
    m = re.match(r'^\((.+)\)(.*)$', match_string, re.DOTALL)
    if m:
        match_string = m.group(1).strip() + m.group(2).strip()

    # 3. 去掉正则元字符序列（\b=word boundary, \d, \w, \s 等），
    #    它们不是对后续字符的转义，而是独立的正则指令，应整体删除。
    match_string = re.sub(r'\\[bBdDwWsS]', '', match_string)

    # 去掉正则转义字符（Go 规则的 match 常为 "exec\\.Command|os\\.StartProcess"）
    # 只保留 \s, \(, \) 等正则元字符的转义，去掉 \. 的转义
    match_string = re.sub(
        r'\\(.)',
        lambda m: m.group(1) if m.group(1) not in ('s', '*', '(', ')', '[', ']', '{', '}', '+', '?', '|', '^', '$') else m.group(0),
        match_string,
    )

    # 去掉剩余的正则转义序列（\s, \(, \[ 等未转换的）
    match_string = re.sub(r'\\.', '', match_string)

    raw_names = match_string.split('|')
    result = []
    for name in raw_names:
        name = name.strip()
        if not name:
            continue

        # 清理每个 sink 名中的正则元字符后缀（如 \(, \[, +, *, ? 等）
        name = re.sub(r'[^a-zA-Z0-9_.:]', '', name)
        if not name:
            continue

        # 前缀标志: a:ClassName (注解匹配), r: (return节点匹配)
        prefix = None
        if name.startswith('a:'):
            prefix = 'a'
            name = name[2:]
        elif name.startswith('r:'):
            prefix = 'r'
            name = name[2:]
        if not name:
            continue

        for sep in ['::', '.']:
            if sep in name:
                parts = name.split(sep, 1)
                cls = parts[0].strip()
                method = parts[1].strip()
                if cls and method:
                    if prefix:
                        result.append(SinkName(class_=f'{prefix}:{cls}', method=method))
                    else:
                        result.append(SinkName(class_=cls, method=method))
                    break
        else:
            if prefix:
                result.append(SinkName(class_=f'{prefix}:', method=name))
            else:
                result.append(SinkName(class_=None, method=name))

    return result
