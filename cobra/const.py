# -*- coding: utf-8 -*-

"""
    const
    ~~~~~

    Implements CONSTS

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""

# Match-Mode
mm_function_param_controllable = 'function-param-regex'  # 函数正则匹配
mm_regex_param_controllable = 'vustomize-match'  # 自定义匹配
mm_regex_only_match = 'only-regex'
mm_regex_return_regex = 'regex-return-regex'
match_modes = [
    mm_regex_only_match,
    mm_regex_param_controllable,
    mm_function_param_controllable,
    mm_regex_return_regex,
]

#
# Function-Param-Controllable
#
# (?:eval|call_function)\s*\((.*)(?:\))
# eval ($test + $test2);
# call_function ($exp);
#
fpc = '\s*\((.*)(?:\))'
fpc_single = '[f]{fpc}'.format(fpc=fpc)
fpc_multi = '(?:[f]){fpc}'.format(fpc=fpc)

#
# Find All variables
#
# Hallo $var. blabla $var, $iam a var $varvarvar gfg djf jdfgjh fd $variable $_GET['req']
#
fav = '\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'
