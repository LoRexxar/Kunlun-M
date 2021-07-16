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
sp_crx_keyword_match = 'special-crx-keyword-match'  # crx特殊匹配
file_path_regex_match = 'file-path-regex-match'  # 文件名或者路径匹配

match_modes = [
    mm_regex_only_match,
    mm_regex_param_controllable,
    mm_function_param_controllable,
    mm_regex_return_regex,
    sp_crx_keyword_match,
    file_path_regex_match,
]


TAMPER_TYPE = ["Filter-Function", "Input-Function"]

#
# Function-Param-Controllable
#
# (?:eval|call_function)\s*\((.*)(?:\))
# eval ($test + $test2);
# call_function ($exp);
#
fpc = '\s*\((.*)(?:\))'

fpc_echo_statement_single = '[f]\s*[\'"]?(.+?)?\$(.+?)?[\'"]?(.+?)?;'
fpc_echo_statement_multi = '(?:[f])\s*[\'"]?(.+?)?\$(.+?)?[\'"]?(.+?)?;'

fpc_single = '[f]{fpc}'.format(fpc=fpc)
fpc_multi = '(?:[f]){fpc}'.format(fpc=fpc)
fpc_loose = '(?:(\A|\s|\\b)[f])({fpc})?\\b'.format(fpc=fpc)

#
# Find All variables
#
# Hallo $var. blabla $var, $iam a var $varvarvar gfg djf jdfgjh fd $variable $_GET['req']
#
fav = '\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'

ext_dict = {
    "php": ['.php', '.php3', '.php4', '.php5', '.php7', '.pht', '.phs', '.phtml', '.inc'],
    "solidity": ['.sol'],
    "javascript": ['.js'],
    "chromeext": ['.crx'],
    "html": ['.html'],
    "base": ['*']
}

ext_comment_dict = {
    "php": ['//', '/*'],
    "javascript": ['//', '/*'],
}

default_black_list = ['.crx_files', 'vendor']
IGNORE_LIST = []

VUL_LEVEL = ['low', 'low', 'low', 'low', 'medium', 'medium', 'medium', 'medium', 'high', 'high', 'high']

# base result class


class VulnerabilityResult:
    def __init__(self):
        self.id = ''
        self.file_path = None
        self.analysis = ''
        self.chain = ""

        self.rule_name = ''
        self.language = ''
        self.line_number = None
        self.code_content = None
        self.commit_author = 'Unknown'

    def convert_to_dict(self):
        _dict = {}
        _dict.update(self.__dict__)
        return _dict
