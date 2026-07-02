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
mm_function_param_controllable = 'function-param-regex'  # 函数正则匹配（主路径）
mm_java_function_param_controllable = 'java-function-param-regex'  # LEGACY: all rules migrated to function-param-regex
mm_go_function_param_controllable = 'go-function-param-regex'     # LEGACY: all rules migrated to function-param-regex
mm_c_function_param_controllable = 'c-function-param-regex'      # LEGACY: all rules migrated to function-param-regex
mm_regex_param_controllable = 'vustomize-match'  # LEGACY: no rules use this anymore
mm_regex_only_match = 'only-regex'  # LEGACY: rules using this mode are skipped
mm_regex_return_regex = 'regex-return-regex'  # LEGACY: rules using this mode are skipped
sp_crx_keyword_match = 'special-crx-keyword-match'  # LEGACY: migrated to file-pattern
file_path_regex_match = 'file-path-regex-match'  # LEGACY: migrated to file-pattern
vendor_source_match = 'vendor_source_match'  # sca
mm_framework_dependency = 'framework-dependency'  # 框架依赖版本检测 (pom.xml/build.gradle)
mm_file_pattern = 'file-pattern'  # 文件名+内容双重匹配

match_modes = [
    mm_regex_only_match,
    mm_regex_param_controllable,
    mm_function_param_controllable,
    mm_java_function_param_controllable,
    mm_go_function_param_controllable,
    mm_c_function_param_controllable,
    mm_regex_return_regex,
    sp_crx_keyword_match,
    file_path_regex_match,
    vendor_source_match,
    mm_framework_dependency,
]


TAMPER_TYPE = ["Filter-Function", "Input-Function"]

#
# Function-Param-Controllable
#
# (?:eval|call_function)\s*\((.*)(?:\))
# eval ($test + $test2);
# call_function ($exp);
#
fpc = r'\s*\((.*)(?:\))'

fpc_echo_statement_single = r"[f]\s*['\"]?(.+?)?\$(.+?)?['\"]?(.+?)?;"
fpc_echo_statement_multi = r"(?:[f])\s*['\"]?(.+?)?\$(.+?)?['\"]?(.+?)?;"

fpc_single = '[f]{fpc}'.format(fpc=fpc)
fpc_multi = '(?:[f]){fpc}'.format(fpc=fpc)
fpc_loose = r'(?:(\A|\s|\b)[f])({fpc})?\b'.format(fpc=fpc)

#
# Find All variables
#
# Hallo $var. blabla $var, $iam a var $varvarvar gfg djf jdfgjh fd $variable $_GET['req']
#
fav = r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'

ext_dict = {
    "php": ['.php', '.php3', '.php4', '.php5', '.php7', '.pht', '.phs', '.phtml'],
    "solidity": ['.sol'],
    "javascript": ['.js'],
    "typescript": ['.ts', '.tsx'],
    "chromeext": ['.crx'],
    "html": ['.html'],
    "python": ['.py'],
    "java": ['.java', '.jar', '.xml'],
    "go": ['.go'],
    "c": ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx'],
    "rust": ['.rs'],
    "ruby": ['.rb'],
    "csharp": ['.cs'],
    "kotlin": ['.kt', '.kts'],
    "lua": ['.lua'],
    "base": ['*']
}

ext_comment_dict = {
    "php": ['//', '/*'],
    "javascript": ['//', '/*'],
    "typescript": ['//', '/*'],
    "python": ['#'],
    "go": ['//'],
    "c": ['//', '/*'],
    "rust": ['//', '/*'],
    "ruby": ['#', '=begin'],
    "csharp": ['//', '/*'],
    "kotlin": ['//', '/*'],
    "lua": ['--', '--[['],
}

default_black_list = ['.crx_files', 'vendor']
IGNORE_LIST = []

VUL_LEVEL = ['low', 'low', 'low', 'low', 'medium', 'medium', 'medium', 'medium', 'high', 'high', 'critical']

VENDOR_FILE_DICT = {
    "java": ['pom.xml', 'build.gradle'],
    'golang': ['go.mod'],
    'python': ['requirements.txt'],
    'php': ['composer.json'],
    'nodejs': ['package.json'],
}

VENDOR_ECOSYSTEM = {
    "java": {"osv": "Maven", "depsdev": "maven", "murphysec": "java"},
    "golang": {"osv": "Go", "depsdev": "go", "murphysec": "golang"},
    "python": {"osv": "PyPI", "ossindex": "pypi", "murphysec": "python"},
    "php": {"osv": "Packagist", "ossindex": "composer", "murphysec": "php"},
    "nodejs": {"osv": "npm", "depsdev": "npm", "murphysec": "js"},
}

VENDOR_VUL_LEVEL = ['None', 'low', 'low', 'low', 'medium', 'medium', 'medium', 'medium', 'high', 'high', 'high']

VENDOR_CVIID = 9999

# base result class


class VulnerabilityResult:
    """扫描结果数据模型

    表示一次规则匹配命中的漏洞结果。

    Attributes:
        id: 规则编号（对应 ScanResultTask.cvi_id）
        file_path: 文件绝对路径
        line_number: 行号
        code_content: 命中的代码片段（可能为 bytes 或 str）
        rule_name: 漏洞名称（如 "SSRF"、"Reflected XSS"）
        language: 目标语言（php/javascript/solidity/chromeext）
        analysis: 分析结论/原因（matcher 返回的 reason，对应 ScanResultTask.result_type）
        chain: 污点传播链，list[tuple] 格式 [(node_type, node_content, node_path, node_lineno), ...]
               空结果时为空列表 []
        commit_author: 规则作者
        is_unconfirm: 是否未确认（默认从 analysis 自动推断，也可手动设置）
    """

    def __init__(self):
        self.id = ''
        self.file_path = None
        self.analysis = ''
        self.chain = []           # 默认空列表
        self.rule_name = ''
        self.language = ''
        self.line_number = None
        self.code_content = None
        self.commit_author = 'Unknown'
        self.is_unconfirm = None  # None 表示未手动设置（延迟推断）
        self.indirect_map = {}    # 间接调用：变量名 -> 实际 sink 函数名

    @property
    def is_unconfirmed(self):
        """推断是否未确认漏洞。优先使用手动设置的值，否则从 analysis 文本判断。"""
        if self.is_unconfirm is not None:
            return self.is_unconfirm
        if self.analysis:
            return "unconfirmed" in str(self.analysis).lower()
        return False

    @classmethod
    def from_match(cls, single_match, svid, language, rule_name='', author='Unknown'):
        """工厂方法：从正则匹配元组构造实例

        消除 scanner.parse_match 和 rule_generator.auto_parse_match 的重复逻辑。

        Args:
            single_match: 正则匹配结果元组 (file_path, line_number, code_content)
            svid: 规则编号
            language: 目标语言
            rule_name: 漏洞名称（默认空字符串）
            author: 作者（默认 'Unknown'）

        Returns:
            VulnerabilityResult 实例
        """
        mr = cls()
        try:
            try:
                mr.line_number = int(single_match[1])
            except (ValueError, TypeError):
                mr.line_number = int(float(single_match[1])) if single_match[1] else 0
            mr.code_content = single_match[2]
            mr.file_path = single_match[0]
            # 间接调用：第 4 个元素是 indirect_map
            if len(single_match) > 3 and single_match[3]:
                mr.indirect_map = single_match[3]
        except Exception:
            from utils.log import logger
            logger.warning('[ENGINE] match line parse exception')
            mr.file_path = ''
            mr.code_content = ''
            mr.line_number = 0
        mr.rule_name = rule_name
        mr.id = svid
        mr.language = language
        mr.commit_author = author
        return mr

    def to_db_params(self, target_directory=''):
        """生成保存到 ScanResultTask 所需的参数字典

        统一字段映射，消除 scanner.py 中散落的手写映射。

        Args:
            target_directory: 项目根目录（用于计算相对路径 trigger）

        Returns:
            dict: 包含 cvi_id, language, vulfile_path, source_code, result_type, is_unconfirm
        """
        try:
            code = self.code_content[:50].strip() if self.code_content else ''
        except AttributeError:
            code = str(self.code_content)[:50].strip() if self.code_content else ''

        # 处理 bytes
        if isinstance(code, bytes):
            try:
                code = code.decode('utf-8')[:100].strip()
            except (UnicodeDecodeError, AttributeError):
                code = str(code)[:100].strip()

        trigger = '{}:{}'.format(
            self.file_path.replace(target_directory, '') if target_directory and self.file_path else (self.file_path or ''),
            self.line_number if self.line_number and not isinstance(self.line_number, str) else int(float(self.line_number or 0))
        )

        return {
            'cvi_id': str(self.id),
            'language': self.language,
            'vulfile_path': trigger,
            'source_code': code.replace('\r\n', ' ').replace('\n', ' '),
            'result_type': self.analysis,
            'is_unconfirm': self.is_unconfirmed,
        }

    def convert_to_dict(self):
        """转换为字典（保持向后兼容）"""
        return dict(self.__dict__)
