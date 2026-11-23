# -*- coding: utf-8 -*-

"""
    matcher
    ~~~~~~~

    漏洞判定引擎

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import traceback

from core.core_engine.php.parser import scan_parser as php_scan_parser
from core.core_engine.javascript.parser import scan_parser as js_scan_parser
from core.core_engine.java.parser import scan_parser as java_scan_parser
from core.core_engine.python.parser import scan_parser as python_scan_parser
from core.core_engine.go.parser import scan_parser as go_scan_parser
from core.core_engine.c.parser import scan_parser as c_scan_parser
from core.core_engine.kotlin.parser import scan_parser as kotlin_scan_parser

from core.filter_functions import load_builtin, get_repair_functions, clear_runtime
from .cast import CAST
from .filters import VulnerabilityFilter
from Kunlun_M import const
from utils.log import logger


class VulnerabilityMatcher(object):
    def __init__(self, target_directory, vulnerability_result, single_rule, project_name, white_list, test=False,
                 index=0, files=None, languages=None, tamper_name=None, is_unconfirm=False):
        """
        Initialize
        :param: target_directory:
        :param: vulnerability_result:
        :param single_rule: rule class
        :param project_name: project name
        :param white_list: white-list
        :param test: is test
        :param index: vulnerability index
        :param files: core file list
        :param tamper_name: tamper name
        """
        self.data = []
        self.repair_dict = {}
        self.repair_functions = []
        self.controlled_list = []
        self.extra_sinks = {}  # {pattern_str: set_of_svids}

        self.target_directory = os.path.normpath(target_directory)

        self.file_path = vulnerability_result.file_path.strip()
        self.line_number = vulnerability_result.line_number
        # self.code_content = vulnerability_result.code_content.strip()
        self.code_content = vulnerability_result.code_content
        self.indirect_map = getattr(vulnerability_result, 'indirect_map', {}) or {}
        self.files = files
        self.languages = languages
        self.tamper_name = tamper_name

        self.rule_match = single_rule.match
        self.rule_match_mode = single_rule.match_mode
        self.vul_function = single_rule.vul_function
        self.cvi = single_rule.svid
        self.lan = single_rule.language.lower()
        self.single_rule = single_rule
        self.is_unconfirm = is_unconfirm

        self.project_name = project_name
        self.white_list = white_list
        self.test = test

        self.status = None
        self.status_init = 0
        self.status_fixed = 2

        # const.py
        self.repair_code = None
        self.repair_code_init = 0
        self.repair_code_fixed = 1
        self.repair_code_not_exist_file = 4000
        self.repair_code_special_file = 4001
        self.repair_code_whitelist = 4002
        self.repair_code_test_file = 4003
        self.repair_code_annotation = 4004
        self.repair_code_modify = 4005
        self.repair_code_empty_code = 4006
        self.repair_code_const_file = 4007
        self.repair_code_third_party = 4008

        self.method = None

        self.filter = VulnerabilityFilter(target_directory, white_list, self.lan, self.rule_match_mode)

        logger.debug("""[CVI-{cvi}] [VERIFY-VULNERABILITY] ({index})
        > File: `{file}:{line}`
        > Code: `{code}`""".format(
            cvi=single_rule.svid,
            index=index,
            file=self.file_path,
            line=self.line_number,
            code=self.code_content))

    def init_php_repair(self):
        """
        初始化修复函数和可控源配置

        加载顺序：
        1. 加载该语言的基础配置 (_base.py)
        2. 自动识别项目框架并合并框架配置
        3. 如果指定了 -tp 参数，加载指定 tamper 作为 override
        4. 注册到 filter_functions L1 层
        :return:
        """
        # 清除上一次的运行时数据（L2/L3），保留 L1
        clear_runtime()

        # Step 1: 加载基础配置
        from rules.tamper._loader import load_base_config, detect_frameworks, merge_framework_config
        self.repair_dict, self.controlled_list = load_base_config(self.lan)

        # Step 2: 自动识别框架
        if self.target_directory:
            detected = detect_frameworks(self.lan, self.target_directory)
            for fw_mod in detected:
                extra = merge_framework_config(self.repair_dict, self.controlled_list, fw_mod)
                if extra:
                    for pattern, svids in extra.items():
                        if pattern not in self.extra_sinks:
                            self.extra_sinks[pattern] = set()
                        self.extra_sinks[pattern] |= svids

        # Step 3: 手动指定 tamper (-tp 参数, override)
        if self.tamper_name is not None:
            try:
                # 尝试新版框架配置路径: rules.tamper.{language}.{name}
                import importlib
                # 先在对应语言目录下找
                lang_prefix = 'rules.tamper.{}'.format(self.lan)
                try:
                    mod = importlib.import_module('{}.{}'.format(lang_prefix, self.tamper_name))
                    if hasattr(mod, 'FILTER_FUNCTIONS'):
                        extra = merge_framework_config(self.repair_dict, self.controlled_list, mod)
                        if extra:
                            for pattern, svids in extra.items():
                                if pattern not in self.extra_sinks:
                                    self.extra_sinks[pattern] = set()
                                self.extra_sinks[pattern] |= svids
                    elif hasattr(mod, 'FRAMEWORK_NAME'):
                        extra = merge_framework_config(self.repair_dict, self.controlled_list, mod)
                        if extra:
                            for pattern, svids in extra.items():
                                if pattern not in self.extra_sinks:
                                    self.extra_sinks[pattern] = set()
                                self.extra_sinks[pattern] |= svids
                except ImportError:
                    # 回退到旧版格式: rules.tamper.{name}
                    a = __import__('rules.tamper.' + self.tamper_name, fromlist=[self.tamper_name])
                    a = getattr(a, self.tamper_name)
                    self.repair_dict.update(a.items())
                    b = __import__('rules.tamper.' + self.tamper_name, fromlist=[self.tamper_name + "_controlled"])
                    b = getattr(b, self.tamper_name + "_controlled")
                    self.controlled_list += b
            except ImportError:
                logger.warning('[AST][INIT] tamper_name init error... No module named {}'.format(self.tamper_name))

        # Step 4: 注册到 filter_functions L1（仅首次）
        from core.filter_functions import stats, register_rule_functions
        if not stats().get(self.lan, {}).get("L1_builtin", 0):
            load_builtin(self.lan, self.repair_dict)

        # L3 注册：规则级自定义修复函数
        extra_repair = getattr(self.single_rule, 'extra_repair_functions', None)
        if extra_repair and isinstance(extra_repair, list):
            register_rule_functions(self.lan, self.single_rule.svid, extra_repair)
            logger.debug("[FILTER] L3 registered for svid {}: {}".format(
                self.single_rule.svid, extra_repair))

        # 兼容：按 svid 过滤生成 repair_functions 列表（含 L1+L2+L3）
        # scan_parser 仍通过此列表传递 repair_functions 参数
        self.repair_functions = get_repair_functions(self.lan, self.single_rule.svid)

    def scan(self):
        """
        Scan vulnerabilities
        :flow:
        - whitelist file
        - special file
        - test file
        - annotation
        - rule
        :return: is_vulnerability, code
        """
        self.method = 0
        self.code_content = self.code_content
        if len(self.code_content) > 512:
            self.code_content = self.code_content[:500]
        self.status = self.status_init
        self.repair_code = self.repair_code_init

        # 前置过滤
        skip, reason = self.filter.check(self.file_path, self.code_content)
        if skip:
            if 'Whitelist' in reason:
                logger.debug("[RET] Whitelist")
            elif 'Special' in reason:
                logger.debug("[RET] Special File")
            else:
                logger.debug("[RET] Annotation")
            return False, reason

        # test_file 只记录日志不跳过
        if self.filter.is_test_file(self.file_path):
            logger.debug("[CORE] Test File")

        # 按语言分派
        logger.debug('[CVI-{cvi}] match-mode {mm}'.format(cvi=self.cvi, mm=self.rule_match_mode))

        dispatch = {
            'php': self._scan_php,
            'solidity': self._scan_solidity,
            'javascript': self._scan_javascript,
            'chromeext': self._scan_chromeext,
            'java': self._scan_java,
            'python': self._scan_python,
            'go': self._scan_go,
            'c': self._scan_c,
            'kotlin': self._scan_kotlin,
        }
        handler = dispatch.get(self.lan, self._scan_generic)
        return handler()

    def _parse_ast_result(self, result):
        """
        统一解析 PHP/JS AST parser 返回结果，处理 code=1/2/3/4 逻辑
        返回 None 表示未匹配，调用方应继续后续流程
        """
        result_code_list = []

        for r in result:
            result_code_list.append(r['code'])

            if r['code'] == 1:  # 函数参数可控
                return True, 'Function-param-controllable', r['chain']

        for r in result:
            if r['code'] in (4, 5):  # 配置型漏洞 / 新规则生成
                # 区分：chain 中有 NewFunction 标记 → NewCore 二次扫描
                # chain 中无 NewFunction → 配置型漏洞（code 1 等价）
                chain = r.get('chain', [])
                has_new_function = any(isinstance(c, tuple) and len(c) >= 1 and c[0] == 'NewFunction' for c in chain)
                if has_new_function:
                    return False, 'New Core', r['source']
                if chain and len(chain) > 1:
                    return True, 'Config-vulnerability-confirmed', chain
                return False, 'New Core', r['source']

        for r in result:
            if r['code'] == 3:  # 疑似漏洞
                if self.is_unconfirm:
                    return True, 'Unconfirmed Function-param-controllable', r['chain']
                else:
                    return False, 'Unconfirmed Function-param-controllable', r['chain']

            elif r['code'] == 2:  # 漏洞修复
                return False, 'Function-param-controllable but fixed', r['chain']

            else:  # 函数参数不可控
                return False, 'Function-param-uncontrollable', r['chain']

        logger.debug('[AST] [CODE] {code}'.format(code=result_code_list))
        return None

    def _handle_vustomize_match(self, ast):
        """统一处理 vustomize-match / regex-param-controllable 的结果"""
        param_is_controllable, code, data, chain = ast.is_controllable_param()

        if param_is_controllable:
            logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param is controllable'.format(cvi=self.cvi))

            if code == 1 or code == -1:
                return True, 'Vustomize-Match', chain
            elif code == 3:
                if self.is_unconfirm:
                    return True, 'Unconfirmed Vustomize-Match', chain
                else:
                    return False, 'Unconfirmed Vustomize-Match', chain

        else:
            if type(data) is tuple:
                # 三元组格式: (wrapper_func, param_name, vul_function) — 来自 cast.py code=4/5 修复
                if len(data) == 3 and isinstance(data[0], str):
                    return False, 'New Core', data
                # 旧格式兼容: tuple([code, controlled_params])
                if int(data[0]) in (4, 5):
                    return False, 'New Core', data[1]

            logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param Not Controllable'.format(cvi=self.cvi))
            return False, 'Param-Not-Controllable'

    def _scan_php(self):
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            # only match
            if self.rule_match_mode == const.mm_regex_only_match:
                #
                # Regex-Only-Match
                # Match(regex) -> Repair -> Done
                #
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'

            # Match for function-param-regex
            if self.rule_match_mode == const.mm_function_param_controllable:
                rule_match = self.rule_match.strip('()').split('|')
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    result = php_scan_parser(rule_match, self.line_number, self.file_path,
                                             repair_functions=self.repair_functions,
                                             controlled_params=self.controlled_list, svid=self.cvi,
                                             indirect_map=self.indirect_map)
                    logger.debug('[AST] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, 'Can\'t parser'
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            # vustomize-match
            return self._handle_vustomize_match(ast)

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_solidity(self):
        try:
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions)

            # only match
            if self.rule_match_mode == const.mm_regex_only_match:
                #
                # Regex-Only-Match
                # Match(regex) -> Repair -> Done
                #
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'
            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'
            else:
                logger.warn(
                    "[CVI-{cvi} [OTHER-MATCH]] sol rules only support for Regex-only-match and Regex-return-regex...".format(
                        cvi=self.cvi))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_javascript(self):
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            # only match
            if self.rule_match_mode == const.mm_regex_only_match:
                #
                # Regex-Only-Match
                # Match(regex) -> Repair -> Done
                #
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'
            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'

                # Match for function-param-regex
            elif self.rule_match_mode == const.mm_function_param_controllable:
                rule_match = self.rule_match.strip('()').split('|')
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    result = js_scan_parser(rule_match, self.line_number, self.file_path,
                                            repair_functions=self.repair_functions,
                                            controlled_params=self.controlled_list,
                                            indirect_map=self.indirect_map)
                    logger.debug('[AST] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, 'Can\'t parser'
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn("[CVI-{cvi} [OTHER-MATCH]] javascript not support this rules...".format(cvi=self.cvi))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_chromeext(self):
        try:
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions)

            # only match
            if self.rule_match_mode == const.mm_regex_only_match:
                #
                # Regex-Only-Match
                # Match(regex) -> Repair -> Done
                #
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'
            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'
            elif self.rule_match_mode == const.sp_crx_keyword_match:
                logger.debug("[CVI-{cvi}] [SPECIAL-CRX-KEYWORD-MATCH]".format(cvi=self.cvi))
                return True, 'Specail-crx-keyword-match'
            else:
                logger.warn("[CVI-{cvi} [OTHER-MATCH]] chrome ext rules not support it...".format(cvi=self.cvi))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_java(self):
        """Java 扫描（支持 only-regex、regex-return-regex、function-param-controllable、vustomize-match）"""
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            if self.rule_match_mode == const.mm_regex_only_match:
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'

            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'

            elif self.rule_match_mode in (const.mm_function_param_controllable,
                                           const.mm_java_function_param_controllable):
                # 调用规则的 main() 做二次筛选（类似 PHP cast.py:212 的 self.sr.main()）
                # 优先传完整源码行（而非 grep 片段），让 main() 能看到上下文
                main_input = self.code_content
                try:
                    with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                        source_lines = f.readlines()
                    idx = int(self.line_number) - 1
                    if 0 <= idx < len(source_lines):
                        main_input = source_lines[idx].strip()
                except Exception:
                    pass
                main_result = self.single_rule.main(main_input)
                if main_result is not None and main_result is not False:
                    # main() 返回非 None/False → 通过二次筛选，继续 AST 分析
                    pass
                elif main_result is False:
                    logger.debug('[CVI-{cvi}] main() returned False, skip'.format(cvi=self.cvi))
                    return False, 'Filtered by rule.main()'
                # main() 返回 None → 不做二次筛选（默认 pass），继续 AST 分析

                # 确定用于 AST 分析的函数名列表
                if (hasattr(self.single_rule, 'vul_function') and
                    isinstance(self.single_rule.vul_function, list) and
                    len(self.single_rule.vul_function) > 0):
                    rule_match = self.single_rule.vul_function
                else:
                    rule_match = self.rule_match.strip('()').split('|')
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    # 获取规则是否声明为配置型漏洞
                    is_config_vuln = getattr(self.single_rule, 'is_config_vuln', False)
                    result = java_scan_parser(rule_match, self.line_number, self.file_path,
                                              repair_functions=self.repair_functions,
                                              controlled_params=self.controlled_list,
                                              is_config_vuln=is_config_vuln,
                                              indirect_map=self.indirect_map)
                    logger.debug('[AST] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, 'Can\'t parser'
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn(
                    "[CVI-{cvi}] Java unsupported match mode: {m}".format(
                        cvi=self.cvi, m=self.rule_match_mode))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_python(self):
        """Python 扫描（支持 only-regex、function-param-controllable、vustomize-match）"""
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            if self.rule_match_mode == const.mm_regex_only_match:
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, "Regex-only-match"

            elif self.rule_match_mode == const.mm_function_param_controllable:
                rule_match = self.rule_match.strip("()").split("|")
                # 清理正则转义: Python AST parser 做精确字符串匹配，不需要反斜杠和括号
                rule_match = [r.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')').rstrip('(') for r in rule_match]
                logger.debug("[RULE_MATCH] {r}".format(r=rule_match))
                try:
                    result = python_scan_parser(rule_match, self.line_number, self.file_path,
                                                repair_functions=self.repair_functions,
                                                controlled_params=self.controlled_list, svid=self.cvi,
                                                indirect_map=self.indirect_map)
                    logger.debug("[AST] [RET] {c}".format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            "[AST] Parser failed / vulnerability parameter is not controllable {r}".format(
                                r=result))
                        return False, "Can\"t parser"
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn(
                    "[CVI-{cvi}] Python unsupported match mode: {m}".format(
                        cvi=self.cvi, m=self.rule_match_mode))
                return False, "Unsupport Match"

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, "Exception"

    def _scan_go(self):
        """Go 扫描（支持 only-regex、regex-return-regex、function-param-controllable）"""
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            if self.rule_match_mode == const.mm_regex_only_match:
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'

            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'

            elif self.rule_match_mode in (const.mm_function_param_controllable,
                                           const.mm_go_function_param_controllable):
                # Go function-param-regex 模式（含 Go 专用 AST 污点追踪）
                rule_match = self.vul_function
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    result = go_scan_parser(rule_match, self.line_number, self.file_path,
                                            repair_functions=self.repair_functions,
                                            controlled_params=self.controlled_list, svid=self.cvi,
                                            indirect_map=self.indirect_map)
                    logger.debug('[AST][Go] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST][Go] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, "Can't parser"
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn(
                    "[CVI-{cvi}] Go unsupported match mode: {m}".format(
                        cvi=self.cvi, m=self.rule_match_mode))
                return False, 'Unsupport Match'

        except Exception as e:
            print('[CI] DEBUG: [CVI-{cvi}] _scan_go EXCEPTION: {tb}'.format(
                cvi=self.cvi, tb=traceback.format_exc()))
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_c(self):
        """C/C++ 扫描（支持 only-regex、function-param-controllable、c-function-param-regex）"""
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            if self.rule_match_mode == const.mm_regex_only_match:
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'

            elif self.rule_match_mode in (const.mm_function_param_controllable,
                                           const.mm_c_function_param_controllable):
                # 调用规则的 main() 做二次筛选
                main_input = self.code_content
                try:
                    with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                        source_lines = f.readlines()
                    idx = int(self.line_number) - 1
                    if 0 <= idx < len(source_lines):
                        main_input = source_lines[idx].strip()
                except Exception:
                    pass

                if hasattr(self.single_rule, 'main') and callable(self.single_rule.main):
                    try:
                        main_result = self.single_rule.main(main_input)
                        if main_result is False:
                            logger.debug('[CVI-{cvi}] C main() returned False, skip'.format(cvi=self.cvi))
                            return False, 'Filtered by rule.main()'
                    except Exception:
                        pass

                # 优先使用 vul_function
                if (hasattr(self, 'vul_function') and
                    isinstance(self.vul_function, list) and
                    len(self.vul_function) > 0):
                    rule_match = self.vul_function
                else:
                    rule_match = self.rule_match.strip('()').split('|')
                    rule_match = [r.replace('\\.', '.').replace('\\(', '(').replace('\\)', ')').rstrip('(') for r in rule_match]
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    result = c_scan_parser(rule_match, self.line_number, self.file_path,
                                           repair_functions=self.repair_functions,
                                           controlled_params=self.controlled_list, svid=self.cvi,
                                           indirect_map=self.indirect_map)
                    logger.debug('[AST] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, "Can't parser"
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn(
                    "[CVI-{cvi}] C unsupported match mode: {m}".format(
                        cvi=self.cvi, m=self.rule_match_mode))
                return False, 'Unsupport Match'

        except Exception as e:
            print('[CI] DEBUG: [CVI-{cvi}] _scan_c EXCEPTION: {tb}'.format(
                cvi=self.cvi, tb=traceback.format_exc()))
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_kotlin(self):
        """Kotlin 扫描（支持 only-regex、regex-return-regex、function-param-controllable）"""
        try:
            self.init_php_repair()
            ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                       self.code_content, files=self.files, rule_class=self.single_rule,
                       repair_functions=self.repair_functions, controlled_params=self.controlled_list)

            if self.rule_match_mode == const.mm_regex_only_match:
                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'

            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'

            elif self.rule_match_mode in (const.mm_function_param_controllable,
                                           const.mm_java_function_param_controllable):
                # 调用规则的 main() 做二次筛选
                main_input = self.code_content
                try:
                    with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                        source_lines = f.readlines()
                    idx = int(self.line_number) - 1
                    if 0 <= idx < len(source_lines):
                        main_input = source_lines[idx].strip()
                except Exception:
                    pass
                main_result = self.single_rule.main(main_input)
                if main_result is not None and main_result is not False:
                    pass
                elif main_result is False:
                    logger.debug('[CVI-{cvi}] main() returned False, skip'.format(cvi=self.cvi))
                    return False, 'Filtered by rule.main()'

                # 确定用于 AST 分析的函数名列表
                if (hasattr(self.single_rule, 'vul_function') and
                    isinstance(self.single_rule.vul_function, list) and
                    len(self.single_rule.vul_function) > 0):
                    rule_match = self.single_rule.vul_function
                else:
                    rule_match = self.rule_match.strip('()').split('|')
                logger.debug('[RULE_MATCH] {r}'.format(r=rule_match))
                try:
                    result = kotlin_scan_parser(rule_match, self.line_number, self.file_path,
                                               repair_functions=self.repair_functions,
                                               controlled_params=self.controlled_list)
                    logger.debug('[AST][Kotlin] [RET] {c}'.format(c=result))
                    if len(result) > 0:
                        parsed = self._parse_ast_result(result)
                        if parsed is not None:
                            return parsed
                    else:
                        logger.debug(
                            '[AST][Kotlin] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                r=result))
                        return False, "Can't parser"
                except Exception:
                    exc_msg = traceback.format_exc()
                    logger.warning(exc_msg)
                    raise

            elif self.rule_match_mode == const.mm_regex_param_controllable:
                return self._handle_vustomize_match(ast)

            else:
                logger.warn(
                    "[CVI-{cvi}] Kotlin unsupported match mode: {m}".format(
                        cvi=self.cvi, m=self.rule_match_mode))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'

    def _scan_generic(self):
        try:
            # only match
            if self.rule_match_mode == const.mm_regex_only_match:

                logger.debug("[CVI-{cvi}] [ONLY-MATCH]".format(cvi=self.cvi))
                return True, 'Regex-only-match'
            elif self.rule_match_mode == const.mm_regex_return_regex:
                logger.debug("[CVI-{cvi}] [REGEX-RETURN-REGEX]".format(cvi=self.cvi))
                return True, 'Regex-return-regex'

            elif self.rule_match_mode == const.file_path_regex_match:
                logger.debug("[CVI-{cvi}] [File-REGEX]".format(cvi=self.cvi))
                return True, 'file-path-regex-match'
            else:
                logger.warn(
                    "[CVI-{cvi} [OTHER-MATCH]] other rules only support for Regex-only-match and Regex-return-regex...".format(
                        cvi=self.cvi))
                return False, 'Unsupport Match'

        except Exception as e:
            logger.debug(traceback.format_exc())
            return False, 'Exception'
