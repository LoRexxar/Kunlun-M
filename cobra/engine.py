# -*- coding: utf-8 -*-

"""
    engine
    ~~~~~~

    Implements scan engine

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import re
import json
import portalocker
import traceback
from . import const
from .rule import Rule
from .utils import Tool
from .log import logger
from .config import running_path
from .result import VulnerabilityResult
from .cast import CAST
from .parser import scan_parser
from .file import FileParseAll
from rules.autorule import autorule
from prettytable import PrettyTable


class Running:
    def __init__(self, sid):
        self.sid = sid

    def init_list(self, data=None):
        """
        Initialize asid_list file.
        :param data: list or a string
        :return:
        """
        file_path = os.path.join(running_path, '{sid}_list'.format(sid=self.sid))
        if not os.path.exists(file_path):
            if isinstance(data, list):
                with open(file_path, 'w') as f:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': len(data),
                    }))
            else:
                with open(file_path, 'w') as f:
                    portalocker.lock(f, portalocker.LOCK_EX)
                    f.write(json.dumps({
                        'sids': {},
                        'total_target_num': 1,
                    }))

    def list(self, data=None):
        file_path = os.path.join(running_path, '{sid}_list'.format(sid=self.sid))
        if data is None:
            with open(file_path, 'r') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
                return json.loads(result)
        else:
            with open(file_path, 'r+') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.read()
                if result == '':
                    result = {'sids': {}}
                else:
                    result = json.loads(result)
                result['sids'][data[0]] = data[1]
                f.seek(0)
                f.truncate()
                f.write(json.dumps(result))

    def status(self, data=None):
        file_path = os.path.join(running_path, '{sid}_status'.format(sid=self.sid))
        if data is None:
            with open(file_path) as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data)
            with open(file_path, 'w') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                f.writelines(data)

    def data(self, data=None):

        file_path = os.path.abspath(running_path + '/{sid}_data'.format(sid=self.sid))

        if data is None:
            with open(file_path) as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                result = f.readline()
            return json.loads(result)
        else:
            data = json.dumps(data, sort_keys=True)
            with open(file_path, 'w+') as f:
                portalocker.lock(f, portalocker.LOCK_EX)
                f.writelines(data)

    def is_file(self, is_data=False):
        if is_data:
            ext = 'data'
        else:
            ext = 'status'
        file_path = os.path.join(running_path, '{sid}_{ext}'.format(sid=self.sid, ext=ext))
        return os.path.isfile(file_path)


def score2level(score):
    level_score = {
        'CRITICAL': [9, 10],
        'HIGH': [6, 7, 8],
        'MEDIUM': [3, 4, 5],
        'LOW': [1, 2]
    }
    score = int(score)
    level = None
    for l in level_score:
        if score in level_score[l]:
            level = l
    if level is None:
        return 'Unknown'
    else:
        if score < 10:
            score_full = '0{s}'.format(s=score)
        else:
            score_full = score

        a = '{s}{e}'.format(s=score * '■', e=(10 - score) * '□')
        return '{l}-{s}: {ast}'.format(l=level[:1], s=score_full, ast=a)


def scan_single(target_directory, single_rule, files=None, ast=False):
    try:
        return SingleRule(target_directory, single_rule, files, ast).process()
    except Exception:
        raise


def scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0, files=None):
    r = Rule()
    vulnerabilities = r.vulnerabilities
    rules = r.rules(special_rules)
    find_vulnerabilities = []

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                res.file_path = res.file_path.replace(target_directory, '')
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
    push_rules = []

    for idx, single_rule in enumerate(sorted(rules.keys())):

        # init rule class
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.id))
            continue
        # SR(Single Rule)
        logger.debug("""[PUSH] [CVI_{cvi}] {idx}.{vulnerability}({language})""".format(
            cvi=rule.svid,
            idx=idx,
            vulnerability=rule.vulnerability,
            language=rule.language
        ))
        result = scan_single(target_directory, rule, files)
        store(result)

    # print
    data = []
    table = PrettyTable(
        ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Target-File:Line-Number',
         'Commit(Author)', 'Source Code Content', 'Analysis'])
    table.align = 'l'
    trigger_rules = []
    for idx, x in enumerate(find_vulnerabilities):
        trigger = '{fp}:{ln}'.format(fp=x.file_path, ln=x.line_number)
        commit = u'@{author}'.format(author=x.commit_author)
        try:
            code_content = x.code_content[:50].strip()
        except AttributeError as e:
            code_content = x.code_content.decode('utf-8')[:100].strip()
        row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit, code_content, x.analysis]
        data.append(row)
        table.add_row(row)
        if x.id not in trigger_rules:
            logger.debug(' > trigger rule (CVI-{cvi})'.format(cvi=x.id))
            trigger_rules.append(x.id)
    diff_rules = list(set(push_rules) - set(trigger_rules))
    vn = len(find_vulnerabilities)
    if vn == 0:
        logger.info('[SCAN] Not found vulnerability!')
    else:
        logger.info("[SCAN] Trigger Rules: {tr} Vulnerabilities ({vn})\r\n{table}".format(tr=len(trigger_rules),
                                                                                          vn=len(find_vulnerabilities),
                                                                                          table=table))
        if len(diff_rules) > 0:
            logger.info(
                '[SCAN] Not Trigger Rules ({l}): {r}'.format(l=len(diff_rules), r=','.join(diff_rules)))
    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
                'language': language,
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(rules),
                'trigger_rules': len(trigger_rules),
                'target_directory': target_directory
            }
        })
    return True


class SingleRule(object):
    def __init__(self, target_directory, single_rule, files, ast=False):
        self.target_directory = target_directory
        self.find = Tool().find
        self.grep = Tool().grep
        self.sr = single_rule
        self.files = files
        self.ast = ast
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        if self.sr.match_mode == const.mm_regex_only_match or self.sr.match_mode == const.mm_regex_param_controllable:
            match = self.sr.match
        elif self.sr.match_mode == const.mm_function_param_controllable:
            # param controllable
            if '|' in self.sr.match:
                match = const.fpc_multi.replace('[f]', self.sr.match)
            else:
                match = const.fpc_single.replace('[f]', self.sr.match)

        else:
            logger.warning('Exception match mode: {m}'.format(m=self.sr.match_mode))

        try:
            if match:
                f = FileParseAll(self.files, self.target_directory)
                result = f.grep(match)
            else:
                result = None
        except Exception as e:
            traceback.print_exc()
            logger.debug('match exception ({e})'.format(e=e))
            return None
        try:
            result = result.decode('utf-8')
        except AttributeError as e:
            pass

        return result

    def process(self):
        """
        Process Single Rule
        :return: SRV(Single Rule Vulnerabilities)
        """
        origin_results = self.origin_results()
        # exists result
        if origin_results == '' or origin_results is None:
            logger.debug('[CVI-{cvi}] [ORIGIN] NOT FOUND!'.format(cvi=self.sr.svid))
            return None

        origin_vulnerabilities = origin_results
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            logger.debug(
                '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr.svid, line=": ".join(list(origin_vulnerability))))
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue
            vulnerability = self.parse_match(origin_vulnerability)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False
            try:
                datas = Core(self.target_directory, vulnerability, self.sr, 'project name',
                             ['whitelist1', 'whitelist2'], test=is_test, index=index,
                             files=self.files).scan()

                if len(datas) == 3:
                    is_vulnerability, reason, data = datas
                elif len(datas) == 2:
                    is_vulnerability, reason = datas
                else:
                    is_vulnerability, reason = False, "Unpack error"

                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr.svid, code=reason))
                    vulnerability.analysis = reason
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    if reason == 'New Core':  # 新的规则
                        logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules init')
                        new_rule_vulnerabilities = NewCore(self.target_directory, data, self.files)

                        if len(new_rule_vulnerabilities) > 0:
                            self.rule_vulnerabilities.extend(new_rule_vulnerabilities)

                    else:
                        logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception:
                raise
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                        count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities

    def parse_match(self, single_match):
        mr = VulnerabilityResult()
        # grep result
        #
        # Rules
        #
        # (u'D:\\program\\cobra-w\\tests\\vulnerabilities/v.php', 10, 'echo($callback . ";");\n')
        try:
            mr.line_number = single_match[1]
            mr.code_content = single_match[2]
            mr.file_path = single_match[0]
        except Exception:
            logger.warning('[ENGINE] match line parse exception')
            mr.file_path = ''
            mr.code_content = ''
            mr.line_number = 0

        # vulnerability information
        mr.rule_name = self.sr.vulnerability
        mr.id = self.sr.svid
        mr.language = self.sr.language
        mr.commit_author = self.sr.author

        return mr


class Core(object):
    def __init__(self, target_directory, vulnerability_result, single_rule, project_name, white_list, test=False,
                 index=None, files=None):
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
        """
        self.data = []

        self.target_directory = target_directory

        self.file_path = vulnerability_result.file_path.strip()
        self.line_number = vulnerability_result.line_number
        self.code_content = vulnerability_result.code_content.strip()
        self.files = files

        self.rule_match = single_rule.match
        self.rule_match_mode = single_rule.match_mode
        self.cvi = single_rule.svid
        self.single_rule = single_rule

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
        logger.debug("""[CVI-{cvi}] [VERIFY-VULNERABILITY] ({index})
        > File: `{file}:{line}`
        > Code: `{code}`""".format(
            cvi=single_rule.svid,
            index=index,
            file=self.file_path.replace(self.target_directory, ''),
            line=self.line_number,
            code=self.code_content))

    def is_white_list(self):
        """
        Is white-list file
        :return: boolean
        """
        return self.file_path.split(self.target_directory, 1)[1] in self.white_list

    def is_special_file(self):
        """
        Is special file
        :method: According to the file name to determine whether the special file
        :return: boolean
        """
        special_paths = [
            '/node_modules/',
            '/bower_components/',
            '.min.js',
        ]
        for path in special_paths:
            if path in self.file_path:
                return True
        return False

    def is_test_file(self):
        """
        Is test case file
        :method: file name
        :return: boolean
        """
        test_paths = [
            '/test/',
            '/tests/',
            '/unitTests/'
        ]
        for path in test_paths:
            if path in self.file_path:
                return True
        return False

    def is_match_only_rule(self):
        """
        Whether only match the rules, do not parameter controllable processing
        :method: It is determined by judging whether the left and right sides of the regex_location are brackets
        :return: boolean
        """
        if self.rule_match_mode == 'regex-only-match':
            return True
        else:
            return False

    def is_annotation(self):
        """
        Is annotation
        :method: Judgment by matching comment symbols (skipped when self.is_match_only_rule condition is met)
               - PHP:  `#` `//` `\*` `*`
                    //asdfasdf
                    \*asdfasdf
                    #asdfasdf
                    *asdfasdf
               - Java:
        :return: boolean
        """
        match_result = re.findall(r"(#|\\\*|\/\/)+", self.code_content)
        # Skip detection only on match
        if self.is_match_only_rule():
            return False
        else:
            return len(match_result) > 0

    def is_can_parse(self):
        """
        Whether to parse the parameter is controllable operation
        :return:
        """
        for language in CAST.languages:
            if self.file_path[-len(language):].lower() == language:
                return True
        return False

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
        if self.is_white_list():
            logger.debug("[RET] Whitelist")
            return False, 'Whitelists(白名单)'

        if self.is_special_file():
            logger.debug("[RET] Special File")
            return False, 'Special File(特殊文件)'

        if self.is_test_file():
            logger.debug("[CORE] Test File")

        if self.is_annotation():
            logger.debug("[RET] Annotation")
            return False, 'Annotation(注释)'

        #
        # function-param-regex
        # Match(function) -> Param-Controllable -> Repair -> Done
        #

        #
        # vustomize-match
        # Match(function) -> vustomize-match() -> Param-Controllable -> Repair -> Done
        #
        logger.debug('[CVI-{cvi}] match-mode {mm}'.format(cvi=self.cvi, mm=self.rule_match_mode))
        if self.file_path[-3:].lower() == 'php':
            try:
                ast = CAST(self.rule_match, self.target_directory, self.file_path, self.line_number,
                           self.code_content, files=self.files, rule_class=self.single_rule)

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
                        with open(self.file_path, 'r') as fi:
                            code_contents = fi.read()
                            result = scan_parser(code_contents, rule_match, self.line_number, self.file_path)
                            logger.debug('[AST] [RET] {c}'.format(c=result))
                            if len(result) > 0:
                                if result[0]['code'] == 1:  # 函数参数可控
                                    return True, 'Function-param-controllable'

                                if result[0]['code'] == 2:  # 函数为敏感函数
                                    return False, 'Function-sensitive'

                                if result[0]['code'] == 0:  # 漏洞修复
                                    return False, 'Function-param-controllable but fixed'

                                if result[0]['code'] == -1:  # 函数参数不可控
                                    return False, 'Function-param-uncon'

                                logger.debug('[AST] [CODE] {code}'.format(code=result[0]['code']))
                            else:
                                logger.debug(
                                    '[AST] Parser failed / vulnerability parameter is not controllable {r}'.format(
                                        r=result))
                                return False, 'Can\'t parser'
                    except Exception as e:
                        logger.warning(traceback.format_exc())
                        raise

                # vustomize-match
                param_is_controllable, data = ast.is_controllable_param()
                if param_is_controllable:
                    logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param is controllable'.format(cvi=self.cvi))
                    # Repair
                    # is_repair, data = ast.match(self.rule_repair, self.repair_block)
                    # if is_repair:
                    #     # fixed
                    #     logger.debug('[CVI-{cvi}] [REPAIR] Vulnerability Fixed'.format(cvi=self.cvi))
                    #     return False, 'Vulnerability-Fixed(漏洞已修复)'
                    # else:
                    # logger.debug('[CVI-{cvi}] [REPAIR] [RET] Not fixed'.format(cvi=self.cvi))
                    return True, 'Vustomize-Match'
                else:
                    if type(data) is tuple:
                        if int(data[0]) == 4:
                            return False, 'New Core', data[1]

                    logger.debug('[CVI-{cvi}] [PARAM-CONTROLLABLE] Param Not Controllable'.format(cvi=self.cvi))
                    return False, 'Param-Not-Controllable'
            except Exception as e:
                logger.debug(traceback.format_exc())
                return False, 'Exception'


def init_match_rule(data):
    """
    处理新生成规则初始化正则匹配
    :param data: 
    :return: 
    """

    try:
        function = data[0]
        function_params = function.params
        function_name = function.name
        param = data[1]
        index = 0
        for function_param in function_params:
            if function_param.name == param.name:
                break
            index += 1

        # curl_setopt\s*\(.*,\s*CURLOPT_URL\s*,(.*)\)
        match = function_name + "\s*\("
        for i in xrange(len(function_params)):
            if i != 0:
                match += ","

            if function_params[i].default is not None:
                match += "?"

            if i == index:
                match += "(.*)"
            else:
                match += ".*"

        match += "\)"

        # 去除定义函数
        match2 = "function\s+"+function_name

    except:
        logger.error('[New Rule] Error to unpack function param, Something error')
        traceback.print_exc()
        match = None
        match2 = None
        index = 0

    return match, match2, index


def auto_parse_match(single_match):
    mr = VulnerabilityResult()
    # grep result
    #
    # Rules
    #
    # (u'D:\\program\\cobra-w\\tests\\vulnerabilities/v.php', 10, 'echo($callback . ";");\n')
    try:
        mr.line_number = single_match[1]
        mr.code_content = single_match[2]
        mr.file_path = single_match[0]
    except Exception:
        logger.warning('match line parse exception')
        mr.file_path = ''
        mr.code_content = ''
        mr.line_number = 0

    # vulnerability information
    mr.rule_name = 'auto rule'
    mr.id = '00000'
    mr.language = 'None'
    mr.commit_author = 'Cobra-W'

    return mr


def NewCore(target_directory, new_rules, files):
    """
    处理新的规则生成
    :param target_directory: 
    :param new_rules: 
    :param files: 
    :return: 
    """

    # init
    match_mode = "New rule to Vustomize-Match"
    logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=match_mode))

    match, match2, index = init_match_rule(new_rules)
    logger.debug('[ENGINE] [New Rule] new match_rule: {}'.format(match))

    sr = autorule()
    sr.match = match

    # grep

    try:
        if match:
            f = FileParseAll(files, target_directory)
            result = f.grep(match)
        else:
            result = None
    except Exception as e:
        traceback.print_exc()
        logger.debug('match exception ({e})'.format(e=e))
        return None
    try:
        result = result.decode('utf-8')
    except AttributeError as e:
        pass

    # 进入分析
    origin_vulnerabilities = result
    rule_vulnerabilities = []

    for index, origin_vulnerability in enumerate(origin_vulnerabilities):

        code =  origin_vulnerability[2]
        if match2 is not None:
            if re.search(match2, code, re.I):
                continue

        logger.debug(
            '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi="00000", line=": ".join(list(origin_vulnerability))))
        if origin_vulnerability == ():
            logger.debug(' > continue...')
            continue
        vulnerability = auto_parse_match(origin_vulnerability)
        if vulnerability is None:
            logger.debug('Not vulnerability, continue...')
            continue

        try:
            is_vulnerability, reason = Core(target_directory, vulnerability, sr, 'project name',
                                            ['whitelist1', 'whitelist2'], files=files).scan()
            if is_vulnerability:
                logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi="00000", code=reason))
                vulnerability.analysis = reason
                rule_vulnerabilities.append(vulnerability)

        except Exception:
            raise

    return rule_vulnerabilities
