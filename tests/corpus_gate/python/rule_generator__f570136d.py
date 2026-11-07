# -*- coding: utf-8 -*-

"""
    rule_generator
    ~~~~~~~~~~~~~~

    规则初始化与递归新规则生成

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import re
import traceback

from core.core_engine.php.engine import init_match_rule as php_init_match_rule
from core.core_engine.javascript.engine import init_match_rule as js_init_match_rule
from core.core_engine.python.engine import init_match_rule as py_init_match_rule
from core.core_engine.go.engine import init_match_rule as go_init_match_rule
from core.core_engine.c.engine import init_match_rule as c_init_match_rule
from core.core_engine.java.engine import init_match_rule as java_init_match_rule

from rules.autorule import autorule
from Kunlun_M.const import VulnerabilityResult
from utils.file import FileParseAll, get_line
from utils.log import logger


def init_match_rule(data, lan='php'):
    """
    处理新生成规则初始化正则匹配
    :param lan:
    :param data:
    :return:
    """
    if lan.lower() == "php":
        return php_init_match_rule(data)

    if lan.lower() == "javascript":
        return js_init_match_rule(data)

    if lan.lower() == "python":
        return py_init_match_rule(data)

    if lan.lower() == "go":
        return go_init_match_rule(data)

    if lan.lower() in ("c", "c++", "cpp"):
        return c_init_match_rule(data)

    if lan.lower() == "java":
        return java_init_match_rule(data)


def NewCore(old_single_rule, target_directory, new_rules, files, count=0, languages=None, tamper_name=None,
            is_unconfirm=False, newcore_function_list={}):
    """
    处理新的规则生成
    :param languages:
    :param old_single_rule:
    :param tamper_name:
    :param target_directory:
    :param new_rules:
    :param files:
    :param count:
    :return:
    """
    # 延迟导入，避免与 matcher.py 产生循环依赖
    from core.matcher import VulnerabilityMatcher as Core

    count += 1

    if count > 20:
        logger.warning("[New Rule] depth too big to auto exit...")
        return False

    # init
    match_mode = "New rule to Vustomize-Match"
    logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=match_mode))

    result = init_match_rule(new_rules, lan=old_single_rule.language)
    if result is None:
        logger.debug('[New Rule] init_match_rule returned None for language: {}'.format(old_single_rule.language))
        return False
    match, match2, vul_function, index, origin_func_name = result
    logger.debug('[ENGINE] [New Rule] new match_rule: {}'.format(match))

    # 想办法传递新函数类型
    sr = autorule()

    if index == -1:
        sr = autorule(is_eval_object=True)

    sr.match = match
    sr.vul_function = vul_function

    # 从旧的规则类中读取部分数据
    svid = old_single_rule.svid
    language = old_single_rule.language
    sr.svid = svid
    sr.language = language

    # check vul rule exist
    if vul_function in newcore_function_list:
        logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules {macth} exist.'.format(cvi=svid, macth=vul_function))

        if svid not in newcore_function_list[vul_function]["svid"]:
            newcore_function_list[vul_function]["svid"].append(svid)

        if origin_func_name not in newcore_function_list[vul_function]["origin_func_name"]:
            newcore_function_list[vul_function]["origin_func_name"].append(origin_func_name)

        return []
    else:
        newcore_function_list[vul_function] = {"svid": [svid], "origin_func_name": [origin_func_name]}

    # grep
    try:
        if match:
            f = FileParseAll(files, target_directory, language=language)
            result = f.grep(match)
        else:
            result = {}
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

        code = get_line(origin_vulnerability[0], "{line},{line}".format(line=origin_vulnerability[1]))
        code = "".join(code)
        if match2 is not None:
            if re.search(match2, code, re.I):
                continue

        try:
            logger.debug(
                '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=svid, line=": ".join(list(origin_vulnerability))))
        except Exception:
            pass
        if origin_vulnerability == ():
            logger.debug(' > continue...')
            continue
        vulnerability = VulnerabilityResult.from_match(origin_vulnerability, svid=svid,
                                                        language=language,
                                                        rule_name='Auto rule',
                                                        author='Kunlun-M')
        if vulnerability is None:
            logger.debug('Not vulnerability, continue...')
            continue

        try:
            datas = Core(target_directory, vulnerability, sr, 'project name',
                         ['whitelist1', 'whitelist2'], files=files, tamper_name=tamper_name,
                         is_unconfirm=is_unconfirm).scan()
            data = ""

            if len(datas) == 3:
                is_vulnerability, reason, data = datas

                if "New Core" not in reason:
                    code = "Code: {}".format(origin_vulnerability[2]) if len(origin_vulnerability) > 2 else "Code: unknown"
                    data.insert(1, ("NewScan", code, origin_vulnerability[0], origin_vulnerability[1]))

            elif len(datas) == 2:
                is_vulnerability, reason = datas
            else:
                is_vulnerability, reason = False, "Unpack error"

            if is_vulnerability:
                logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi="00000", code=reason))
                vulnerability.analysis = reason
                vulnerability.chain = data
                rule_vulnerabilities.append(vulnerability)
            else:
                if reason == 'New Core':  # 新的规则
                    logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules init'.format(cvi=sr.svid))
                    new_rule_vulnerabilities = NewCore(sr, target_directory, data, files, count,
                                                       tamper_name=tamper_name, is_unconfirm=is_unconfirm,
                                                       newcore_function_list=newcore_function_list)

                    if not new_rule_vulnerabilities:
                        continue

                    if len(new_rule_vulnerabilities) > 0:
                        rule_vulnerabilities.extend(new_rule_vulnerabilities)

                else:
                    logger.debug('Not vulnerability: {code}'.format(code=reason))

        except Exception as e:
            logger.debug('[CVI-{cvi}] Exception processing result: {exc}'.format(
                cvi=svid, exc=e))
            continue

    return rule_vulnerabilities
