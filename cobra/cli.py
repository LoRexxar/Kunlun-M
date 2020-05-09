# -*- coding: utf-8 -*-

"""
    cli
    ~~~

    Implements CLI mode

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""

import os
import codecs
from prettytable import PrettyTable

from .detection import Detection
from .engine import scan, Running
from .exceptions import PickupException
from .export import write_to_file
from .log import logger
from .file import Directory
from .utils import ParseArgs
from .utils import md5, random_generator
from .pretreatment import ast_object
from .config import rules_path


def get_sid(target, is_a_sid=False):
    target = target
    if isinstance(target, list):
        target = ';'.join(target)
    sid = md5(target)[:5]
    if is_a_sid:
        pre = 'a'
    else:
        pre = 's'
    sid = '{p}{sid}{r}'.format(p=pre, sid=sid, r=random_generator())
    return sid.lower()


def start(target, formatter, output, special_rules, a_sid=None, language=None, secret_name=None, black_path=None, is_unconfirm=False, is_unprecom=False):
    """
    Start CLI
    :param black_path: 
    :param secret_name: 
    :param language: 
    :param target: File, FOLDER, GIT
    :param formatter:
    :param output:
    :param special_rules:
    :param a_sid: all scan id
    :return:
    """
    global ast_object
    # generate single scan id
    s_sid = get_sid(target)
    r = Running(a_sid)
    data = (s_sid, target)
    r.init_list(data=target)
    r.list(data)

    report = '?sid={a_sid}'.format(a_sid=a_sid)
    d = r.status()
    d['report'] = report
    r.status(d)

    # parse target mode and output mode
    pa = ParseArgs(target, formatter, output, special_rules, language, black_path, a_sid=None)
    target_mode = pa.target_mode
    output_mode = pa.output_mode
    black_path_list = pa.black_path_list

    # target directory
    try:
        target_directory = pa.target_directory(target_mode)
        logger.info('[CLI] Target : {d}'.format(d=target_directory))

        # static analyse files info
        files, file_count, time_consume = Directory(target_directory, black_path_list).collect_files()

        # detection main language and framework

        if not language:
            dt = Detection(target_directory, files)
            main_language = dt.language
            main_framework = dt.framework
        else:
            main_language = pa.language
            main_framework = pa.language

        logger.info('[CLI] [STATISTIC] Language: {l} Framework: {f}'.format(l=",".join(main_language), f=main_framework))
        logger.info('[CLI] [STATISTIC] Files: {fc}, Extensions:{ec}, Consume: {tc}'.format(fc=file_count,
                                                                                           ec=len(files),
                                                                                           tc=time_consume))

        if pa.special_rules is not None:
            logger.info('[CLI] [SPECIAL-RULE] only scan used by {r}'.format(r=','.join(pa.special_rules)))

        # Pretreatment ast object
        ast_object.init_pre(target_directory, files)
        ast_object.pre_ast_all(main_language, is_unprecom=is_unprecom)

        # scan
        scan(target_directory=target_directory, a_sid=a_sid, s_sid=s_sid, special_rules=pa.special_rules,
             language=main_language, framework=main_framework, file_count=file_count, extension_count=len(files),
             files=files, secret_name=secret_name, is_unconfirm=is_unconfirm)
    except KeyboardInterrupt as e:
        logger.critical("[!] KeyboardInterrupt, exit...")
        exit()
    except PickupException as e:
        result = {
            'code': 1002,
            'msg': 'Repository not exist!'
        }
        Running(s_sid).data(result)
        raise
    except Exception:
        result = {
            'code': 1002,
            'msg': 'Exception'
        }
        Running(s_sid).data(result)
        raise

    # 输出写入文件
    write_to_file(target=target, sid=s_sid, output_format=formatter, filename=output)


def show_info(type, key):
    """
    展示信息
    """
    def list_parse(rules_path, istamp=False):

        files = os.listdir(rules_path)
        result = []

        for f in files:

            if f.startswith("_") or f.endswith("pyc"):
                continue

            if os.path.isdir(os.path.join(rules_path, f)):
                if f not in ['test', 'secret']:
                    result.append(f)

            if f.startswith("CVI_"):
                result.append(f)

            if istamp:
                if f not in ['test.py', 'demo.py', 'none.py']:
                    result.append(f)

        return result

    info_dict = {}

    if type == "rule":

        rule_lan_list = list_parse(rules_path)
        rule_dict = {}
        if key == "all":
            # show all
            for lan in rule_lan_list:
                info_dict[lan] = []
                rule_lan_path = os.path.join(rules_path, lan)

                info_dict[lan] = list_parse(rule_lan_path)

        elif key in rule_lan_list:
            info_dict[key] = []
            rule_lan_path = os.path.join(rules_path, key)

            info_dict[key] = list_parse(rule_lan_path)

        elif str(int(key)) == key:
            for lan in rule_lan_list:
                info_dict[lan] = []
                rule_lan_path = os.path.join(rules_path, lan)

                info_dict[lan] = list_parse(rule_lan_path)

            for lan in info_dict:
                if "CVI_{}.py".format(key) in info_dict[lan]:
                    f = codecs.open(os.path.join(rules_path, lan, "CVI_{}.py".format(key)), encoding='utf-8', errors="ignore")
                    return f.read()

            logger.error('[Show] no CVI id {}.'.format(key))
            return ""
        else:
            logger.error('[Show] error language/CVI id input.')
            return ""

        i = 0
        table = PrettyTable(
            ['#', 'CVI', 'Lang/CVE-id', 'Rule(ID/Name)', 'Match', 'Status'])

        table.align = 'l'

        for lan in info_dict:
            for rule in info_dict[lan]:
                i += 1
                rulename = rule.split('.')[0]
                rulefile = "rules." + lan + "." + rulename

                rule_obj = __import__(rulefile, fromlist=rulename)
                p = getattr(rule_obj, rulename)

                ruleclass = p()

                table.add_row([i, ruleclass.svid, ruleclass.language, ruleclass.vulnerability, ruleclass.match, ruleclass.status])

        return table

    elif type == "tamper":

        table = PrettyTable(
            ['#', 'TampName', 'FilterFunc', 'InputControl'])

        table.align = 'l'
        i = 0

        tamp_path = os.path.join(rules_path, 'secret/')
        tamp_list = list_parse(tamp_path, True)

        if key == "all":
            for tamp in tamp_list:
                i += 1
                tampname = tamp.split('.')[0]
                tampfile = "rules.secret." + tampname

                tamp_obj = __import__(tampfile, fromlist=tampname)

                filter_func = getattr(tamp_obj, tampname)
                input_control = getattr(tamp_obj, tampname + "_controlled")

                table.add_row([i, tampname, filter_func, input_control])

            return table
        elif key + ".py" in tamp_list:
            tampname = key
            tampfile = "rules.secret." + tampname

            tamp_obj = __import__(tampfile, fromlist=tampname)

            filter_func = getattr(tamp_obj, tampname)
            input_control = getattr(tamp_obj, tampname + "_controlled")

            return """
Tamper Name:
    {}

Filter Func:
    {}
    
Input Control:
    {}
""".format(tampname, filter_func, input_control)
        else:
            logger.error("[Info] no tamper name {]".format(key))

    return ""





