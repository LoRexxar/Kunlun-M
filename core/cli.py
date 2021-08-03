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
import pprint
from prettytable import PrettyTable

from .detection import Detection
from .engine import scan, Running
from .vendors import Vendors

from core.pretreatment import ast_object
from utils.export import write_to_file
from utils.log import logger
from utils.file import Directory, load_kunlunmignore
from utils.utils import show_context
from utils.utils import ParseArgs
from utils.utils import md5, random_generator
from core.vendors import get_project_by_version, get_project_vendor_by_name
from Kunlun_M.settings import RULES_PATH
from Kunlun_M.const import VUL_LEVEL

from web.index.models import ScanTask, ScanResultTask, Rules, NewEvilFunc, Project, ProjectVendors
from web.index.models import get_resultflow_class, get_and_check_scantask_project_id, check_and_new_project_id, get_and_check_scanresult


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


def check_scantask(task_name, target_path, parameter_config, project_origin, project_des="", auto_yes=False):
    s = ScanTask.objects.filter(task_name=task_name, target_path=target_path, parameter_config=parameter_config, is_finished=1).order_by("-id").first()

    if s and not auto_yes:
        logger.warning("[INIT] ScanTask for {} has been executed.".format(task_name))
        logger.warning("[INIT] whether rescan Task {}?(Y/N) (Default N)".format(task_name))

        if input().lower() != 'y':
            logger.warning("[INIT] whether Show Last Scan Result?(Y/N) (Default Y)")

            if input().lower() != 'n':
                scan_id = s.id
                table = PrettyTable(
                    ['#', 'CVI', 'Rule(ID/Name)', 'Lang/CVE-id', 'Level', 'Target-File:Line-Number',
                     'Commit(Author)', 'Source Code Content', 'Analysis'])
                table.align = 'l'

                # check unconfirm
                logger.warning("[INIT] whether Show Unconfirm Result?(Y/N) (Default Y)")
                project_id = get_and_check_scantask_project_id(scan_id)
                logger.info("[INIT] Now Project ID is {}".format(project_id))

                if input().lower() != 'n':
                    srs = get_and_check_scanresult(scan_id).objects.filter(scan_project_id=project_id, is_active=True)
                else:
                    srs = get_and_check_scanresult(scan_id).objects.filter(scan_project_id=project_id, is_active=True, is_unconfirm=False)

                if srs:
                    logger.info("[MainThread] Last Scan id {} Result: ".format(scan_id))

                    for sr in srs:
                        rule = Rules.objects.filter(svid=sr.cvi_id).first()
                        rule_name = rule.rule_name
                        author = rule.author
                        level = VUL_LEVEL[rule.level]

                        row = [sr.result_id, sr.cvi_id, rule_name, sr.language, level, sr.vulfile_path,
                               author, sr.source_code, sr.result_type]

                        table.add_row(row)

                        # show Vuls Chain
                        ResultFlow = get_resultflow_class(scan_id)
                        rfs = ResultFlow.objects.filter(vul_id=sr.id)

                        logger.info("[Chain] Vul {}".format(sr.id))
                        for rf in rfs:
                            logger.info("[Chain] {}, {}, {}:{}".format(rf.node_type, rf.node_content, rf.node_path, rf.node_lineno))
                            show_context(rf.node_path, rf.node_lineno)

                        logger.info(
                            "[SCAN] ending\r\n -------------------------------------------------------------------------")

                    logger.info("[SCAN] Trigger Vulnerabilities ({vn})\r\n{table}".format(vn=len(srs), table=table))

                    # show New evil Function
                    nfs = NewEvilFunc.objects.filter(project_id=project_id, is_active=1)

                    if nfs:

                        table2 = PrettyTable(
                            ['#', 'NewFunction', 'OriginFunction', 'Related Rules id'])

                        table2.align = 'l'
                        idy = 1

                        for nf in nfs:
                            row = [idy, nf.func_name, nf.origin_func_name, nf.svid]

                            table2.add_row(row)
                            idy += 1

                        logger.info("[MainThread] New evil Function list by NewCore:\r\n{table}".format(table=table2))

                else:
                    logger.info("[MainThread] Last Scan id {} has no Result.".format(scan_id))

        else:
            s = ScanTask(task_name=task_name, target_path=target_path, parameter_config=parameter_config)
            s.save()

            # check and new project
            check_and_new_project_id(scantask_id=s.id, task_name=task_name, project_origin=project_origin, project_des=project_des)

    else:
        s = ScanTask(task_name=task_name, target_path=target_path, parameter_config=parameter_config)
        s.save()

        # check and new project
        check_and_new_project_id(s.id, task_name=task_name, project_origin=project_origin, project_des=project_des)

    return s


def start(target, formatter, output, special_rules, a_sid=None, language=None, tamper_name=None, black_path=None, is_unconfirm=False, is_unprecom=False):
    """
    Start CLI
    :param black_path: 
    :param tamper_name:
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

    task_id = a_sid

    # 加载 kunlunmignore
    load_kunlunmignore()

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

        # vendor check
        project_id = get_and_check_scantask_project_id(task_id)
        Vendors(project_id, target_directory, files)

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
             files=files, tamper_name=tamper_name, is_unconfirm=is_unconfirm)
    except KeyboardInterrupt as e:
        logger.error("[!] KeyboardInterrupt, exit...")
        exit()
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
                if f not in ['test', 'tamper']:
                    result.append(f)

            if f.startswith("CVI_"):
                result.append(f)

            if istamp:
                if f not in ['test.py', 'demo.py', 'none.py']:
                    result.append(f)

        return result

    info_dict = {}

    if type == "rule":

        rule_lan_list = list_parse(RULES_PATH)
        rule_dict = {}
        if key == "all":
            # show all
            for lan in rule_lan_list:
                info_dict[lan] = []
                rule_lan_path = os.path.join(RULES_PATH, lan)

                info_dict[lan] = list_parse(rule_lan_path)

        elif key in rule_lan_list:
            info_dict[key] = []
            rule_lan_path = os.path.join(RULES_PATH, key)

            info_dict[key] = list_parse(rule_lan_path)

        elif str(int(key)) == key:
            for lan in rule_lan_list:
                info_dict[lan] = []
                rule_lan_path = os.path.join(RULES_PATH, lan)

                info_dict[lan] = list_parse(rule_lan_path)

            for lan in info_dict:
                if "CVI_{}.py".format(key) in info_dict[lan]:
                    f = codecs.open(os.path.join(RULES_PATH, lan, "CVI_{}.py".format(key)), encoding='utf-8', errors="ignore")
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

        tamp_path = os.path.join(RULES_PATH, 'tamper/')
        tamp_list = list_parse(tamp_path, True)

        if key == "all":
            for tamp in tamp_list:
                i += 1
                tampname = tamp.split('.')[0]
                tampfile = "rules.tamper." + tampname

                tamp_obj = __import__(tampfile, fromlist=tampname)

                filter_func = getattr(tamp_obj, tampname)
                input_control = getattr(tamp_obj, tampname + "_controlled")

                table.add_row([i, tampname, filter_func, input_control])

            return table
        elif key + ".py" in tamp_list:
            tampname = key
            tampfile = "rules.tamper." + tampname

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
""".format(tampname, pprint.pformat(filter_func, indent=4), pprint.pformat(input_control, indent=4))
        else:
            logger.error("[Info] no tamper name {]".format(key))

    return ""


def search_project(search_type, keyword, keyword_value):
    """
    根据信息搜索项目信息
    :param search_type:
    :param keyword:
    :param keyword_value:
    :return:
    """
    if search_type == 'vendor':
        ps = get_project_by_version(keyword, keyword_value)
        table = PrettyTable(
            ['#', 'ProjectId', 'Project Name', 'Project Origin', 'Vendor', 'Version'])

        table.align = 'l'
        i = 0

        if not ps:
            return False

        for p in ps:
            pid = p.id
            pname = p.project_name
            porigin = p.project_origin
            vs = ps[p]

            for v in vs:
                i += 1
                vendor_name = v.name
                vendor_vension = v.version

                table.add_row([i, pid, pname, porigin, vendor_name, vendor_vension])

        logger.info("Project List (Small than {} {}):\n{}".format(keyword, keyword_value, table))

    return True



