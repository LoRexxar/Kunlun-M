#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    core
    ~~~~~

    Implements core main

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os
import sys
import time
import argparse
import logging
import traceback

from django.core.management import call_command
from utils.log import log, logger, log_add, log_rm
from utils.utils import get_mainstr_from_filename
from utils.status import get_scan_id
from utils.web import upload_log
from utils.file import load_kunlunmignore

from . import cli
from .cli import get_sid, show_info
from .engine import Running

from .__version__ import __title__, __introduction__, __url__, __version__
from .__version__ import __author__, __author_email__, __license__
from .__version__ import __copyright__, __epilog__, __scan_epilog__

from core.rule import RuleCheck, TamperCheck
from core.console import KunlunInterpreter
from web.index.models import ScanTask

from Kunlun_M.settings import LOGS_PATH, IS_OPEN_REMOTE_SERVER

from . import plugins

try:
    reload(sys)
    sys.setdefaultencoding('utf-8')
except NameError as e:
    pass


def main():
    try:
        # arg parse
        t1 = time.time()
        parser = argparse.ArgumentParser(prog=__title__, description=__introduction__.format(detail="Main Program"), epilog=__epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS)

        subparsers = parser.add_subparsers()

        # init
        parser_group_init = subparsers.add_parser('init', help='Kunlun-M init before use.')
        parser_group_init.add_argument('init', choices=['initialize', 'checksql'], default='init', help='check and migrate SQL')
        parser_group_init.add_argument('appname', choices=['index', 'dashboard', 'backend', 'api'],  nargs='?', default='index',
                                       help='Check App name')
        parser_group_init.add_argument('migrationname', default='migrationname',  nargs='?', help='Check migration name')

        # load config into database
        parser_group_core = subparsers.add_parser('config', help='config for rule&tamper', description=__introduction__.format(detail='config for rule&tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)
        parser_group_core.add_argument('load', choices=['load', 'recover', 'loadtamper', 'retamper'], default=False, help='operate for rule&tamper')

        parser_group_scan = subparsers.add_parser('scan', help='scan target path', description=__introduction__.format(detail='scan target path'), epilog=__scan_epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
        parser_group_scan.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='file, folder')
        parser_group_scan.add_argument('-f', '--format', dest='format', action='store', default='csv', metavar='<format>', choices=['html', 'json', 'csv', 'xml'], help='vulnerability output format (formats: %(choices)s)')
        parser_group_scan.add_argument('-o', '--output', dest='output', action='store', default='', metavar='<output>', help='vulnerability output STREAM, FILE')
        parser_group_scan.add_argument('-r', '--rule', dest='special_rules', action='store', default=None, metavar='<rule_id>', help='specifies rules e.g: 1000, 1001')
        parser_group_scan.add_argument('-tp', '--tamper', dest='tamper_name', action='store', default=None, metavar='<tamper_name>', help='tamper repair function e.g: wordpress')
        parser_group_scan.add_argument('-l', '--log', dest='log', action='store', default=None, metavar='<log>', help='log name')
        parser_group_scan.add_argument('-lan', '--language', dest='language', action='store', default=None, help='set target language')
        parser_group_scan.add_argument('-b', '--blackpath', dest='black_path', action='store', default=None, help='black path list')

        # for api
        parser_group_scan.add_argument('-a', '--api', dest='api', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('-y', '--yes', dest='yes', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('--origin', dest='origin', action='store', default=None, metavar='<origin>', help='project origin')
        parser_group_scan.add_argument('-des', '--description', dest='description', action='store', default=None, metavar='<description>', help='project description')

        # for log
        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')

        # for scan profile
        parser_group_scan.add_argument('-uc', '--unconfirm', dest='unconfirm', action='store_true', default=False, help='show unconfirmed vuls')
        parser_group_scan.add_argument('-upc', '--unprecom', dest='unprecom', action='store_true', default=False, help='without Precompiled')

        # for vendor vuln scan
        parser_group_scan.add_argument('--without-vendor', dest='without_vendor', action='store_true', default=False, help='without scan vendor vuln (default open)')

        # show for rule & tamper
        parser_group_show = subparsers.add_parser('show', help='show rule&tamper', description=__introduction__.format(detail='show rule&tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)

        parser_group_show.add_argument('list', choices=['rule', "tamper"], action='store', default=None,
                                       help='show all rules & tanmpers')

        parser_group_show.add_argument('-k', '--key', dest='listkey', action='store', default="all",
                                       help='key for show rule & tamper. eg: 1001/wordpress')

        # for search vendor
        parser_group_search = subparsers.add_parser('search', help='search project by vendor/path/...', description=__introduction__.format(detail='search project by vendor/path/...'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)

        parser_group_search.add_argument('stype', choices=['vendor'], default='vendor', help='search type')

        parser_group_search.add_argument('keyword_name', default='flask', nargs='?', help='keyword name for search')

        parser_group_search.add_argument('keyword_value', default='1.0.0', nargs='?', help='keyword value for search')

        parser_group_search.add_argument('--with-vuls', dest='with_vuls', action='store_true', default=False, help='with vuls scan (default False)')

        # console
        parser_group_console = subparsers.add_parser('console', help='enter console mode',
                                                     description=__introduction__.format(detail='enter console mode'),
                                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                                     usage=argparse.SUPPRESS, add_help=True)
        parser_group_console.add_argument('console', action='store_true', default=True,
                                          help='enter console mode')

        # 加载插件参数列表以及帮助

        parser_group_plugin = subparsers.add_parser('plugin', help=plugins.PLUGIN_DESCS,
                                                    description=__introduction__.format(detail=plugins.PLUGIN_DESCS),
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    usage=argparse.SUPPRESS, add_help=True)
        parser_group_plugin.add_argument('plugin_name', choices=plugins.PLUGIN_LIST, default=False,
                                         help='enter plugin name')

        # web

        parser_group_web = subparsers.add_parser('web', help='KunLun-m Web mode',
                                                 description=__introduction__.format(detail='KunLun-m Web mode'),
                                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                                 usage=argparse.SUPPRESS, add_help=True)

        parser_group_web.add_argument('-p', '--port', dest='port', action='store', default='9999',
                                      help='port for web')

        # args = parser.parse_args()
        args = parser.parse_known_args()[0]

        # log
        log(logging.INFO)

        # 插件需要提前声明
        if hasattr(args, "plugin_name") and args.plugin_name:
            logger.info('[INIT] Load Plugin {}.'.format(args.plugin_name))
            plugins.PLUGIN_DICT[args.plugin_name](parser, parser_group_plugin)
            exit()

        # 其余需要验证
        args = parser.parse_args()

        if hasattr(args, "debug") and args.debug:
            logger.setLevel(logging.DEBUG)

        if hasattr(args, "init"):
            if args.init == 'checksql':
                logger.info('Show migrate sql.')
                call_command('sqlmigrate', args.appname, args.migrationname)
            else:
                logger.info('Init Database for KunLun-M.')
                call_command('makemigrations')
                call_command('migrate')
                logger.info('Init Database Finished.')
            exit()

        if hasattr(args, "port"):
            logger.info('Start KunLun-M Web in Port: {}'.format(args.port))
            call_command('runserver', args.port)

        if hasattr(args, "load"):
            if args.load == "load":
                logger.info("[INIT] RuleCheck start.")
                RuleCheck().load()

                logger.info("[INIT] RuleCheck finished.")
                exit()

            elif args.load == "recover":
                logger.info("[INIT] RuleRecover start.")
                RuleCheck().recover()

                logger.info("[INIT] RuleRecover finished.")
                exit()

            elif args.load == "loadtamper":
                logger.info("[INIT] TamperCheck start.")
                TamperCheck().load()

                logger.info("[INIT] TamperCheck finished.")
                exit()

            elif args.load == "retamper":
                logger.info("[INIT] TamperRecover start.")
                TamperCheck().recover()

                logger.info("[INIT] TamperRecover finished.")
                exit()

            else:
                parser_group_core.print_help()
                exit()

        if hasattr(args, "list"):
            if args.list:
                logger.info("Show {}:\n{}".format(args.list, show_info(args.list, args.listkey.strip(""))))
                exit()
            else:
                parser_group_show.print_help()
                exit()

        if hasattr(args, "stype"):
            # search and show vuls
            if args.stype:
                logger.info("[SEARCH] Search Project by {} in {} {}".format(args.stype, args.keyword_name, args.keyword_value))
                cli.search_project(args.stype, args.keyword_name, args.keyword_value, args.with_vuls)
                exit()
            else:
                parser_group_show.print_help()
                exit()

        if hasattr(args, "console"):
            # check rule and tamper
            logger.info("[INIT] RuleCheck start.")
            RuleCheck().load()

            logger.info("[INIT] RuleCheck finished.")

            logger.info("[INIT] TamperCheck start.")
            TamperCheck().load()

            logger.info("[INIT] TamperCheck finished.")

            logger.info("[INIT] Enter KunLun-M console mode.")
            shell = KunlunInterpreter()
            shell.start()
            exit()

        if not hasattr(args, "target") or args.target == '':
            parser.print_help()
            exit()

        # for api close log
        if hasattr(args, "api") and args.api:
            log_rm()

        logger.debug('[INIT] start Scan Task...')
        logger.debug('[INIT] set logging level: {}'.format(logger.level))

        # check for project data
        if hasattr(args, "origin") and args.origin:
            origin = args.origin
        else:
            origin = "File in {}".format(args.target)

        # new scan task
        task_name = get_mainstr_from_filename(args.target)
        s = cli.check_scantask(task_name=task_name, target_path=args.target, parameter_config=sys.argv, project_origin=origin, project_des=args.description, auto_yes=args.yes)

        if s.is_finished:
            logger.info("[INIT] Finished Task.")
            exit()

        # 标识任务id
        sid = str(s.id)
        task_id = get_scan_id()

        #  for api
        if hasattr(args, "api") and args.api:
            print("TaskID: {}".format(task_id))
        else:
            logger.info("TaskID: {}".format(task_id))

        if hasattr(args, "log") and args.log:
            logger.info("[INIT] New Log file {}.log .".format(args.log))
            log_name = args.log
        else:
            logger.info("[INIT] New Log file ScanTask_{}.log .".format(sid))
            log_name = "ScanTask_{}".format(sid)

        log_add(logging.DEBUG, log_name)

        if hasattr(args, "without_vendor"):
            # 共享变量
            import Kunlun_M.settings as settings
            settings.WITH_VENDOR = False if args.without_vendor else settings.WITH_VENDOR
            logger.info("[INIT] Vendor Vuls Scan Status: {}".format(settings.WITH_VENDOR))

        data = {
            'status': 'running',
            'report': ''
        }
        Running(sid).status(data)

        cli.start(args.target, args.format, args.output, args.special_rules, sid, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom)

        s.is_finished = True
        s.save()
        t2 = time.time()

        # 如果开启了上传日志到远程，则上传
        if IS_OPEN_REMOTE_SERVER:
            log_path = os.path.join(LOGS_PATH, "{}.log".format(log_name))

            upload_log(log_path)

        logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

    except KeyboardInterrupt:
        logger.warning("[KunLun-M] Stop KunLun-M.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning(exc_msg)


if __name__ == '__main__':
    main()