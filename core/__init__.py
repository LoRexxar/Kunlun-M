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
import sys
import time
import argparse
import logging
import traceback

from django.core.management import call_command
from utils.log import log, logger, log_add
from utils.utils import get_mainstr_from_filename, get_scan_id

from . import cli
from .cli import get_sid, show_info
from .engine import Running

from .__version__ import __title__, __introduction__, __url__, __version__
from .__version__ import __author__, __author_email__, __license__
from .__version__ import __copyright__, __epilog__, __scan_epilog__

from core.rule import RuleCheck, TamperCheck
from core.console import KunlunInterpreter
from web.index.models import ScanTask

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

        parser_group_init = subparsers.add_parser('init', help='Kunlun-M init before use.')
        parser_group_init.add_argument('-init', action='store_true', default=False)

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

        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')

        parser_group_scan.add_argument('-uc', '--unconfirm', dest='unconfirm', action='store_false', default=False, help='show unconfirmed vuls')
        parser_group_scan.add_argument('-upc', '--unprecom', dest='unprecom', action='store_false', default=False, help='without Precompiled')

        parser_group_show = subparsers.add_parser('show', help='show rule&tamper', description=__introduction__.format(detail='show rule&tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)

        parser_group_show.add_argument('list', choices=['rule', "tamper"], action='store', default=None,
                                       help='show all rules & tanmpers')

        parser_group_show.add_argument('-k', '--key', dest='listkey', action='store', default="all",
                                       help='key for show rule & tamper. eg: 1001/wordpress')

        parser_group_console = subparsers.add_parser('console', help='enter console mode',
                                                     description=__introduction__.format(detail='enter console mode'),
                                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                                     usage=argparse.SUPPRESS, add_help=True)
        parser_group_console.add_argument('console', action='store_true', default=True,
                                          help='enter console mode')

        # 加载插件参数列表以及帮助

        parser_group_plugin = subparsers.add_parser('plugin', help='Load plugins',
                                                    description=__introduction__.format(detail='Load plugins'),
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    usage=argparse.SUPPRESS, add_help=True)
        parser_group_plugin.add_argument('plugin_name', choices=plugins.PLUGIN_LIST, default=False,
                                         help='enter plugin name')

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
            logger.debug('[INIT] set logging level: debug')

        if hasattr(args, "init"):
            logger.info('Init Database for KunLun-M.')
            call_command('makemigrations')
            call_command('migrate')
            logger.info('Init Database Finished.')
            exit()

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

        logger.debug('[INIT] start Scan Task...')

        # new scan task
        task_name = get_mainstr_from_filename(args.target)
        s = cli.check_scantask(task_name=task_name, target_path=args.target, parameter_config=sys.argv)

        if s.is_finished:
            logger.info("[INIT] Finished Task.")
            exit()

        # 标识任务id
        sid = str(s.id)
        get_scan_id()

        if hasattr(args, "log") and args.log:
            logger.info("[INIT] New Log file {}.log .".format(args.log))
            log_add(logging.INFO, args.log)
        else:
            logger.info("[INIT] New Log file ScanTask_{}.log .".format(sid))
            log_add(logging.INFO, "ScanTask_{}".format(sid))

        if hasattr(args, "debug") and args.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug('[INIT] set logging level: debug')

        data = {
            'status': 'running',
            'report': ''
        }
        Running(sid).status(data)

        cli.start(args.target, args.format, args.output, args.special_rules, sid, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom)

        s.is_finished = True
        s.save()
        t2 = time.time()
        logger.info('[INIT] Done! Consume Time:{ct}s'.format(ct=t2 - t1))

    except KeyboardInterrupt:
        logger.warning("[KunLun-M] Stop KunLun-M.")
        sys.exit(0)

    except Exception as e:
        exc_msg = traceback.format_exc()
        logger.warning(exc_msg)


if __name__ == '__main__':
    main()
