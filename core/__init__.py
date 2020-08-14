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

from utils.log import log, logger

from . import cli
from .cli import get_sid, show_info
from .engine import Running

from .__version__ import __title__, __introduction__, __url__, __version__
from .__version__ import __author__, __author_email__, __license__
from .__version__ import __copyright__, __epilog__, __scan_epilog__

from core.rule import RuleCheck, TamperCheck

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

        parser_group_core = subparsers.add_parser('config', help='config for rule&tamper', description=__introduction__.format(detail='config for rule&tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)
        parser_group_core.add_argument('load', choices=['load', 'recover', 'loadtamper', 'retamper'], default=False, help='operate for rule&tamper')

        parser_group_scan = subparsers.add_parser('scan', help='scan target path', description=__introduction__.format(detail='scan target path'), epilog=__scan_epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
        parser_group_scan.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='file, folder, compress, or repository address')
        parser_group_scan.add_argument('-f', '--format', dest='format', action='store', default='csv', metavar='<format>', choices=['html', 'json', 'csv', 'xml'], help='vulnerability output format (formats: %(choices)s)')
        parser_group_scan.add_argument('-o', '--output', dest='output', action='store', default='', metavar='<output>', help='vulnerability output STREAM, FILE')
        parser_group_scan.add_argument('-r', '--rule', dest='special_rules', action='store', default=None, metavar='<rule_id>', help='specifies rules e.g: 1000, 1001')
        parser_group_scan.add_argument('-tp', '--tamper', dest='tamper_name', action='store', default=None, metavar='<tamper_name>', help='tamper repair function e.g: wordpress')
        parser_group_scan.add_argument('-i', '--sid', dest='sid', action='store', default=None, metavar='<sid>', help='set sid')
        parser_group_scan.add_argument('-l', '--log', dest='log', action='store', default=None, metavar='<log>', help='log name')
        parser_group_scan.add_argument('-lan', '--language', dest='language', action='store', default=None, help='set target language')
        parser_group_scan.add_argument('-b', '--blackpath', dest='black_path', action='store', default=None, help='black path list')

        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')

        parser_group_scan.add_argument('-uc', '--unconfirm', dest='unconfirm', action='store_false', default=False, help='show unconfirmed vuls')
        parser_group_scan.add_argument('-upc', '--unprecom', dest='unprecom', action='store_false', default=False, help='without Precompiled')

        parser_group_show = subparsers.add_parser('show', help='show rule&tamper', description=__introduction__.format(detail='show rule&tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)

        parser_group_show.add_argument('-list', '--list', dest='list', action='store', default=None, help='show all rules')
        parser_group_show.add_argument('-listt', '--listtamper', dest='listtamper', action='store', default=None,
                                       help='show all tamper')

        args = parser.parse_args()

        # log
        if hasattr(args, "log") and args.log:
            log(logging.INFO, args.log)
        else:
            log(logging.INFO, str(time.time()))

        if hasattr(args, "debug") and args.debug:
            logger.setLevel(logging.DEBUG)
            logger.debug('[INIT] set logging level: debug')

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

        if hasattr(args, "list"):
            if args.list or args.listtamper:
                if args.list:
                    logger.info("Show List:\n{}".format(show_info('rule', args.list.strip(""))))

                if args.listtamper:
                    logger.info("Show Tamper List:\n{}".format(show_info('tamper', args.listtamper.strip(""))))

                exit()

        if (not hasattr(args, "target") or args.target == '') or (not hasattr(args, "output") or args.output == ''):
            parser.print_help()
            exit()

        logger.debug('[INIT] start scanning...')

        if hasattr(args, "sid") and args.sid:
            a_sid = args.sid
        else:
            a_sid = get_sid(args.target, True)

        data = {
            'status': 'running',
            'report': ''
        }
        Running(a_sid).status(data)

        cli.start(args.target, args.format, args.output, args.special_rules, a_sid, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom)

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
