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

from django.utils import timezone
from django.core.management import call_command
from utils.log import log, logger, log_add, log_rm
from utils.utils import get_mainstr_from_filename, random_generator
from utils.status import get_scan_id, set_scan_id_provider
from utils.web import upload_log
from utils.file import load_kunlunmignore

from . import cli
from .cli import get_sid, show_info
from .engine import Running

from .__version__ import __title__, __introduction__, __url__, __version__
from .__version__ import __author__, __author_email__, __license__
from .__version__ import __copyright__, __epilog__, __scan_epilog__

from core.rule import RuleCheck, TamperCheck
from core.scaffold import write_rule_file, write_tamper_file
from core.console import KunlunInterpreter
from web.index.models import ScanTask, check_and_new_project_id

# 注册 scan_id 提供者回调，解耦 utils/status.py 对 web 层的直接依赖
set_scan_id_provider(lambda: (lambda o: o.id if o else -1)(ScanTask.objects.order_by("-id").first()))

from Kunlun_M.settings import LOGS_PATH, IS_OPEN_REMOTE_SERVER, REMOTE_URL

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

        # 核心命令列表，在 -h 中分组展示
        CORE_COMMANDS = {'init', 'scan', 'console', 'web', 'analyze'}

        class GroupedSubparsersFormatter(argparse.RawDescriptionHelpFormatter):
            """自定义 formatter：将 subparsers 拆分为 Core Commands 和 Other Commands 两组"""

            def _format_subgroup(self, title, actions):
                """格式化子命令分组"""
                if not actions:
                    return ''
                max_len = max(len(a.dest) for a in actions)
                lines = [title, '-' * len(title)]
                for a in actions:
                    help_text = self._expand_help(a)
                    help_lines = help_text.split(chr(10))
                    lines.append('  {:<{}} {}'.format(a.dest, max_len, help_lines[0]))
                    for extra in help_lines[1:]:
                        lines.append('  {:<{}} {}'.format('', max_len, extra.strip()))
                return chr(10).join(lines)

            def _format_action(self, action):
                if isinstance(action, argparse._SubParsersAction):
                    core = [s for s in action._get_subactions() if s.dest in CORE_COMMANDS]
                    other = [s for s in action._get_subactions() if s.dest not in CORE_COMMANDS]
                    parts = []
                    if core:
                        parts.append(self._format_subgroup("Core Commands", core))
                    if other:
                        parts.append(self._format_subgroup("Other Commands", other))
                    return chr(10).join(parts)
                return super()._format_action(action)

        parser = argparse.ArgumentParser(prog=__title__, description=__introduction__.format(detail="Main Program"), epilog=__epilog__, formatter_class=GroupedSubparsersFormatter, usage=argparse.SUPPRESS)

        subparsers = parser.add_subparsers()

        # init
        parser_group_init = subparsers.add_parser('init', help='Kunlun-M init before use.')
        parser_group_init.set_defaults(init="init")

        # export rules and tampers from database to files
        parser_group_export = subparsers.add_parser('export', help='export rules and tampers from database to files', description=__introduction__.format(detail='export rules and tampers'), epilog='Usage:\n  python {} export'.format('kunlun.py'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)
        parser_group_export.set_defaults(export="export")

        parser_group_generate = subparsers.add_parser(
            'generate',
            help='generate rule & tamper',
            description=__introduction__.format(detail='generate rule & tamper'),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            usage=argparse.SUPPRESS,
            add_help=True,
        )
        parser_group_generate_sub = parser_group_generate.add_subparsers(dest='generate_type')

        parser_generate_rule = parser_group_generate_sub.add_parser('rule', help='generate rule file')
        parser_generate_rule.add_argument('-lan', '--language', dest='language', action='store', default=None, help='language (php/javascript/solidity/chrome_ext)')
        parser_generate_rule.add_argument('--name', dest='rule_name', action='store', default=None, help='rule name (vulnerability)')
        parser_generate_rule.add_argument('--author', dest='author', action='store', default=__author__, help='author')
        parser_generate_rule.add_argument('--description', dest='rule_description', action='store', default=None, help='description')
        parser_generate_rule.add_argument('--level', dest='level', action='store', default=1, type=int, help='level')
        parser_generate_rule.add_argument('--disable', dest='disable', action='store_true', default=False, help='disable rule')
        parser_generate_rule.add_argument('--match-mode', dest='match_mode', action='store', default='function-param-regex', help='match mode')
        parser_generate_rule.add_argument('--match', dest='match', action='store', default=None, help='match regex or python literal')
        parser_generate_rule.add_argument('--unmatch', dest='unmatch', action='store', default=None, help='unmatch regex or python literal')
        parser_generate_rule.add_argument('--svid', dest='svid', action='store', default=None, type=int, help='rule id')
        parser_generate_rule.add_argument('--sync', dest='sync', action='store_true', default=False, help='sync to database after generated')
        parser_generate_rule.add_argument('--force', dest='force', action='store_true', default=False, help='overwrite if file exists')

        parser_generate_tamper = parser_group_generate_sub.add_parser('tamper', help='generate tamper file')
        parser_generate_tamper.add_argument('--name', dest='tamper_name', action='store', default=None, help='tamper name')
        parser_generate_tamper.add_argument('--filter-func', dest='filter_func', action='store', default=None, help='json dict or k=v,k=v')
        parser_generate_tamper.add_argument('--controlled', dest='controlled', action='store', default=None, help='controlled sources list split by ,')
        parser_generate_tamper.add_argument('--sync', dest='sync', action='store_true', default=False, help='sync to database after generated')
        parser_generate_tamper.add_argument('--force', dest='force', action='store_true', default=False, help='overwrite if file exists')

        parser_group_scan = subparsers.add_parser('scan', help='scan target path', description=__introduction__.format(detail='scan target path'), epilog=__scan_epilog__, formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
        parser_group_scan.add_argument('-t', '--target', dest='target', action='store', default='', metavar='<target>', help='file, folder')
        parser_group_scan.add_argument('-f', '--format', dest='format', action='store', default='csv', metavar='<format>', choices=['html', 'md', 'json', 'csv', 'xml'], help='vulnerability output format (formats: %(choices)s)')
        parser_group_scan.add_argument('-o', '--output', dest='output', action='store', default='', metavar='<output>', help='vulnerability output STREAM, FILE')
        parser_group_scan.add_argument('-r', '--rule', dest='special_rules', action='store', default=None, metavar='<rule_id>', help='specifies rules e.g: 1000, 1001')
        parser_group_scan.add_argument('-tp', '--tamper', dest='tamper_name', action='store', default=None, metavar='<tamper_name>', help='tamper repair function e.g: wordpress')
        parser_group_scan.add_argument('-l', '--log', dest='log', action='store', default=None, metavar='<log>', help='log name')
        parser_group_scan.add_argument('-lan', '--language', dest='language', action='store', default=None, help='set target language')
        parser_group_scan.add_argument('-b', '--blackpath', dest='black_path', action='store', default=None, help='black path list')
        parser_group_scan.add_argument('-ht', '--html-template', dest='html_template', action='store', default=None, metavar='<template>', help='custom Jinja2 HTML template for report')

        # for api
        parser_group_scan.add_argument('-a', '--api', dest='api', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('-y', '--yes', dest='yes', action='store_true', default=False,
                                       help='without any output for shell')
        parser_group_scan.add_argument('-np', '--newpro', dest='newpro', action='store_true', default=False,
                                       help='Default use new project for scan task.')
        parser_group_scan.add_argument('--origin', dest='origin', action='store', default=None, metavar='<origin>', help='project origin')
        parser_group_scan.add_argument('-des', '--description', dest='description', action='store', default=None, metavar='<description>', help='project description')
        parser_group_scan.add_argument('--task-id', dest='task_id', action='store', default=None, metavar='<task_id>', help='reuse an existing ScanTask id (for web scan)')

        # for log
        parser_group_scan.add_argument('-d', '--debug', dest='debug', action='store_true', default=False, help='open debug mode')

        # for scan profile
        parser_group_scan.add_argument('-uc', '--unconfirm', dest='unconfirm', action='store_true', default=False, help='show unconfirmed vuls')
        parser_group_scan.add_argument('-upc', '--unprecom', dest='unprecom', action='store_true', default=False, help='without Precompiled')
        parser_group_scan.add_argument('--no-cache', dest='no_cache', action='store_true', default=False, help='force rebuild graph without loading cache')

        # for vendor vuln scan
        parser_group_scan.add_argument('--without-vendor', dest='without_vendor', action='store_true', default=False, help='without scan vendor vuln (default open)')

        # show for rule & tamper
        parser_group_show = subparsers.add_parser('show', help='show rule & tamper', description=__introduction__.format(detail='show rule & tamper'), formatter_class=argparse.RawDescriptionHelpFormatter, usage=argparse.SUPPRESS, add_help=True)

        parser_group_show.add_argument('list', choices=['rule', "tamper"], action='store', default=None,
                                       help='show all rules & tampers')

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
        parser_group_console.set_defaults(console=True)

        # analyze — secondary graph analysis
        parser_group_analyze = subparsers.add_parser('analyze', help='secondary analysis on AST graph',
                                                    description=__introduction__.format(detail='secondary analysis on AST graph'),
                                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                                    usage=argparse.SUPPRESS, add_help=True)
        parser_group_analyze.add_argument('-g', '--graph-dir', dest='graph_dir', required=False, default=None,
                                           help='graph directory (default: auto from workspace)')
        parser_group_analyze.add_argument('-s', '--scan-id', dest='scan_id', type=int, default=None,
                                           help='scan ID to analyze (default: latest)')
        parser_group_analyze.add_argument('-d', '--db', dest='db_path', default=None,
                                           help='SQLite DB path')
        parser_group_analyze.add_argument('-l', '--language', dest='language', default='php',
                                           help='source language')
        parser_group_analyze.add_argument('query_type', nargs='?', default='overview',
                                           help='query type: overview/file/function/trace/search')
        parser_group_analyze.add_argument('query_arg', nargs='?', default=None,
                                           help='argument for query (file path / function name / file:line)')
        parser_group_analyze.set_defaults(analyze="analyze")

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
            logger.info('Init Database for KunLun-M.')
            call_command('makemigrations')
            call_command('migrate')
            logger.info('Init Database Finished.')
            exit()

        if hasattr(args, "port"):
            logger.info('Start KunLun-M Web in Port: {}'.format(args.port))
            # 自动执行数据库迁移，确保新增 model 字段在启动时生效
            try:
                call_command('migrate', verbosity=0)
                logger.info('[INIT] Database migration applied.')
            except Exception as e:
                logger.warning('[INIT] Database migration failed: {}'.format(e))
            # 自动同步规则和 tamper 到数据库
            logger.debug('[INIT] Syncing rules and tampers...')
            try:
                RuleCheck().load()
                TamperCheck().load()
                logger.info('[INIT] Rule/Tamper sync finished.')
            except Exception as e:
                logger.warning('[INIT] Rule/Tamper sync skipped: {}'.format(e))
            call_command('runserver', args.port)

        if hasattr(args, "export") and args.export == "export":
            logger.info("[INIT] Export rules and tampers start.")
            RuleCheck().export()
            TamperCheck().export()
            logger.info("[INIT] Export rules and tampers finished.")
            exit()

        if hasattr(args, "generate_type") and args.generate_type:
            if args.generate_type == "rule":
                if not args.language or not args.rule_name:
                    parser_group_generate.print_help()
                    exit()
                rid, rule_path = write_rule_file(
                    language=args.language,
                    rule_name=args.rule_name,
                    author=args.author,
                    description=args.rule_description,
                    svid=args.svid,
                    level=args.level,
                    status=not args.disable,
                    match_mode=args.match_mode,
                    match=args.match,
                    unmatch=args.unmatch,
                    force=args.force,
                )
                logger.info("[INIT] Generated rule CVI_{}: {}".format(rid, rule_path))
                if args.sync:
                    logger.info("[INIT] RuleCheck start.")
                    RuleCheck().load()
                    logger.info("[INIT] RuleCheck finished.")
                exit()

            if args.generate_type == "tamper":
                if not args.tamper_name:
                    parser_group_generate.print_help()
                    exit()
                tamper_path = write_tamper_file(
                    tam_name=args.tamper_name,
                    filter_func=args.filter_func,
                    controlled=args.controlled,
                    force=args.force,
                )
                logger.info("[INIT] Generated tamper {}: {}".format(args.tamper_name, tamper_path))
                if args.sync:
                    logger.info("[INIT] TamperCheck start.")
                    TamperCheck().load()
                    logger.info("[INIT] TamperCheck finished.")
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

        if hasattr(args, "analyze") and args.analyze == "analyze":
            import json as _json
            from core.graph.session import AstGraphSession
            from core.graph.workspace import get_workspace_db

            workspace_db = get_workspace_db()
            scan_id = getattr(args, 'scan_id', None)
            graph_dir = args.graph_dir

            # 自动查找 scan
            if not graph_dir:
                from core.graph.sqlite_index import ScanRecord
                sr = ScanRecord(workspace_db)
                if scan_id is not None:
                    info = sr.get_by_id(scan_id)
                else:
                    info = sr.get_latest()
                if not info:
                    logger.error("No scan found in workspace. Run a scan first.")
                    exit(1)
                scan_id = info['id']
                graph_dir = os.path.dirname(info['graph_path'])
                logger.info("[ANALYZE] Using scan_id=%s, graph_dir=%s", scan_id, graph_dir)

            try:
                session = AstGraphSession(graph_dir, db_path=workspace_db, language=args.language)
                session.load()

                if args.query_type == "overview":
                    result = session.query.overview()
                elif args.query_type == "file":
                    if not args.query_arg:
                        logger.error("Usage: kunlun.py analyze file <path>")
                        exit(1)
                    result = session.query.get_file(args.query_arg)
                elif args.query_type == "function":
                    if not args.query_arg:
                        logger.error("Usage: kunlun.py analyze function <name>")
                        exit(1)
                    result = session.query.get_function(args.query_arg)
                elif args.query_type == "trace":
                    if not args.query_arg:
                        logger.error("Usage: kunlun.py analyze trace <file:line>")
                        exit(1)
                    parts = args.query_arg.rsplit(":", 1)
                    if len(parts) != 2:
                        logger.error("trace argument format: <file_path>:<line_number>")
                        exit(1)
                    result = session.query.trace(parts[0], int(parts[1]))
                elif args.query_type == "search":
                    if not args.query_arg:
                        result = session.query.search()
                    else:
                        tokens = args.query_arg.split(":", 2)
                        label = tokens[0] if len(tokens) > 0 else None
                        name = tokens[1] if len(tokens) > 1 else None
                        result = session.query.search(label=label, name=name)
                else:
                    logger.error("Unknown query type: %s", args.query_type)
                    exit(1)

                print(_json.dumps(result, indent=2, ensure_ascii=False, default=str))
            except FileNotFoundError as e:
                logger.error(e)
                exit(1)
            except Exception as e:
                logger.error("[ANALYZE] Error: %s", e)
                exit(1)

        if hasattr(args, "console"):
            # 静默同步规则和 tamper
            logger.debug("[INIT] Syncing rules and tampers...")
            try:
                RuleCheck().load()
                TamperCheck().load()
            except Exception as e:
                logger.warning("[INIT] Rule/Tamper sync skipped: {}".format(e))
            logger.debug("[INIT] Sync finished.")

            logger.info("[INIT] Enter KunLun-M console mode.")
            shell = KunlunInterpreter()
            shell.start()
            exit()

        if not hasattr(args, "target") or args.target == '':
            parser.print_help()
            exit()

        # 静默同步规则和 tamper（scan 模式也需要）
        logger.debug("[INIT] Syncing rules and tampers...")
        try:
            RuleCheck().load()
            TamperCheck().load()
        except Exception as e:
            logger.warning("[INIT] Rule/Tamper sync skipped: {}".format(e))

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

        if hasattr(args, "task_id") and args.task_id:
            s = ScanTask.objects.filter(id=int(args.task_id)).first()
            if not s:
                logger.warning("[INIT] ScanTask {} not found.".format(args.task_id))
                exit()

            if int(s.is_finished) == 1:
                logger.info("[INIT] Finished Task.")
                exit()

            s.target_path = args.target
            s.parameter_config = sys.argv
            s.last_scan_time = timezone.now()
            if not s.task_name:
                s.task_name = get_mainstr_from_filename(args.target)
            s.save()

            check_and_new_project_id(s.id, s.task_name, origin, project_des=args.description)
        else:
            if args.newpro:
                logger.info('[INIT] Use new project for scan task.')
                task_name = random_generator(16)
            else:
                task_name = get_mainstr_from_filename(args.target)
            s = cli.check_scantask(task_name=task_name, target_path=args.target, parameter_config=sys.argv, project_origin=origin, project_des=args.description, auto_yes=args.yes)

            if int(s.is_finished) == 1:
                logger.info("[INIT] Finished Task.")
                exit()

        # 标识任务id
        sid = str(s.id)
        task_id = get_scan_id()

        #  for api
        if hasattr(args, "api") and args.api:
            print("TaskID: {}".format(task_id))
            # 计算结果路径
            result_url = "{}dashboard/tasks/detail/{}?token={}".format(REMOTE_URL, s.id, s.visit_token)
            print("Result Url: {}".format(result_url))
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

        s.is_finished = 2
        s.started_at = timezone.now()
        s.finished_at = None
        s.exit_code = None
        s.error_message = None
        s.save()

        try:
            cli.start(args.target, args.format, args.output, args.special_rules, sid, args.language, args.tamper_name, args.black_path, args.unconfirm, args.unprecom, template_path=args.html_template, no_cache=args.no_cache)
        except Exception as e:
            s.is_finished = 0
            s.finished_at = timezone.now()
            s.exit_code = 1
            s.error_message = str(e)[:2000]
            s.save()
            raise

        s.is_finished = 1
        s.finished_at = timezone.now()
        s.exit_code = 0
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
