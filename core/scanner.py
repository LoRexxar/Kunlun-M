# -*- coding: utf-8 -*-

"""
    scanner
    ~~~~~~~

    扫描调度与任务管理

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import json
import os
import re
import asyncio
import traceback
import portalocker

from core.rule import Rule
from core.matcher import VulnerabilityMatcher as Core
# ── Legacy engine imports (only used by oldscan/scan_single/SingleRule below) ──
from core.rule_generator import NewCore
from core.core_engine.php.parser import find_sinks as php_find_sinks
from core.core_engine.python.parser import find_sinks as python_find_sinks
from core.core_engine.java.parser import find_sinks as java_find_sinks
from core.core_engine.javascript.parser import find_sinks as js_find_sinks
from core.core_engine.go.parser import find_sinks as go_find_sinks
from core.core_engine.c.parser import find_sinks as c_find_sinks
try:
    from core.core_engine.typescript.parser import find_sinks as ts_find_sinks
except ImportError:
    ts_find_sinks = None
from Kunlun_M import const
from Kunlun_M.const import VulnerabilityResult
from utils.utils import show_context
from utils.file import FileParseAll, file_list_parse
from utils.log import logger
from utils.status import get_scan_id

from Kunlun_M.settings import RUNNING_PATH
from web.index.models import ScanResultTask, NewEvilFunc, TaintChain
from web.index.models import check_update_or_new_scanresult


class Running:
    def __init__(self, sid):
        self.sid = sid

    def init_list(self, data=None):
        """
        Initialize asid_list file.
        :param data: list or a string
        :return:
        """
        file_path = os.path.join(RUNNING_PATH, '{sid}_list'.format(sid=self.sid))
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
        file_path = os.path.join(RUNNING_PATH, '{sid}_list'.format(sid=self.sid))
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
        file_path = os.path.join(RUNNING_PATH, '{sid}_status'.format(sid=self.sid))
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

        file_path = os.path.abspath(RUNNING_PATH + '/{sid}_data'.format(sid=self.sid))

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
        file_path = os.path.join(RUNNING_PATH, '{sid}_{ext}'.format(sid=self.sid, ext=ext))
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


# ══════════════════════════════════════════════════════════════
#  LEGACY ENGINE — oldscan / scan_single / SingleRule / NewCore
#  These functions are no longer called by the graph-based scan()
#  pipeline. Retained for backward compatibility only. DO NOT use
#  in new code. Will be removed in a future cleanup pass.
# ══════════════════════════════════════════════════════════════

def scan_single(target_directory, single_rule, files=None, language=None, tamper_name=None, is_unconfirm=False,
                newcore_function_list=None):
    raise RuntimeError(
        "scan_single() is DEPRECATED. All scans must use the graph-based scan() engine. "
        "This legacy regex-based engine is no longer callable.")
    try:
        return SingleRule(target_directory, single_rule, files, language, tamper_name, is_unconfirm,
                          newcore_function_list).process()
    except Exception:
        raise


def scan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
         extension_count=0, files=None, tamper_name=None, is_unconfirm=False, no_cache=False, auto_yes=False):
    """Graph-based scan — AST 图扫描引擎入口"""
    r = Rule(language)
    rules = r.rules(special_rules)
    find_vulnerabilities = []

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))

    # 预加载框架 tamper EXTRA_SINKS 并注入为虚拟规则
    # （从 oldscan 移植，适配 graph scan 的 rules dict 格式）
    _framework_method_sinks: set[str] = set()  # short method names for find_sinks Path C
    if language and target_directory:
        try:
            from rules.tamper._loader import detect_frameworks, merge_framework_config, load_base_config
            from utils.api import VirtualRule
            import types as _types
            _languages_for_tamper = language if isinstance(language, list) else [language]
            for _lang in _languages_for_tamper:
                _lang_lower = _lang.lower() if isinstance(_lang, str) else str(_lang).lower()
                _detected = detect_frameworks(_lang_lower, target_directory)
                if _detected:
                    _repair_tmp, _controlled_tmp = load_base_config(_lang_lower)
                    for _fw_mod in _detected:
                        _extra = merge_framework_config(_repair_tmp, _controlled_tmp, _fw_mod)
                        if _extra:
                            for _pattern, _svids in _extra.items():
                                for _svid in _svids:
                                    _vw_name = "VW_{}_{}".format(_svid, len(rules))
                                    _vw_class = type(_vw_name, (VirtualRule,), {
                                        '__init__': lambda self, _p=_pattern, _s=_svid, _l=_lang_lower: VirtualRule.__init__(self, _p, _s, _l)
                                    })
                                    _vw_module = _types.ModuleType(_vw_name)
                                    setattr(_vw_module, _vw_name, _vw_class)
                                    rules[_vw_name] = _vw_module
                                    logger.info('[CVI-{cvi}] [VIRTUAL] EXTRA_SINK: {p} (framework: {fw})'.format(
                                        cvi=_svid, p=_pattern, fw=getattr(_fw_mod, 'FRAMEWORK_NAME', '?')))
                                # Collect method-call short names (->method) for
                                # framework-agnostic short-name matching (Path C).
                                if '->' in _pattern:
                                    import re as _re
                                    _m = _re.search(r'->(\w+)', _pattern)
                                    if _m:
                                        _framework_method_sinks.add(_m.group(1).lower())
        except Exception as e:
            logger.warning('[SCAN] tamper extra_sinks loading failed: {e}'.format(e=e))

    # 按语言分组规则
    languages = language if isinstance(language, list) else [language]
    lang_rules = {}
    for rule_key in sorted(rules.keys()):
        rule_cls = getattr(rules[rule_key], rule_key)
        rule = rule_cls()
        if rule.status is False and len(rules) != 1:
            continue
        lang = rule.language.lower() if rule.language else 'unknown'
        if lang not in lang_rules:
            lang_rules[lang] = []
        lang_rules[lang].append(rule)

    # 尝试加载缓存或构建 AST 图
    graph = None

    # no_cache 扫描：标记同 target 旧 task 的结果为过期（排除 tp）
    if no_cache and a_sid:
        try:
            from web.index.models import ScanResultTask, ScanTask
            task = ScanTask.objects.get(id=a_sid)
            target = task.target_path.rstrip('/')
            old_tasks = ScanTask.objects.filter(target_path__startswith=target).exclude(id=a_sid)
            old_task_ids = list(old_tasks.values_list('id', flat=True))
            if old_task_ids:
                updated = ScanResultTask.objects.filter(
                    scan_task_id__in=old_task_ids
                ).exclude(
                    verification_status__in=['tp', 'stale']
                ).update(verification_status='stale')
                logger.info('[SCAN] Marked %d old results as stale (excluded tp)', updated)
        except Exception as e:
            logger.warning('[SCAN] Failed to mark stale results: %s', e)

    if not no_cache:
        try:
            from core.graph.graph_pipeline import load_cached_graph
            cached_graph, cache_info = load_cached_graph(target_directory)
            if cached_graph is not None and cache_info.get("reason") is None:
                # 有有效缓存
                if not auto_yes:
                    print(
                        f"\n[Cache] 发现已扫描过的图缓存 (scan #{cache_info['scan_id']}, "
                        f"{cache_info['node_count']} nodes, {cache_info['edge_count']} edges, "
                        f"{cache_info['created_at']})"
                    )
                    try:
                        choice = input("       加载缓存? [Y/n] ").strip().lower()
                    except EOFError:
                        # 非交互模式（管道/重定向 stdin），默认加载缓存
                        choice = ''
                    if choice in ('n', 'no'):
                        graph = None
                        logger.info('[SCAN] [GRAPH] User chose to rebuild graph')
                    else:
                        graph = cached_graph
                else:
                    # --yes 模式：静默加载缓存
                    graph = cached_graph
            # 缓存命中且有 scan_id 时，确保图保存到当前 scan 的 workspace
            if graph is not None and a_sid:
                try:
                    from core.graph.workspace import ensure_scan_dir, get_workspace_db
                    from core.graph.graph_io import AstGraphIO
                    from core.graph.sqlite_index import ScanRecord
                    scan_dir = ensure_scan_dir(a_sid)
                    gio = AstGraphIO(scan_dir)
                    meta = gio.save(graph)
                    sr = ScanRecord(get_workspace_db())
                    sr.upsert(
                        scan_id=a_sid,
                        language=language[0] if language else None,
                        target=target_directory,
                        graph_path=meta["file_path"],
                        node_count=graph.vcount(),
                        edge_count=graph.ecount(),
                    )
                    logger.info('[SCAN] [GRAPH] Cached graph saved to workspace/%s', a_sid)
                except Exception as e:
                    logger.warning('[SCAN] [GRAPH] Failed to save cached graph to workspace/%s: %s', a_sid, e)
        except Exception as e:
            logger.warning('[SCAN] [GRAPH] Cache check failed, will rebuild: %s', e)

    if graph is None:
        try:
            from core.pretreatment import ast_object
            from core.graph.graph_pipeline import build_ast_graph
            from Kunlun_M.settings import BASE_DIR
            # db_path 传 None，让 pipeline 根据 scan_id 自动使用 workspace DB
            # 仅在无 scan_id 时 fallback 到主库（保持 analyze 子命令可用）
            db_path = os.path.join(BASE_DIR, 'db', 'kunlun.db') if not a_sid else None
            graph = build_ast_graph(files=files, language=language, target_directory=target_directory, db_path=db_path, scan_id=a_sid)
            logger.info('[SCAN] [GRAPH] Built graph: %d nodes, %d edges', graph.vcount(), graph.ecount())
        except Exception as e:
            logger.warning('[SCAN] [GRAPH] Build failed: %s', e)

    if graph is None or graph.vcount() == 0:
        logger.warning('[SCAN] [GRAPH] Empty or no graph — sink-based rules skipped')

    # ── 非 sink-compatible 规则过滤 ──
    from Kunlun_M.const import mm_framework_dependency as _MM_FW_DEP
    _skip_modes = {'only-regex', 'only-keyword', 'regex-return-regex'}
    _skip_count = 0
    _fw_dep_rules = []
    _file_pattern_rules = []
    for _lang, _rules in lang_rules.items():
        _remaining = []
        for _rule in _rules:
            _mm = getattr(_rule, 'match_mode', '')
            if _mm == _MM_FW_DEP:
                _fw_dep_rules.append(_rule)
                continue
            if _mm == 'file-pattern':
                _file_pattern_rules.append(_rule)
                continue
            if _mm in _skip_modes:
                _skip_count += 1
                logger.info('[CVI-%s] [SKIP] match_mode=%s not supported by graph engine',
                           _rule.svid, _mm)
                continue
            _remaining.append(_rule)
        lang_rules[_lang] = _remaining
    if _skip_count:
        logger.info('[SCAN] Skipped %d non-sink-compatible rules', _skip_count)
    if _fw_dep_rules:
        logger.info('[SCAN] %d framework-dependency rules will be processed separately', len(_fw_dep_rules))
    if _file_pattern_rules:
        logger.info('[SCAN] %d file-pattern rules will be processed separately', len(_file_pattern_rules))

    # ── Sink-based scan (requires valid graph) ──
    if graph is not None and graph.vcount() > 0:
        # ── Taint enrichment ──
        try:
            from core.pretreatment import ast_object
            from core.graph.knowledge_bridge import enrich_taint
            from core.core_engine.trace_cache import TraceCache

            # 语言 → (模块路径, builtin sources 属性名)
            # 对有 _BUILTIN_SOURCE_MEMBERS 的语言，创建轻量 SourceRegistry
            # 对 JS/TS 用 discover_sources（包含框架检测 + AST 遍历）
            _LANG_BUILTIN_SOURCE = {
                'go': ('core.core_engine.go.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'c': ('core.core_engine.c.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'python': ('core.core_engine.python.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'ruby': ('core.core_engine.ruby.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'rust': ('core.core_engine.rust.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'csharp': ('core.core_engine.csharp.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'kotlin': ('core.core_engine.kotlin.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'lua': ('core.core_engine.lua.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'cpp': ('core.core_engine.cpp.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
                'typescript': ('core.core_engine.typescript.source_discovery', '_BUILTIN_SOURCE_MEMBERS'),
            }
            # 注释：JS/TS 需要全局 ast_object，PHP 的 SourceRegistry 接口不同，需单独处理

            def _make_source_registry(lang):
                """为指定语言创建 source_registry（静态种子 source：builtin + 框架检测）。

                通过 discover_sources(project_dir, None) 获取框架检测 + builtin source，
                传入 tree=None 跳过 AST 遍历（间接 source 由 function_summary 在图上发现）。
                """
                # JS/TS：需要全局 ast_object（含跨文件 import/require 分析）
                if lang in ('javascript', 'typescript'):
                    engine = 'javascript' if lang == 'javascript' else 'typescript'
                    from importlib import import_module
                    mod = import_module(f'core.core_engine.{engine}.source_discovery')
                    return mod.discover_sources(ast_object.target_directory, ast_object)
                # PHP：dataclass，builtin_sources 字段已含 superglobals
                if lang == 'php':
                    from core.core_engine.php.source_discovery import (
                        SourceRegistry as _SR,
                        detect_framework,
                    )
                    _php_sr = _SR()
                    # 检测框架并注入框架 source 配置
                    fw = detect_framework(target_directory)
                    if fw:
                        _php_sr.add_framework(fw)
                    # 适配接口：添加 is_source_member 方法
                    _orig_isv = _php_sr.is_source_variable
                    _php_sr.source_members = _php_sr.builtin_sources
                    def _php_ism(expr):
                        return _orig_isv(expr.split('.')[0].split('(')[0]) if expr else False
                    _php_sr.is_source_member = _php_ism
                    return _php_sr
                # 其他语言：通过 discover_sources(project_dir, None) 获取框架 + builtin 种子 source
                # 跳过无效的语言标识（如 'base' 等通用规则语言）
                _VALID_DISCOVER_LANGS = {
                    'python', 'java', 'javascript', 'typescript', 'php',
                    'ruby', 'go', 'rust', 'c', 'cpp', 'csharp', 'kotlin', 'lua',
                }
                if lang not in _VALID_DISCOVER_LANGS:
                    return None
                try:
                    from importlib import import_module
                    mod = import_module(f'core.core_engine.{lang}.source_discovery')
                    sr = mod.discover_sources(target_directory, None)
                    # 接口适配：确保有 is_source_member（Java 没有）
                    if not hasattr(sr, 'is_source_member'):
                        _src_members = sr.source_members if hasattr(sr, 'source_members') else set()
                        _java_prefixes = frozenset({
                            'request', 'req', 'httpRequest', 'httpServletRequest',
                            'servletRequest', 'httpReq',
                        })
                        def _make_ism(members, java_prefixes, lang):
                            def _ism(expr):
                                # Reject expressions containing operators/special chars.
                                # These are not valid source member names (e.g.
                                # "request.META.get() || ''" should not match "request.META").
                                if any(op in expr for op in ('||', '&&', ' and ', ' or ')):
                                    return False
                                for m in members:
                                    if expr == m or expr.startswith(m + '.') or expr.startswith(m + '('):
                                        # Don't let startswith match if expr contains expression chars
                                        # like "request.META.get() || ''"
                                        rest = expr[len(m):] if expr.startswith(m) else ''
                                        if rest and rest[0] == '.' and '(' in rest:
                                            continue  # expr is like "request.META.get(...)" — too broad
                                        return True
                                    # 后缀匹配：request.getParameter → matches getParameter
                                    # example.setOrderByClause → matches setOrderByClause
                                    if '.' in expr and expr.rsplit('.', 1)[-1] == m:
                                        # Java: suffix match alone is too broad.
                                        # url.getParameter should NOT match getParameter
                                        # because 'url' is not a known HTTP request variable.
                                        if lang == 'java':
                                            prefix = expr.rsplit('.', 1)[0]
                                            if prefix not in java_prefixes:
                                                continue
                                        return True
                                return False
                            return _ism
                        sr.is_source_member = _make_ism(_src_members, _java_prefixes, lang)
                    return sr
                except Exception as e:
                    logger.debug('[SCAN] [GRAPH] discover_sources(%s) failed: %s', lang, e)
                    # fallback：仅加载 builtin
                    entry = _LANG_BUILTIN_SOURCE.get(lang)
                    if not entry:
                        return None
                    try:
                        fmod = __import__(entry[0], fromlist=['SourceRegistry', entry[1]])
                        SR = getattr(fmod, 'SourceRegistry', None)
                        BSM = getattr(fmod, entry[1], None)
                        if SR and BSM:
                            sr = SR()
                            for sm in BSM:
                                sr.add_source_member(sm)
                            if lang == "rust":
                                for sm in BSM:
                                    for prefix in ("std::", "std::process::", "std::io::", "std::net::"):
                                        if sm.startswith(prefix):
                                            sr.add_source_member(sm[len(prefix):])
                            return sr
                    except ImportError:
                        pass
                    return None

            # 按语言分别创建 TraceCache 并 enrich
            for lang in lang_rules.keys():
                trace_cache = TraceCache(lang)
                sr = _make_source_registry(lang)
                count = enrich_taint(
                    graph, language=lang,
                    trace_cache=trace_cache,
                    source_registry=sr,
                )
                if count:
                    logger.info('[SCAN] [GRAPH] Enriched %d function taint annotations for %s', count, lang)

            # ── 用户自定义函数摘要（DFG 反向追踪 return → parameter） ──
            # 在 enrich_taint 之后运行：读取 builtin 函数的 taint_type 注解，
            # 写入 func_summary_type / func_summary_pt，并同步到 taint 属性，
            # 供 GraphAnalyzer Rule 4c 消费。
            try:
                from core.graph.function_summary import build_function_summaries
                summary_stats = build_function_summaries(
                    graph, languages=list(lang_rules.keys())
                )
                if summary_stats.get("annotated"):
                    logger.info(
                        '[SCAN] [GRAPH] Function summaries: %d annotated (pt=%d, source=%d, safe=%d, literal=%d, unknown=%d)',
                        summary_stats["annotated"],
                        summary_stats.get("passthrough", 0),
                        summary_stats.get("source", 0),
                        summary_stats.get("safe", 0),
                        summary_stats.get("literal", 0),
                        summary_stats.get("unknown", 0),
                    )
            except Exception as e:
                logger.warning('[SCAN] [GRAPH] Function summary building failed: %s', e)
        except Exception as e:
            logger.warning('[SCAN] [GRAPH] Taint enrichment failed: %s', e)

        # 对每种语言使用 GraphAnalyzer 扫描
        from core.graph.graph_analyzer import GraphAnalyzer, AnalysisResult
        from core.utils import parse_sink_names
        from Kunlun_M.const import VulnerabilityResult
        from utils.igraph_compat import _vattr

        def _get_rule_sink_names(rule) -> list[str]:
            """Extract cleaned sink names from a rule object.

            Handles the fact that DB vul_function is stored as a *string*
            representation of a list (e.g. "['exec', 'query']") rather than
            an actual list.  Falls back to the rule's ``match`` field and runs
            it through ``parse_sink_names`` to strip regex noise.
            """
            raw = getattr(rule, 'vul_function', None)
            if not raw:
                raw = getattr(rule, 'match', None)
            if not raw:
                return []
            # DB stores list as string — parse it back
            if isinstance(raw, str):
                raw_stripped = raw.strip()
                if raw_stripped.startswith('['):
                    try:
                        import ast as _ast
                        parsed = _ast.literal_eval(raw_stripped)
                        if isinstance(parsed, list):
                            raw = parsed
                        else:
                            raw = raw_stripped
                    except Exception:
                        raw = raw_stripped
                else:
                    raw = raw_stripped
            if isinstance(raw, list):
                join_str = '|'.join(str(x) for x in raw if x)
            else:
                join_str = str(raw)
            if not join_str:
                return []
            result: list[str] = []
            for sn in parse_sink_names(join_str):
                if sn.class_:
                    # 前缀标志 (a:, r:) 保持冒号分隔，非前缀用点分隔
                    if sn.class_.endswith(':'):
                        name_str = f"{sn.class_}{sn.method}"
                    else:
                        name_str = f"{sn.class_}.{sn.method}"
                else:
                    name_str = sn.method
                # 清理但保留 a: 和 r: 前缀中的冒号
                if name_str.startswith(('a:', 'r:')):
                    cleaned = re.sub(r'[^a-zA-Z0-9_.:]', '', name_str)
                else:
                    cleaned = re.sub(r'[^a-zA-Z0-9_.]', '', name_str)
                if cleaned:
                    result.append(cleaned)
            return result

        def _get_rule_sink_names_list(rule):
            """Return raw SinkName list from a rule (for LEGACY oldscan path)."""
            raw = getattr(rule, 'vul_function', None)
            if not raw:
                return None
            if isinstance(raw, str) and raw.strip().startswith('['):
                try:
                    import ast as _ast
                    parsed = _ast.literal_eval(raw.strip())
                    if isinstance(parsed, list) and parsed:
                        return parse_sink_names('|'.join(str(x) for x in parsed))
                except Exception:
                    pass
            if isinstance(raw, list) and raw:
                return parse_sink_names('|'.join(str(x) for x in raw))
            return None


        for lang, lang_rule_list in lang_rules.items():
            analyzer = GraphAnalyzer(graph, language=lang, source_registry=_make_source_registry(lang),
                                     framework_method_sinks=_framework_method_sinks)

            # 收集该语言所有规则的 sink 函数名
            all_sink_names = []
            for rule in lang_rule_list:
                try:
                    for name_str in _get_rule_sink_names(rule):
                        all_sink_names.append(name_str)
                except Exception:
                    continue

            if not all_sink_names:
                continue

            all_sink_names = list(set(all_sink_names))
            logger.info('[SCAN] [GRAPH] Looking for %d sink patterns in %s', len(all_sink_names), lang)
            sinks = analyzer.find_sinks(sink_names=all_sink_names)
            logger.info('[SCAN] [GRAPH] Found %d potential sinks in %s', len(sinks), lang)

            for sink in sinks:
                try:
                    _sn = sink.get('name', '')
                    # Skip sinks that are not actual call nodes
                    # (e.g. identifier nodes that leaked into results)
                    _stype = sink.get('type', '')
                    if _stype and _stype not in ('call', 'method_call', 'static_call', 'new'):
                        continue
                    # 对 sink 的每个参数做污点回溯（去重 + 跳过 function/callee 节点）
                    arg_vids = list(dict.fromkeys(sink.get('arg_vids', [])))
                    any_arg_repaired = False
                    # call_user_func / call_user_func_array: RCE 风险仅存在于
                    # 第一个参数（callable）可控的情况。数据参数即使可控也
                    # 不构成 RCE——危险的是攻击者能控制调用哪个函数。
                    _CALLABLE_ONLY_SINK = {
                        "call_user_func", "call_user_func_array",
                        "array_map", "array_filter", "array_walk",
                        "array_reduce", "array_walk_recursive",
                        "usort", "uasort", "uksort",
                    }
                    sink_name_lower = sink.get("name", "").lower()
                    callable_only = sink_name_lower in _CALLABLE_ONLY_SINK
                    # Format-string functions: only the format string argument
                    # is dangerous if user-controlled (format string vulnerability).
                    # Value arguments (%s expansion) are NOT dangerous regardless
                    # of controllability.
                    #   printf(fmt, ...)       → arg 0 is format string
                    #   fprintf(fp, fmt, ...)  → arg 1 is format string
                    #   sprintf(dst, fmt, ...) → arg 1 is format string
                    #   snprintf(dst, sz, fmt, ...) → arg 2 is format string
                    _FMT_SINK_FMT_INDEX = {
                        "printf": 0, "vprintf": 0,
                        "fprintf": 1, "vfprintf": 1,
                        "sprintf": 1, "vsprintf": 1,
                        "snprintf": 2, "vsnprintf": 2,
                    }
                    fmt_only_idx = -1
                    for _fn, _idx in _FMT_SINK_FMT_INDEX.items():
                        if sink_name_lower == _fn or sink_name_lower.endswith("." + _fn):
                            fmt_only_idx = _idx
                            break

                    # Path-only sinks: only the path argument is dangerous for
                    # Path Traversal (CVI-1017). The content/data argument is
                    # user input but does not control WHERE the file is written.
                    #   file_put_contents(path, data)  → arg 0 is path
                    _PATH_SINK_INDEX = {
                        "file_put_contents": 0,
                        # Django/Flask redirect: only first arg is the URL target.
                        # Subsequent args are URL reverse parameters.
                        "redirect": 0,
                        "HttpResponseRedirect": 0,
                        "RedirectResponse": 0,
                        # Java Files.write(path, content): only arg0 (path)
                        # is relevant to Path Traversal. Content (arg1) is
                        # user data but does not control WHERE it's written.
                        "files.write": 0,
                        # Java Files.copy(source, target): target is arg1.
                        # Source is a file path (read) not write destination.
                        "files.copy": 1,
                        # Java Files.move(source, target): target is arg1.
                        "files.move": 1,
                    }
                    path_only_idx = -1
                    for _fn, _idx in _PATH_SINK_INDEX.items():
                        if sink_name_lower == _fn or sink_name_lower.endswith("." + _fn):
                            path_only_idx = _idx
                            break
                    found_controllable = False
                    found_unconfirmed = False
                    result = None
                    unconfirmed_result = None
                    for i, arg_vid in enumerate(arg_vids):
                        # Format-string sinks: only check the format string argument.
                        # Value arguments (printf %s values) are not dangerous.
                        if fmt_only_idx >= 0 and i != fmt_only_idx:
                            continue
                        # Path-only sinks (file_put_contents): only check the
                        # path argument. Content data does not cause Path Traversal.
                        if path_only_idx >= 0 and i != path_only_idx:
                            continue
                        arg_label = _vattr(graph.vs[arg_vid], 'label', '')
                        if arg_label == 'function':
                            continue
                        # call_user_func/call_user_func_array: 只检查 callable 参数（第一个）
                        # 数据参数（第二个及以后）不构成 RCE 风险
                        if callable_only and i > 0:
                            continue
                        # If arg is an operator (e.g. new InputSource(...)),
                        # recursively trace sub-args for controllable data
                        if arg_label == 'operator':
                            def _deep_trace_args(op_vid, depth=0, max_depth=3):
                                """Recursively trace operator sub-args for controllable data."""
                                if depth >= max_depth:
                                    return None, None
                                # Check if this operator is a repair function —
                                # if so, its output is safe, return repaired.
                                _callee = analyzer._resolve_callee_name(op_vid)
                                if _callee and analyzer._is_repair_function(_callee):
                                    from core.graph.graph_analyzer import AnalysisResult as _AR
                                    return _AR(
                                        code=2, reason=f"nested repair '{_callee}'",
                                        chain=[{"step": "repair", "vid": op_vid,
                                                "name": _callee, "code": 2}],
                                        path=[op_vid]), None
                                # Check knowledge_bridge taint_type="safe" annotation.
                                # Catches framework sanitizers (e.g. WordPress esc_attr,
                                # esc_html) that builtin_knowledge marks safe=True
                                # but are not in the hardcoded _REPAIR_FUNCTIONS set.
                                if _vattr(graph.vs[op_vid], "taint_type", "") == "safe":
                                    from core.graph.graph_analyzer import AnalysisResult as _AR
                                    return _AR(
                                        code=2, reason=f"nested safe '{_callee or ''}'",
                                        chain=[{"step": "safe", "vid": op_vid,
                                                "name": _callee or '', "code": 2}],
                                        path=[op_vid]), None
                                # Fix 14: PHP type cast sanitization.
                                # (int), (float), (bool), (array) casts destroy string
                                # content, making XSS/SQLi/injection impossible.
                                if (_vattr(graph.vs[op_vid], "type", "") == "type_cast"
                                        and _vattr(graph.vs[op_vid], "name", "")
                                        in ("int", "integer", "float", "double", "real",
                                            "bool", "boolean", "array", "object")):
                                    _cast_name = _vattr(graph.vs[op_vid], "name", "")
                                    from core.graph.graph_analyzer import AnalysisResult as _AR
                                    return _AR(
                                        code=2,
                                        reason=f"type cast '{_cast_name}'",
                                        chain=[{"step": "safe", "vid": op_vid,
                                                "name": _cast_name, "code": 2}],
                                        path=[op_vid]), None
                                sub_arg_vids = [
                                    e.target for e in graph.es.select(_source=op_vid, label="ast")
                                    if _vattr(e, "role") in ("arg", "left", "right")
                                ]
                                if not sub_arg_vids:
                                    # No AST children — try DFG sources as fallback.
                                    # This handles cases where the normalizer
                                    # connects operator operands via DFG edges
                                    # instead of AST edges (e.g. PHP string concat).
                                    sub_arg_vids = [
                                        e.source for e in graph.es.select(_target=op_vid, label="dfg")
                                        if _vattr(graph.vs[e.source], "label") != "function"
                                    ]
                                checked_any = False
                                u = None
                                for sub_vid in sub_arg_vids:
                                    checked_any = True
                                    sub_label = _vattr(graph.vs[sub_vid], 'label', '')
                                    if sub_label == 'identifier':
                                        # Skip variables already marked safe by sanitizer propagation
                                        if _vattr(graph.vs[sub_vid], "taint_type", "") == "safe":
                                            continue
                                    if sub_label == 'function':
                                        # Check if this function is a sanitizer (taint_type="safe")
                                        _sub_callee = analyzer._resolve_callee_name(sub_vid)
                                        _sub_taint = _vattr(graph.vs[sub_vid], "taint_type", "")
                                        if _sub_taint == "safe":
                                            continue  # sanitized, skip this sub-arg
                                        if _sub_callee and analyzer._is_repair_function(_sub_callee):
                                            continue  # repair function, skip this sub-arg
                                        continue
                                    u = None
                                    if sub_label == 'operator':
                                        r, u = _deep_trace_args(sub_vid, depth + 1, max_depth)
                                        if r is not None:
                                            if r.is_controllable:
                                                return r, u
                                            continue
                                    else:
                                        # Check if this identifier is an assign
                                        # LHS whose RHS is a repair function.
                                        # If so, the variable is sanitized.
                                        _rhs_call = analyzer._find_assign_rhs_call(sub_vid)
                                        if _rhs_call is not None:
                                            _rhs_callee = analyzer._resolve_callee_name(_rhs_call)
                                            if _rhs_callee and analyzer._is_repair_function(_rhs_callee):
                                                from core.graph.graph_analyzer import AnalysisResult as _AR
                                                return _AR(
                                                    code=2, reason=f"assign RHS repair '{_rhs_callee}'",
                                                    chain=[{"step": "repair", "vid": _rhs_call,
                                                            "name": _rhs_callee, "code": 2}],
                                                    path=[_rhs_call]), None
                                        sr = analyzer.parameters_back(sub_vid)
                                        if sr is not None and sr.is_controllable:
                                            return sr, None
                                        if sr is not None and not sr.is_uncontrollable and u is None:
                                            u = sr
                                # If any sub-arg was inconclusive (not safe,
                                # not controllable), the operator is not
                                # definitively safe — return inconclusive
                                # rather than marking it safe.
                                if u is not None:
                                    return u, u
                                if checked_any:
                                    from core.graph.graph_analyzer import AnalysisResult as _AR
                                    return _AR(
                                        code=2, reason="all sub-args safe",
                                        chain=[{"step": "safe", "vid": op_vid,
                                                "name": "", "code": 2}],
                                        path=[op_vid]), None
                                return None, None

                            r, u = _deep_trace_args(arg_vid)
                            if r is not None:
                                if r.is_controllable:
                                    found_controllable = True
                                    result = r
                                    break
                                # Repair/safe result — sanitizer found, this arg is safe
                                any_arg_repaired = True
                                continue
                        r = analyzer.parameters_back(arg_vid)
                        if r is not None:
                            if r.is_controllable:
                                # callable_only sink: 检查 callable 参数是否有 null/空
                                # 默认值。null 不是有效 callable，空数组 [] 也不是。
                                # 有这些默认值意味着调用者可以不传参（安全）。
                                if callable_only and i == 0:
                                    # 从 arg 节点回溯到 parameter 声明节点
                                    # 检查 default_value（arg 可能是 identifier 使用处，
                                    # 不是 parameter 声明处）
                                    _dv = _vattr(graph.vs[arg_vid], 'default_value', '')
                                    if not _dv:
                                        # parameter 通过 dfg 边指向 identifier（source→target）
                                        # 所以从 arg 的 incoming dfg 边找 parameter
                                        for _e in graph.es.select(_target=arg_vid):
                                            _el = _vattr(_e, 'label', '')
                                            if _el == 'dfg':
                                                _sv = graph.vs[_e.source]
                                                if _vattr(_sv, 'label') == 'parameter':
                                                    _dv = _vattr(_sv, 'default_value', '')
                                                    break
                                    if _dv and ('null' in _dv or 'Array([])' in _dv):
                                        # callable 有安全默认值，视为 inconclusive
                                        found_unconfirmed = True
                                        unconfirmed_result = r
                                        continue
                                found_controllable = True
                                result = r
                                break
                            elif not r.is_uncontrollable and not found_unconfirmed:
                                found_unconfirmed = True
                                unconfirmed_result = r
                            # Repair/safe result from parameters_back — set flag
                            # so receiver tracing is skipped (arg is sanitized).
                            if r.code == 2:
                                any_arg_repaired = True
                    if not found_controllable:
                        # unconfirm 模式：记录疑似漏洞
                        if found_unconfirmed and is_unconfirm:
                            result = unconfirmed_result
                            found_controllable = True
                        elif not arg_vids:
                            # 无参数的 sink（如 rand::thread_rng()）— 跳过 taint 回溯，
                            # 依赖 rule.main() 做二次筛选。
                            # 先检查 sink 所在函数是否有调用者（cg 入边）：
                            # 如果 sink 所在函数从未被调用（死代码），则跳过。
                            sink_vid = sink['vid']
                            parent_func_vid = None
                            for oe in analyzer.graph.es.select(
                                _target=sink_vid, label="own"
                            ):
                                if _vattr(analyzer.graph.vs[oe.source], "label") == "function":
                                    parent_func_vid = oe.source
                                    break
                            if parent_func_vid is not None:
                                has_callers = any(
                                    True for _ in analyzer.graph.es.select(
                                        _target=parent_func_vid, label="cg"
                                    )
                                )
                                if not has_callers:
                                    logger.debug(
                                        "presence-of-sink skipped: '%s' in "
                                        "uncalled function vid=%d",
                                        sink.get('name', ''), parent_func_vid,
                                    )
                                    continue
                            # 有调用者（或不在函数中），但无参数 sink 无法沿 DFG 追溯，
                            # 改为 receiver 追溯（与有参但不可控时的逻辑一致）。
                            # 对 callable_only sink 不追踪 receiver。
                            # Path-only sinks also skip: receiver tracing would
                            # find content data flow, not path flow.
                            if callable_only or path_only_idx >= 0:
                                continue
                            recv_result = analyzer.parameters_back(sink['vid'])
                            if recv_result is not None and recv_result.is_controllable:
                                found_controllable = True
                                result = recv_result
                                sink_vid = sink['vid']
                            else:
                                continue
                        else:
                            # receiver 追溯：sink 的 arg 都不可控时，
                            # 检查 sink operator 本身是否通过 receiver 链路可控。
                            # 场景：template.process(rootMap, sw) — 参数不可控，
                            # 但 template 对象来自 new Template(userInput, ...).
                            # 对 callable_only sink（call_user_func），不追踪 receiver——
                            # 数据参数即使通过 receiver 链路可控也不构成 RCE。
                            if callable_only:
                                continue
                            # Path-only sinks (file_put_contents): skip receiver
                            # tracing. The path arg was already checked and found
                            # not controllable. Receiver tracing would re-discover
                            # the content arg flow, which is NOT a path traversal.
                            if path_only_idx >= 0:
                                continue
                            # Sanitizer detected in args: skip receiver tracing.
                            # If any arg was sanitizer-wrapped (repair result),
                            # the sink output is safe even if receiver chain is controllable.
                            if any_arg_repaired:
                                continue
                            recv_result = analyzer.parameters_back(sink['vid'])
                            if recv_result is not None and recv_result.is_controllable:
                                found_controllable = True
                                result = recv_result
                                sink_vid = sink['vid']
                            else:
                                continue

                    sink_name = sink.get('name', '')
                    # JSON Content-Type 的 @ResponseBody 不构成 XSS
                    # （浏览器不解析 application/json 为 HTML）
                    if sink.get('json_safe') and sink_name.startswith('a:ResponseBody'):
                        continue
                    # Multi-rule matching per sink:
                    # Collect all matching rules, then try each rule's main() —
                    # first rule whose main() passes gets to report.
                    matched_rules = []
                    sn_lower = sink_name.lower().replace("::", ".")
                    for pass_name in ("exact", "suffix"):
                        for rule in lang_rule_list:
                            rule_sink_names = _get_rule_sink_names(rule)
                            if not rule_sink_names:
                                continue
                            rsn = [n.lower() for n in rule_sink_names]
                            if pass_name == "exact":
                                # Exact match or qualified-name match
                                if sn_lower in rsn:
                                    matched_rules.append(rule)
                                    continue
                                if "." in sn_lower and any("." in n and sn_lower == n for n in rsn):
                                    matched_rules.append(rule)
                                    continue
                            else:
                                # Suffix/fallback match — only for short-name sinks
                                # (qualified-name sinks already matched in exact pass)
                                if "." in sn_lower:
                                    continue
                                if any(sn_lower.endswith("." + n) or n.endswith("." + sn_lower) for n in rsn):
                                    matched_rules.append(rule)
                                    continue
                        if matched_rules:
                            break  # exact pass found matches, skip suffix pass

                    if not matched_rules:
                        continue

                    # Try each matched rule; first whose main() passes reports
                    # rule.main() 二次筛选 — build structured sink context from graph
                    sink_file = _vattr(graph.vs[sink['vid']], 'file_path', '') or _vattr(graph.vs[sink['vid']], 'path', '')
                    sink_lineno = _vattr(graph.vs[sink['vid']], 'lineno', 0) or 0

                    # Extract structured argument info from graph nodes.
                    # Each arg's node label/type/name tells us whether it's a
                    # string literal, variable, method call, etc. — no need
                    # to regex-parse source code lines.
                    # For identifier args, trace one DFG hop upstream to find
                    # constant assignments (e.g. String h = "Content-Disposition").
                    sink_args = []  # list of {name, type, label, vid, resolved_value}
                    for _av in arg_vids:
                        _avn = _vattr(graph.vs[_av], 'name', '')
                        _avt = _vattr(graph.vs[_av], 'type', '')
                        _avl = _vattr(graph.vs[_av], 'label', '')
                        _resolved = ''
                        if _avl == 'identifier':
                            # Trace DFG upstream (up to 3 hops) to find const
                            # assignment. Covers: direct (const→id) and
                            # indirect via assignment operator (const→op→id).
                            _visited = {_av}
                            _frontier = [_av]
                            for _ in range(3):
                                _next_frontier = []
                                for _fv in _frontier:
                                    for _de in graph.es.select(_target=_fv, label='dfg'):
                                        _sv = graph.vs[_de.source]
                                        _sl = _vattr(_sv, 'label', '')
                                        _svid = _de.source
                                        if _svid in _visited:
                                            continue
                                        _visited.add(_svid)
                                        if _sl == 'const':
                                            _resolved = _vattr(_sv, 'name', '')
                                            break
                                        # Also check ast children of operators
                                        # for embedded const (assignment RHS)
                                        if _sl == 'operator':
                                            for _ae in graph.es.select(_source=_svid, label='ast'):
                                                _cv = graph.vs[_ae.target]
                                                if _vattr(_cv, 'label', '') == 'const':
                                                    _resolved = _vattr(_cv, 'name', '')
                                                    break
                                            if _resolved:
                                                break
                                        _next_frontier.append(_svid)
                                    if _resolved:
                                        break
                                if _resolved:
                                    break
                                _frontier = _next_frontier
                        # Check if arg's value comes from a function return
                        # (DFG in-edge from a call operator). This helps rules
                        # distinguish path arguments from content/BytesIO args.
                        # Walk DFG in-edges AND own-edge chain to catch indirect
                        # assignments like `x = func(); sink(x)`.
                        _is_func_return = False
                        _return_callee = ''
                        _visited = set()
                        _frontier = [_av]
                        for _hop in range(5):  # BFS depth limit
                            _next = []
                            for _fv in _frontier:
                                if _fv in _visited:
                                    continue
                                _visited.add(_fv)
                                for _de in graph.es.select(_target=_fv, label='dfg'):
                                    _sv = graph.vs[_de.source]
                                    _sl = _vattr(_sv, 'label', '')
                                    _st = _vattr(_sv, 'type', '')
                                    if _sl == 'operator' and _st in ('call', 'method_call', 'static_call', 'new'):
                                        _is_func_return = True
                                        _return_callee = _vattr(_sv, 'name', '')
                                        if _return_callee:
                                            _return_callee = _return_callee.rsplit('::', 1)[-1].rsplit('.', 1)[-1]
                                        break
                                    # Follow variable chain (own edges)
                                    if _sl == 'identifier':
                                        _next.append(_de.source)
                                if _is_func_return:
                                    break
                                # Also follow own-edges for the original arg
                                for _oe in graph.es.select(_target=_fv, label='own'):
                                    _next.append(_oe.source)
                            if _is_func_return:
                                break
                            _frontier = list(set(_next))
                        sink_args.append({
                            'name': _avn, 'type': _avt, 'label': _avl,
                            'vid': _av, 'resolved_value': _resolved,
                            'is_func_return': _is_func_return,
                            'return_callee': _return_callee,
                        })

                    main_input = sink_name  # default: sink function name
                    # Pre-read source line for main() input (kept as fallback)
                    if sink_file:
                        try:
                            with open(sink_file, 'r', encoding='utf-8', errors='replace') as mf:
                                source_lines = mf.readlines()
                            idx = int(sink_lineno) - 1
                            if 0 <= idx < len(source_lines):
                                main_input = source_lines[idx].strip()
                            elif sink_lineno == 0 and sink_name:
                                # lineno=0 (e.g. class_name identifier): fallback
                                # to scanning the file for a line containing sink_name
                                # Prefer operator patterns (new X, X.method) over declarations
                                fallback_candidates = []
                                for line in source_lines:
                                    stripped = line.strip()
                                    if (not stripped or
                                            stripped.startswith('import ') or
                                            stripped.startswith('package ') or
                                            stripped.startswith('//') or stripped.startswith('*')):
                                        continue
                                    if sink_name in stripped:
                                        fallback_candidates.append(stripped)
                                # If multiple candidates, prefer lines with "new" or "."
                                if len(fallback_candidates) > 1:
                                    operator_lines = [l for l in fallback_candidates
                                                      if 'new ' + sink_name in l or
                                                      sink_name + '.' in l]
                                    if operator_lines:
                                        main_input = operator_lines[0]
                                    else:
                                        main_input = fallback_candidates[0]
                                elif fallback_candidates:
                                    main_input = fallback_candidates[0]
                        except Exception:
                            pass

                    matched_rule = None
                    for candidate_rule in matched_rules:
                        if hasattr(candidate_rule, 'main') and callable(candidate_rule.main):
                            try:
                                # All rules use unified signature:
                                # main(self, regex_string, sink_args=None)
                                # sink_args is a list of {name, type, label, vid, resolved_value}
                                # dicts from graph arg nodes, or empty list.
                                main_result = candidate_rule.main(main_input, sink_args)
                                if main_result is False:
                                    logger.debug('[CVI-{cvi}] [GRAPH] main() returned False, skip rule for sink {sink}'.format(
                                        cvi=candidate_rule.svid, sink=sink_name))
                                    continue
                            except Exception:
                                pass  # main() exception doesn't block
                        matched_rule = candidate_rule
                        break

                    if matched_rule is None:
                        # All candidate rules' main() returned False
                        continue

                    # 文件路径过滤：vendor/test/third-party 目录
                    vuln_file_path = _vattr(graph.vs[sink['vid']], 'file_path', '') or _vattr(graph.vs[sink['vid']], 'path', '')
                    if vuln_file_path:
                        vuln_file_norm = os.path.normpath(vuln_file_path)
                        # vendor 目录
                        if '/vendor/' in vuln_file_norm or vuln_file_norm.endswith(os.path.join('vendor', '')):
                            continue
                        # Framework cache directories (generated/compiled code)
                        if any(cache_path in vuln_file_norm
                               for cache_path in ['/Runtime/Temp/', '/Runtime/Cache/',
                                                  '/storage/framework/views/',
                                                  '/storage/framework/cache/',
                                                  '/storage/logs/']):
                            continue
                        # .mvn/wrapper (Maven wrapper, third-party code)
                        if '.mvn' in vuln_file_norm:
                            continue
                        # jar_decompiled (decompiled JAR files, third-party)
                        if 'jar_decompiled' in vuln_file_norm:
                            continue
                        # test 目录
                        for test_path in ['/test/', '/tests/', '/unitTests/']:
                            if test_path in vuln_file_norm:
                                continue
                        # test 文件名: test_*.py, *_test.py, tests.py, *Test.java, *Tests.java, *.spec.js, *.test.js
                        vuln_fname = os.path.basename(vuln_file_norm).lower()
                        if (vuln_fname.startswith('test_') or
                            vuln_fname.startswith('test.') or
                            vuln_fname.endswith('_test.py') or
                            vuln_fname.endswith('_test.go') or
                            vuln_fname == 'tests.py' or
                            vuln_fname == 'tests.go' or
                            vuln_fname.endswith('test.java') or
                            vuln_fname.endswith('tests.java') or
                            vuln_fname.endswith('.spec.js') or
                            vuln_fname.endswith('.spec.ts') or
                            vuln_fname.endswith('.test.js') or
                            vuln_fname.endswith('.test.ts')):
                            continue

                    # 构建污点传播链
                    chain = []
                    for vid in result.path:
                        v = graph.vs[vid]
                        node_label = _vattr(v, 'label', '')
                        node_name = _vattr(v, 'name', '')
                        node_file = _vattr(v, 'file_path', '') or _vattr(v, 'path', '')
                        node_lineno = int(_vattr(v, 'lineno', 0) or 0)
                        chain.append((node_label, node_name, node_file, node_lineno, vid))

                    # 构建 VulnerabilityResult
                    sink_vid = sink['vid']
                    file_path = _vattr(graph.vs[sink_vid], 'file_path', '') or _vattr(graph.vs[sink_vid], 'path', '')
                    lineno = int(_vattr(graph.vs[sink_vid], 'lineno', 0) or 0)

                    vuln = VulnerabilityResult.from_match(
                        (file_path, lineno, sink_name),
                        svid=matched_rule.svid,
                        language=_vattr(graph.vs[sink_vid], 'language', '') or matched_rule.language,
                        rule_name=matched_rule.vulnerability,
                        author=matched_rule.author
                    )
                    vuln.analysis = result.reason
                    vuln.chain = chain
                    find_vulnerabilities.append(vuln)
                    logger.debug('[CVI-{cvi}] [GRAPH] Found: {sink}'.format(
                        cvi=matched_rule.svid, sink=sink_name))

                except Exception as e:
                    logger.debug('[SCAN] [GRAPH] Sink analysis error: %s', e)
                    continue

            # Release analyzer indexes (~148MB) before next language iteration
            del analyzer

    # ── Framework-dependency rules (independent of graph) ──
    if _fw_dep_rules:
        from utils.pom_parser import check_framework_dependency, search_code_patterns
        try:
            for rule in _fw_dep_rules:
                if rule.status is False:
                    continue
                fw_deps = getattr(rule, 'framework_deps', [])
                config_patterns = getattr(rule, 'config_patterns', [])
                exclude_patterns = getattr(rule, 'exclude_patterns', [])
                for dep_config in fw_deps:
                    try:
                        matched_deps = check_framework_dependency(target_directory, dep_config)
                        for matched in matched_deps:
                            pom_path = matched['pom']
                            version = matched['version']
                            cve = matched.get('cve', '')
                            desc = matched.get('description', '')
                            if config_patterns:
                                config_files = search_code_patterns(target_directory, config_patterns)
                                if not config_files:
                                    continue
                            if exclude_patterns:
                                exclude_files = search_code_patterns(target_directory, exclude_patterns)
                                if exclude_files:
                                    continue
                            match_text = f"{dep_config['group_id']}:{dep_config['artifact_id']}:{version}"
                            if cve:
                                match_text += f" ({cve})"
                            vuln = VulnerabilityResult.from_match(
                                (pom_path, '0', match_text),
                                svid=rule.svid,
                                language=rule.language,
                                rule_name=rule.vulnerability,
                                author=rule.author
                            )
                            vuln.analysis = f'Framework dependency: {match_text}'
                            vuln.chain = [('Dependency', match_text, pom_path, 0, None)]
                            find_vulnerabilities.append(vuln)
                            logger.info('[CVI-%s] [FRAMEWORK] Found: %s', rule.svid, match_text)
                    except Exception as e:
                        logger.debug('[CVI-%s] [FRAMEWORK] Error: %s', rule.svid, e)
        except Exception as e:
            logger.warning('[SCAN] [FRAMEWORK] Framework-dependency scan failed: %s', e)

    # ── File-pattern rules (independent of graph — file name + content match) ──
    if _file_pattern_rules:
        _fp_scan_count = 0
        for root_dir, dirs, files in os.walk(target_directory):
            dirs[:] = [d for d in dirs if d.lower() not in ('vendor', 'node_modules', '.git', '__pycache__', 'build', 'target', '.idea')]
            for fn in files:
                fp_path = os.path.join(root_dir, fn)
                try:
                    with open(fp_path, 'r', encoding='utf-8', errors='replace') as fp_file:
                        content = fp_file.read()
                except Exception:
                    continue
                for rule in _file_pattern_rules:
                    if rule.status is False:
                        continue
                    # File name matching (rule.file_pattern regex against filename)
                    file_pattern = getattr(rule, 'file_pattern', None)
                    if file_pattern:
                        try:
                            if not re.search(file_pattern, fn):
                                continue
                        except Exception:
                            continue
                    # Content matching — 同文件同模式去重
                    pattern = getattr(rule, 'match', None)
                    if not pattern:
                        continue
                    try:
                        compiled = re.compile(pattern)
                    except Exception:
                        continue
                    _fp_seen_in_file: set[str] = set()  # (rule_svid, file, matched_text) 去重
                    for m in compiled.finditer(content):
                        lineno = content[:m.start()].count('\n') + 1
                        matched_text = m.group(0)
                        # main() 二次筛选
                        main_input = matched_text
                        try:
                            source_lines = content.split('\n')
                            if 0 < lineno <= len(source_lines):
                                main_input = source_lines[lineno - 1].strip()
                        except Exception:
                            pass
                        if hasattr(rule, 'main') and callable(rule.main):
                            try:
                                mr = rule.main(main_input)
                                if mr is False:
                                    continue
                            except Exception:
                                pass
                        # vendor/test 路径过滤
                        norm_path = os.path.normpath(fp_path)
                        if '/vendor/' in norm_path or '/test/' in norm_path or '/tests/' in norm_path:
                            continue
                        # 同文件同 matched_text 去重（如 ${criterion.condition} 在一个 Mapper 中出现多次）
                        _dedup_key = matched_text
                        if _dedup_key in _fp_seen_in_file:
                            continue
                        _fp_seen_in_file.add(_dedup_key)
                        vuln = VulnerabilityResult.from_match(
                            (fp_path, lineno, matched_text),
                            svid=rule.svid,
                            language=rule.language,
                            rule_name=rule.vulnerability,
                            author=getattr(rule, 'author', 'KunLun-M')
                        )
                        vuln.analysis = f'File pattern: {matched_text}'
                        vuln.chain = [('Pattern', matched_text, fp_path, lineno, None)]
                        find_vulnerabilities.append(vuln)
                        _fp_scan_count += 1
                        logger.info('[CVI-%s] [FILE-PATTERN] Found: %s:%d - %s', rule.svid, fp_path, lineno, matched_text)
        if _fp_scan_count:
            logger.info('[SCAN] [FILE-PATTERN] Found %d file pattern matches', _fp_scan_count)

    # 写入数据库（复用旧逻辑）
    data = []
    data2 = []
    trigger_rules = []
    for idx, x in enumerate(find_vulnerabilities):
        db_params = x.to_db_params(target_directory=target_directory)
        trigger = db_params['vulfile_path']
        code_content = db_params['source_code']
        commit = u'@{author}'.format(author=x.commit_author)
        row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit,
               code_content, x.analysis]
        row2 = [idx + 1, x.chain]

        sr = check_update_or_new_scanresult(scan_task_id=a_sid, is_active=True, **db_params)
        if sr:
            step = 0
            for chain in x.chain:
                if type(chain) == tuple:
                    node_source = show_context(chain[2], chain[3], is_back=True)
                    node_vid = chain[4] if len(chain) >= 5 else None
                    tc = TaintChain(
                        scan_task=int(a_sid),
                        vul_result=sr.id,
                        chain_index=0,
                        step_order=step,
                        node_label=chain[0],
                        node_name=chain[1],
                        file_path=chain[2],
                        lineno=int(float(chain[3])) if chain[3] else 0,
                        vid=node_vid,
                        source_code=node_source,
                    )
                    tc.save()
                    step += 1

        data.append(row)
        data2.append(row2)

    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
                'language': ",".join(languages),
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(rules),
                'trigger_rules': len(trigger_rules),
                'target_directory': target_directory
            }
        })
    return True


def oldscan(target_directory, a_sid=None, s_sid=None, special_rules=None, language=None, framework=None, file_count=0,
            extension_count=0, files=None, tamper_name=None, is_unconfirm=False):
    raise RuntimeError(
        "oldscan() is DEPRECATED. All scans must use the graph-based scan() engine. "
        "This legacy regex-based engine is no longer callable.")
    r = Rule(language)
    vulnerabilities = r.vulnerabilities
    rules = r.rules(special_rules)
    find_vulnerabilities = []
    newcore_function_list = {}

    # 预加载框架 extra_sinks 并生成虚拟规则注入 rules 队列
    virtual_rule_count = 0
    if language and target_directory:
        try:
            from rules.tamper._loader import detect_frameworks, merge_framework_config, load_base_config
            from utils.api import VirtualRule
            import types as _types
            # language may be a list (e.g. ['php', 'javascript'])
            languages = language if isinstance(language, list) else [language]
            for lang in languages:
                lang_lower = lang.lower() if isinstance(lang, str) else str(lang).lower()
                detected = detect_frameworks(lang_lower, target_directory)
                if detected:
                    repair_tmp, controlled_tmp = load_base_config(lang_lower)
                    for fw_mod in detected:
                        extra = merge_framework_config(repair_tmp, controlled_tmp, fw_mod)
                        if extra:
                            for pattern, svids in extra.items():
                                for svid in svids:
                                    # 从已有规则获取漏洞描述和等级
                                    vuln_desc = ""
                                    vuln_level = 0
                                    for rule_key in rules:
                                        try:
                                            r = getattr(rules[rule_key], rule_key)
                                            rc = r()
                                            if rc.svid == svid:
                                                vuln_desc = rc.vulnerability
                                                vuln_level = rc.level
                                                break
                                        except:
                                            pass

                                    # 生成虚拟规则类（包装为假模块以兼容 getattr 结构）
                                    vw_name = "VW_{}_{}".format(svid, virtual_rule_count)
                                    vw_class = type(vw_name, (VirtualRule,), {
                                        '__init__': lambda self, _p=pattern, _s=svid, _l=lang_lower, _d=vuln_desc, _vl=vuln_level: VirtualRule.__init__(self, _p, _s, _l, _d, level=_vl)
                                    })
                                    vw_module = _types.ModuleType(vw_name)
                                    setattr(vw_module, vw_name, vw_class)
                                    rules[vw_name] = vw_module
                                    virtual_rule_count += 1
                                    logger.info('[CVI-{cvi}] [VIRTUAL] EXTRA_SINK: {p} (framework: {fw})'.format(
                                        cvi=svid, p=pattern, fw=getattr(fw_mod, 'FRAMEWORK_NAME', '?')))
        except Exception as e:
            logger.debug('[SCAN] extra_sinks virtual-rule generation error: {e}'.format(e=e))

    def store(result):
        if result is not None and isinstance(result, list) is True:
            for res in result:
                find_vulnerabilities.append(res)
        else:
            logger.debug('[SCAN] [STORE] Not found vulnerabilities on this rule!')

    async def start_scan(target_directory, rule, files, language, tamper_name):
        result = scan_single(target_directory, rule, files, language, tamper_name, is_unconfirm, newcore_function_list)
        store(result)

    if len(rules) == 0:
        logger.critical('no rules!')
        return False
    logger.info('[PUSH] {rc} Rules'.format(rc=len(rules)))
    if virtual_rule_count > 0:
        logger.info('[PUSH] {n} Virtual Rules from EXTRA_SINKS'.format(n=virtual_rule_count))
    push_rules = []
    scan_list = []

    for idx, single_rule in enumerate(sorted(rules.keys())):

        # init rule class
        r = getattr(rules[single_rule], single_rule)
        rule = r()

        if rule.status is False and len(rules) != 1:
            logger.info('[CVI_{cvi}] [STATUS] OFF, CONTINUE...'.format(cvi=rule.svid))
            continue
        # SR(Single Rule)
        logger.debug("""[PUSH] [CVI_{cvi}] {idx}.{vulnerability}({language})""".format(
            cvi=rule.svid,
            idx=idx,
            vulnerability=rule.vulnerability,
            language=rule.language
        ))
        # result = scan_single(target_directory, rule, files, language, tamper_name)
        scan_list.append(start_scan(target_directory, rule, files, language, tamper_name))
        # store(result)

    # Python 3.11+ no longer recommends manual global event-loop management.
    # Use asyncio.run for compatibility with modern Python (including 3.13+).
    async def _run_scan_list(tasks):
        await asyncio.gather(*tasks)

    asyncio.run(_run_scan_list(scan_list))

    # print
    data = []
    data2 = []
    trigger_rules = []
    for idx, x in enumerate(find_vulnerabilities):

        db_params = x.to_db_params(target_directory=target_directory)
        trigger = db_params['vulfile_path']
        code_content = db_params['source_code']
        commit = u'@{author}'.format(author=x.commit_author)
        row = [idx + 1, x.id, x.rule_name, x.language, trigger, commit,
               code_content, x.analysis]
        row2 = [idx + 1, x.chain]

        # save to database
        sr = check_update_or_new_scanresult(scan_task_id=a_sid, is_active=True, **db_params)

        if sr:
            step = 0
            for chain in x.chain:
                if type(chain) == tuple:
                    node_source = show_context(chain[2], chain[3], is_back=True)
                    tc = TaintChain(
                        scan_task=int(a_sid),
                        vul_result=sr.id,
                        chain_index=0,
                        step_order=step,
                        node_label=chain[0],
                        node_name=chain[1],
                        file_path=chain[2],
                        lineno=int(float(chain[3])) if chain[3] else 0,
                        source_code=node_source,
                    )
                    tc.save()
                    step += 1

        data.append(row)
        data2.append(row2)

    for new_function_name in newcore_function_list:
        # add new evil func in database
        for svid in newcore_function_list[new_function_name]["svid"]:
            if new_function_name and newcore_function_list[new_function_name]["origin_func_name"]:

                nf = NewEvilFunc(svid=svid, scan_task_id=get_scan_id(), func_name=new_function_name,
                                 origin_func_name=newcore_function_list[new_function_name]["origin_func_name"])
                nf.save()

    # completed running data
    if s_sid is not None:
        Running(s_sid).data({
            'code': 1001,
            'msg': 'scan finished',
            'result': {
                'vulnerabilities': [x.__dict__ for x in find_vulnerabilities],
                'language': ",".join(language),
                'framework': framework,
                'extension': extension_count,
                'file': file_count,
                'push_rules': len(rules),
                'trigger_rules': len(trigger_rules),
                'target_directory': target_directory
            }
        })
    return True


# Legacy alias — no longer imported anywhere
old_scan = oldscan


class SingleRule(object):
    """DEPRECATED: Legacy single-rule regex engine. Use graph-based scan() instead."""
    def __init__(self, target_directory, single_rule, files, language=None, tamper_name=None, is_unconfirm=False,
                 newcore_function_list=None):
        raise RuntimeError(
            "SingleRule is DEPRECATED. All scans must use the graph-based scan() engine.")
        self.target_directory = target_directory
        self.sr = single_rule
        self.files = files
        self.languages = language
        self.lan = self.sr.language.lower()
        self.tamper_name = tamper_name
        self.is_unconfirm = is_unconfirm
        # Single Rule Vulnerabilities
        """
        [
            vr
        ]
        """
        self.rule_vulnerabilities = []

        # new core function list
        self.newcore_function_list = newcore_function_list or {}

        logger.info("[!] Start scan [CVI-{sr_id}]".format(sr_id=self.sr.svid))

    def origin_results(self):
        logger.debug('[ENGINE] [ORIGIN] match-mode {m}'.format(m=self.sr.match_mode))

        # grep
        if self.sr.match_mode == const.mm_regex_only_match:
            # 当所有match都满足时成立，当单一unmatch满足时，不成立
            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            result = []
            new_result = []
            old_result = 0

            try:
                if matchs:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)

                    for match in matchs:

                        new_result = f.multi_grep(match)

                        if old_result == 0:
                            old_result = new_result
                            result = new_result
                            continue

                        old_result = result
                        result = []

                        for old_vul in old_result:
                            for new_vul in new_result:
                                if new_vul[0] == old_vul[0]:
                                    result.append(old_vul)

                    for unmatch in unmatchs:
                        uresults = f.multi_grep(unmatch)

                        for uresult in uresults:
                            for vul in result:
                                if vul[0] == uresult[0]:
                                    result.remove(vul)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.mm_regex_param_controllable:
            # 自定义匹配，调用脚本中的匹配函数匹配参数
            match = self.sr.match

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    result = f.grep(match)
                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode in (const.mm_function_param_controllable,
                                     const.mm_java_function_param_controllable):
            # 函数匹配，直接匹配敏感函数，然后处理敏感函数的参数即可
            # param controllable
            
            match = None
            
            if hasattr(self.sr, 'match') and self.sr.match:
                if self.sr.match_mode == const.mm_java_function_param_controllable:
                    # Java 专用模式：match 字段直接作为 grep 正则，不套 fpc 模板
                    match = self.sr.match
                elif (hasattr(self.sr, 'vul_function') and
                      isinstance(self.sr.vul_function, list) and
                      len(self.sr.vul_function) > 0):
                    # 有 vul_function → match 作为完整正则
                    match = self.sr.match
                else:
                    # 传统 PHP/JS 模式：match 是函数名，用 fpc 模板
                    if '|' in self.sr.match:
                        match = const.fpc_multi.replace('[f]', self.sr.match)
                        if self.sr.keyword == 'is_echo_statement':
                            match = const.fpc_echo_statement_multi.replace('[f]', self.sr.match)
                    else:
                        match = const.fpc_single.replace('[f]', self.sr.match)
                        if self.sr.keyword == 'is_echo_statement':
                            match = const.fpc_echo_statement_single.replace('[f]', self.sr.match)

                    if self.sr.language.lower() == "javascript":
                        match = const.fpc_loose.replace('[f]', self.sr.match)

            try:
                if match:
                    f = FileParseAll(self.files, self.target_directory, language=self.lan)
                    
                    # match 可能是字符串或列表
                    if isinstance(match, list):
                        # 多条正则，分别 grep 合并去重
                        all_results = []
                        seen = set()
                        for m in match:
                            r = f.grep(m)
                            if r:
                                for item in r:
                                    if item not in seen:
                                        seen.add(item)
                                        all_results.append(item)
                        result = all_results if all_results else None
                    else:
                        result = f.grep(match)

                else:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

            # AST-based sink finding for indirect call detection
            try:
                if hasattr(self.sr, 'match') and self.sr.match:
                    from core.utils import parse_sink_names, SinkName as _SinkName
                    # 优先使用 vul_function（干净函数名列表）构建 sink_names
                    # C/Go 等语言的 match 是正则表达式，parse_sink_names 无法正确解析
                    if _get_rule_sink_names_list(self.sr):
                        sink_names = _get_rule_sink_names_list(self.sr)
                    else:
                        sink_names = parse_sink_names(self.sr.match)
                    if sink_names:
                        # self.files 是 dict 格式 {('.php', {'count': N, 'list': [paths]})}
                        # 需要用 file_list_parse 提取实际文件路径列表
                        scan_file_list = file_list_parse(self.files, language=self.lan)
                        if scan_file_list:
                            # 按语言选择对应的 find_sinks
                            _find_sinks_fn = {
                                'php': php_find_sinks,
                                'python': python_find_sinks,
                                'java': java_find_sinks,
                                'javascript': js_find_sinks,
                                'go': go_find_sinks,
                                'c': c_find_sinks,
                                'typescript': ts_find_sinks,
                            }.get(self.lan)
                            if _find_sinks_fn:
                                indirect_sinks = _find_sinks_fn(sink_names, scan_file_list)
                                if indirect_sinks:
                                    for sink_info in indirect_sinks:
                                        if sink_info['is_indirect']:
                                            file_path = sink_info['file_path']
                                            lineno = str(sink_info['lineno'])
                                            callee = sink_info['callee_name']
                                            matched_text = '{callee}()'.format(callee=callee)
                                            # 构造 indirect_map: 变量名 -> 实际 sink 函数名
                                            matched_sink = sink_info.get('matched_sink')
                                            indirect_map = {}
                                            if matched_sink:
                                                from core.utils import SinkName
                                                sink_name = '{cls}.{method}'.format(
                                                    cls=matched_sink.class_, method=matched_sink.method
                                                ) if matched_sink.class_ else matched_sink.method
                                                indirect_map = {callee: sink_name}

                                            indirect_result = {
                                                'file_path': file_path,
                                                'lineno': lineno,
                                                'matched_text': matched_text,
                                                'node': sink_info['node'],
                                                'is_indirect': True,
                                                'sink_info': sink_info,
                                                'indirect_map': indirect_map,
                                            }
                                            if result is None:
                                                result = []
                                            if isinstance(result, list):
                                                result.append(indirect_result)
            except Exception as e:
                logger.debug('find_sinks exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())

        elif self.sr.match_mode == const.mm_regex_return_regex:
            # 回馈式正则匹配，将匹配到的内容返回，然后合入正则表达式

            matchs = self.sr.match
            unmatchs = self.sr.unmatch
            matchs_name = self.sr.match_name
            black_list = self.sr.black_list

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.multi_grep_name(matchs, unmatchs, matchs_name, black_list)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.sp_crx_keyword_match:
            # 针对crx研究的keyword匹配，先以sp crx作为入口，逐渐思考普适性

            keyword = self.sr.keyword
            match = self.sr.match
            unmatch = self.sr.unmatch

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.special_crx_keyword_match(keyword, match, unmatch)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.file_path_regex_match:
            # 针对敏感文件名的匹配检查

            match = self.sr.match

            result = []

            try:
                f = FileParseAll(self.files, self.target_directory, language=self.lan)

                result = f.find_keyword_file_or_path(match)
                if not result:
                    result = None
            except Exception as e:
                logger.debug('match exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())
                return None

        elif self.sr.match_mode == const.mm_framework_dependency:
            # 框架依赖版本检测: 解析 pom.xml/build.gradle, 版本范围匹配 + 配置特征二次确认
            from utils.pom_parser import check_framework_dependency, search_code_patterns

            result = []

            try:
                framework_deps = getattr(self.sr, 'framework_deps', [])
                config_patterns = getattr(self.sr, 'config_patterns', [])
                exclude_patterns = getattr(self.sr, 'exclude_patterns', [])

                for dep_config in framework_deps:
                    matched_deps = check_framework_dependency(self.target_directory, dep_config)

                    for matched in matched_deps:
                        pom_path = matched['pom']
                        version = matched['version']
                        cve = matched.get('cve', '')
                        desc = matched.get('description', '')

                        # 二次确认: config_patterns
                        if config_patterns:
                            config_files = search_code_patterns(self.target_directory, config_patterns)
                            if not config_files:
                                logger.debug(f'[FRAMEWORK] config patterns not found, skip {cve}')
                                continue

                        # 排除检查: exclude_patterns
                        if exclude_patterns:
                            exclude_files = search_code_patterns(self.target_directory, exclude_patterns)
                            if exclude_files:
                                logger.debug(f'[FRAMEWORK] exclude patterns found, skip {cve}')
                                continue

                        # 格式化为统一的 result tuple: (file_path, line_number, match_text)
                        match_text = f"{dep_config['group_id']}:{dep_config['artifact_id']}:{version}"
                        if cve:
                            match_text += f" ({cve})"
                        result.append((pom_path, "0", match_text))

                if not result:
                    result = None
            except Exception as e:
                logger.debug(f'framework-dependency match exception ({e})')
                logger.debug(traceback.format_exc())
                return None

        else:
            logger.warning('Exception match mode: {m}'.format(m=self.sr.match_mode))
            result = None

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
        else:
            pass

        # framework-dependency 模式: 直接生成结果，不需要 AST 分析
        if self.sr.match_mode == const.mm_framework_dependency:
            for index, origin_vulnerability in enumerate(origin_results):
                vulnerability = VulnerabilityResult.from_match(origin_vulnerability, svid=self.sr.svid,
                                                                language=self.sr.language,
                                                                rule_name=self.sr.vulnerability,
                                                                author=self.sr.author)
                if vulnerability:
                    cve_info = origin_vulnerability[2] if len(origin_vulnerability) > 2 else ''
                    vulnerability.analysis = f"Framework dependency vulnerability: {cve_info}"
                    vulnerability.chain = [("Dependency", cve_info, origin_vulnerability[0], 0)]
                    self.rule_vulnerabilities.append(vulnerability)
            logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                            count=len(self.rule_vulnerabilities)))
            return self.rule_vulnerabilities

        origin_vulnerabilities = origin_results

        # 分离间接调用结果和直接调用结果
        direct_results = []
        indirect_results = []
        if origin_vulnerabilities:
            for ov in origin_vulnerabilities:
                if isinstance(ov, dict) and ov.get('is_indirect'):
                    indirect_results.append(ov)
                else:
                    direct_results.append(ov)

        # 将间接调用结果转换为 tuple 格式，追加到直接调用结果中
        # 统一走 Core.scan() 的 CAST 验证流程，避免误报
        indirect_indices = []
        for ir in indirect_results:
            try:
                indirect_indices.append(len(direct_results))
                indirect_tuple = (
                    ir['file_path'],
                    ir['lineno'],
                    ir['matched_text'],
                    ir.get('indirect_map', {}),
                )
                direct_results.append(indirect_tuple)
                logger.debug('[CVI-{cvi}] [INDIRECT] Queued for CAST check: {call}'.format(
                    cvi=self.sr.svid, call=ir['matched_text']))
            except Exception as e:
                logger.debug('indirect call exception ({e})'.format(e=e))
                logger.debug(traceback.format_exc())

        # 直接调用结果 + 间接调用结果统一走 CAST 验证
        origin_vulnerabilities = direct_results
        for index, origin_vulnerability in enumerate(origin_vulnerabilities):
            try:
                logger.debug(
                    '[CVI-{cvi}] [ORIGIN] {line}'.format(cvi=self.sr.svid, line=": ".join(list(origin_vulnerability))))
            except Exception:
                pass
            if origin_vulnerability == ():
                logger.debug(' > continue...')
                continue
            vulnerability = VulnerabilityResult.from_match(origin_vulnerability, svid=self.sr.svid,
                                                            language=self.sr.language,
                                                            rule_name=self.sr.vulnerability,
                                                            author=self.sr.author)
            if vulnerability is None:
                logger.debug('Not vulnerability, continue...')
                continue
            is_test = False
            try:
                datas = Core(self.target_directory, vulnerability, self.sr, 'project name',
                             ['whitelist1', 'whitelist2'], test=is_test, index=index,
                             files=self.files, languages=self.languages, tamper_name=self.tamper_name,
                             is_unconfirm=self.is_unconfirm).scan()

                data = ""

                if len(datas) == 3:
                    is_vulnerability, reason, data = datas

                    if "New Core" not in reason:
                        code = "Code: {}".format(origin_vulnerability[2].strip(" "))
                        file_path = os.path.normpath(origin_vulnerability[0])
                        data.insert(1, ("NewScan", code, origin_vulnerability[0], origin_vulnerability[1]))

                elif len(datas) == 2:
                    is_vulnerability, reason = datas
                else:
                    is_vulnerability, reason = False, "Unpack error"

                if is_vulnerability:
                    logger.debug('[CVI-{cvi}] [RET] Found {code}'.format(cvi=self.sr.svid, code=reason))
                    vulnerability.analysis = reason
                    vulnerability.chain = data
                    if index in indirect_indices:
                        vulnerability.analysis = "Arbitrary-function-call"
                        logger.debug('[CVI-{cvi}] [INDIRECT] CAST verified arbitrary function call'.format(
                            cvi=self.sr.svid))
                    self.rule_vulnerabilities.append(vulnerability)
                else:
                    if index in indirect_indices:
                        pass  # 间接调用 CAST 失败，静默跳过
                    if reason == 'New Core':  # 新的规则

                        logger.debug('[CVI-{cvi}] [NEW-VUL] New Rules init'.format(cvi=self.sr.svid))
                        new_rule_vulnerabilities = NewCore(self.sr, self.target_directory, data, self.files, 0,
                                                           languages=self.languages, tamper_name=self.tamper_name,
                                                           is_unconfirm=self.is_unconfirm,
                                                           newcore_function_list=self.newcore_function_list)

                        if not new_rule_vulnerabilities:
                            pass
                        elif len(new_rule_vulnerabilities) > 0:
                            self.rule_vulnerabilities.extend(new_rule_vulnerabilities)

                    else:
                        logger.debug('Not vulnerability: {code}'.format(code=reason))
            except Exception as e:
                logger.debug('[CVI-{cvi}] Exception processing result: {exc}'.format(
                    cvi=self.sr.svid, exc=e))
                continue
        logger.debug('[CVI-{cvi}] {vn} Vulnerabilities: {count}'.format(cvi=self.sr.svid, vn=self.sr.vulnerability,
                                                                        count=len(self.rule_vulnerabilities)))
        return self.rule_vulnerabilities
