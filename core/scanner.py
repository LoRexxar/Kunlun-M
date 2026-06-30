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
                    from core.pretreatment import ast_object as _ao
                    scan_dir = ensure_scan_dir(a_sid)
                    gio = AstGraphIO(scan_dir)
                    meta = gio.save(graph)
                    sr = ScanRecord(get_workspace_db())
                    sr.upsert(
                        scan_id=a_sid,
                        language=_ao.lan[0] if _ao.lan else None,
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
            graph = build_ast_graph(ast_object, db_path=db_path, scan_id=a_sid)
            logger.info('[SCAN] [GRAPH] Built graph: %d nodes, %d edges', graph.vcount(), graph.ecount())
        except Exception as e:
            logger.warning('[SCAN] [GRAPH] Build failed: %s', e)

    if graph is None or graph.vcount() == 0:
        logger.warning('[SCAN] [GRAPH] Empty or no graph — sink-based rules skipped')

    # ── 非 sink-compatible 规则过滤 ──
    from Kunlun_M.const import mm_framework_dependency as _MM_FW_DEP
    _skip_modes = {'only-regex', 'only-keyword', 'file-path-regex-match', 'regex-return-regex', 'vustomize-match'}
    _skip_count = 0
    _fw_dep_rules = []
    for _lang, _rules in lang_rules.items():
        _remaining = []
        for _rule in _rules:
            _mm = getattr(_rule, 'match_mode', '')
            if _mm == _MM_FW_DEP:
                _fw_dep_rules.append(_rule)
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
            # PHP/Java 的 SourceRegistry 接口不同（无 is_source_member），需适配

            def _make_source_registry(lang):
                """为指定语言创建 source_registry（轻量，仅 builtin）"""
                # JS/TS 使用完整 discover（含框架 + AST 遍历）
                if lang in ('javascript', 'typescript'):
                    engine = 'javascript' if lang == 'javascript' else 'typescript'
                    from importlib import import_module
                    mod = import_module(f'core.core_engine.{engine}.source_discovery')
                    return mod.discover_sources(ast_object.target_directory, ast_object)
                # PHP：dataclass，builtin_sources 字段已含 superglobals
                if lang == 'php':
                    from core.core_engine.php.source_discovery import SourceRegistry as _SR
                    _php_sr = _SR()
                    # 适配接口：添加 is_source_member 方法
                    _orig_isv = _php_sr.is_source_variable
                    _php_sr.source_members = _php_sr.builtin_sources
                    def _php_ism(expr):
                        return _orig_isv(expr.split('.')[0].split('(')[0]) if expr else False
                    _php_sr.is_source_member = _php_ism
                    return _php_sr
                # Java：无 is_source_member，需适配
                if lang == 'java':
                    from core.core_engine.java.source_discovery import SourceRegistry as _SR, _BUILTIN_SOURCE_MEMBERS
                    _java_sr = _SR()
                    _java_sr.source_members = set(_BUILTIN_SOURCE_MEMBERS)
                    def _java_ism(expr):
                        for sm in _java_sr.source_members:
                            if expr == sm or expr.startswith(sm + '.') or expr.startswith(sm + '('):
                                return True
                        return False
                    _java_sr.is_source_member = _java_ism
                    return _java_sr
                # 其他语言：从 _BUILTIN_SOURCE_MEMBERS 创建轻量 SourceRegistry
                entry = _LANG_BUILTIN_SOURCE.get(lang)
                if not entry:
                    return None
                try:
                    mod = __import__(entry[0], fromlist=['SourceRegistry', entry[1]])
                    SR = getattr(mod, 'SourceRegistry', None)
                    BSM = getattr(mod, entry[1], None)
                    if SR and BSM:
                        sr = SR()
                        for sm in BSM:
                            sr.add_source_member(sm)
                        # Rust: 注册短名（use std::env → env::args）
                        if lang == "rust":
                            for sm in BSM:
                                for prefix in ("std::", "std::process::", "std::io::", "std::net::"):
                                    if sm.startswith(prefix):
                                        sr.add_source_member(sm[len(prefix):])
                        return sr
                except ImportError:
                    logger.debug('[SCAN] [GRAPH] No source_discovery for lang=%s', lang)
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
                    name_str = f"{sn.class_}.{sn.method}"
                else:
                    name_str = sn.method
                name_str = re.sub(r'[^a-zA-Z0-9_.]', '', name_str)
                if name_str:
                    result.append(name_str)
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
            analyzer = GraphAnalyzer(graph, language=lang, source_registry=_make_source_registry(lang))

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
                    # 对 sink 的每个参数做污点回溯（去重 + 跳过 function/callee 节点）
                    arg_vids = list(set(sink.get('arg_vids', [])))
                    found_controllable = False
                    found_unconfirmed = False
                    result = None
                    unconfirmed_result = None
                    for arg_vid in arg_vids:
                        arg_label = _vattr(graph.vs[arg_vid], 'label', '')
                        if arg_label == 'function':
                            continue
                        r = analyzer.parameters_back(arg_vid)
                        if r is not None:
                            if r.is_controllable:
                                found_controllable = True
                                result = r
                                break
                            elif not r.is_uncontrollable and not found_unconfirmed:
                                found_unconfirmed = True
                                unconfirmed_result = r
                    if not found_controllable:
                        # unconfirm 模式：记录疑似漏洞
                        if found_unconfirmed and is_unconfirm:
                            result = unconfirmed_result
                            found_controllable = True
                        elif not arg_vids:
                            # 无参数的 sink（如 rand::thread_rng()）— 跳过 taint 回溯，
                            # 依赖 rule.main() 做二次筛选
                            found_controllable = True
                            sink_vid = sink['vid']
                            result = AnalysisResult(
                                code=0,
                                reason=f"presence of sink '{sink.get('name', '')}'",
                                chain=[], path=[sink_vid],
                            )
                        else:
                            continue

                    sink_name = sink.get('name', '')
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
                                # Suffix/fallback match
                                if any(sn_lower.endswith("." + n) or n.endswith("." + sn_lower) for n in rsn):
                                    matched_rules.append(rule)
                                    continue
                        if matched_rules:
                            break  # exact pass found matches, skip suffix pass

                    if not matched_rules:
                        continue

                    # Try each matched rule; first whose main() passes reports
                    # rule.main() 二次筛选
                    main_input = sink_name  # default: sink function name
                    sink_file = _vattr(graph.vs[sink['vid']], 'path', '')
                    sink_lineno = _vattr(graph.vs[sink['vid']], 'lineno', 0) or 0
                    # Pre-read source line for main() input
                    if sink_file:
                        try:
                            with open(sink_file, 'r', encoding='utf-8', errors='replace') as mf:
                                source_lines = mf.readlines()
                            idx = int(sink_lineno) - 1
                            if 0 <= idx < len(source_lines):
                                main_input = source_lines[idx].strip()
                        except Exception:
                            pass

                    matched_rule = None
                    for candidate_rule in matched_rules:
                        if hasattr(candidate_rule, 'main') and callable(candidate_rule.main):
                            try:
                                main_result = candidate_rule.main(main_input)
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

                    # 文件路径过滤：vendor/test 目录
                    vuln_file_path = _vattr(graph.vs[sink['vid']], 'path', '')
                    if vuln_file_path:
                        vuln_file_norm = os.path.normpath(vuln_file_path)
                        # vendor 目录
                        if '/vendor/' in vuln_file_norm or vuln_file_norm.endswith(os.path.join('vendor', '')):
                            continue
                        # test 目录
                        for test_path in ['/test/', '/tests/', '/unitTests/']:
                            if test_path in vuln_file_norm:
                                continue

                    # 构建污点传播链
                    chain = []
                    for vid in result.path:
                        v = graph.vs[vid]
                        node_label = _vattr(v, 'label', '')
                        node_name = _vattr(v, 'name', '')
                        node_file = _vattr(v, 'path', '')
                        node_lineno = int(_vattr(v, 'lineno', 0) or 0)
                        chain.append((node_label, node_name, node_file, node_lineno, vid))

                    # 构建 VulnerabilityResult
                    sink_vid = sink['vid']
                    file_path = _vattr(graph.vs[sink_vid], 'path', '')
                    lineno = int(_vattr(graph.vs[sink_vid], 'lineno', 0) or 0)

                    vuln = VulnerabilityResult.from_match(
                        (file_path, lineno, sink_name),
                        svid=matched_rule.svid,
                        language=matched_rule.language,
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
    def __init__(self, target_directory, single_rule, files, language=None, tamper_name=None, is_unconfirm=False,
                 newcore_function_list=None):
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
                        sink_names = [sn.method for sn in _get_rule_sink_names_list(self.sr)]
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
