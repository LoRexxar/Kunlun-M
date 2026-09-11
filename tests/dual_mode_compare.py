#!/usr/bin/env python3
"""双模对比脚本 v2：旧引擎 vs 新引擎

改进：
- 一次性初始化 Pretreatment（避免全局状态污染）
- 新引擎对每个文件独立构建图
- 旧引擎使用统一 ast_object

用法:
  python3 tests/dual_mode_compare.py [--dir TEST_DIR] [--file TEST_FILE]
"""

import os
import sys
import re
import glob
import json
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
os.environ['DJANGO_SETTINGS_MODULE'] = 'Kunlun_M.settings'

import django
django.setup()

from core.pretreatment import ast_object
from core.core_engine.php.parser import scan_parser as old_scan_parser
from core.graph.normalizers import get_normalizer
from core.graph.graph_builder import AstGraphBuilder
from core.graph.edge_builders import run_all
from core.graph.graph_analyzer import GraphAnalyzer, _SINK_FUNCTIONS

SINK_LIST = sorted(_SINK_FUNCTIONS)


def find_sink_grep_results(filepath):
    """用 grep 方式找 sink 函数和行号"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    results = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.split('//')[0].split('#')[0].strip()
        for sink in SINK_LIST:
            if re.search(r'\b' + re.escape(sink) + r'\s*\(', stripped):
                results.append((lineno, sink))
    return results


def run_old_engine_single(filepath, lineno, sink_name):
    """用旧引擎分析单个 sink"""
    try:
        results = old_scan_parser(
            [sink_name], lineno, filepath,
            repair_functions=[], controlled_params=[]
        )
        if results:
            return results[0].get('code')
        return None
    except Exception:
        return None


def run_new_engine_single(filepath):
    """构建新引擎图并分析所有 sink"""
    from phply.phplex import lexer
    from phply.phpparse import make_parser
    import codecs

    fi = codecs.open(filepath, 'r', encoding='utf-8', errors='ignore')
    code = fi.read()
    fi.close()

    try:
        parser = make_parser()
        ast_nodes = parser.parse(code, debug=False, lexer=lexer.clone(), tracking=True)
    except Exception:
        return {}

    if not ast_nodes:
        return {}

    try:
        norm_cls = get_normalizer('php')
        normalizer = norm_cls()
        result = normalizer.normalize(ast_nodes, filepath)
        if result is None:
            return {}

        file_node, nodes, edges = result
        builder = AstGraphBuilder()
        builder.add_file(file_node, nodes, edges)
        graph = builder.build()
        run_all(graph, language='php')

        analyzer = GraphAnalyzer(graph, language='php')
        sinks = analyzer.find_sinks()

        new_results = {}
        for s in sinks:
            for arg_vid in s.get('arg_vids', []):
                r = analyzer.parameters_back(arg_vid)
                key = (s['lineno'], s['name'])
                if key not in new_results or _code_rank(r.code) > _code_rank(new_results[key]['code']):
                    new_results[key] = {
                        'lineno': s['lineno'],
                        'name': s['name'],
                        'code': r.code,
                    'reason': r.reason[:80] if r.reason else '',
                }
        return new_results
    except Exception as e:
        return {'error': str(e)[:100]}


def _code_rank(code):
    if code is None: return -10
    return {1: 10, 2: 8, 3: 5, -1: 3, 4: 2}.get(code, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', help='测试目录')
    ap.add_argument('--file', help='单个测试文件')
    args = ap.parse_args()

    if args.file:
        files = [args.file]
    elif args.dir:
        files = sorted(glob.glob(os.path.join(args.dir, '**/*.php'), recursive=True))
    else:
        files = sorted(glob.glob(os.path.join(PROJECT_ROOT, 'tests', 'vulnerabilities', '*.php')))

    if not files:
        print("没有找到 PHP 文件")
        return

    # ── 旧引擎: 一次性初始化 Pretreatment ──
    file_list = [('.php', {'count': len(files), 'list': files})]
    ast_object.init_pre(PROJECT_ROOT, file_list)
    ast_object.pre_ast_all(['php'])

    print(f"{'='*70}")
    print(f"双模对比: 旧引擎 vs 新引擎")
    print(f"文件数: {len(files)}")
    print(f"{'='*70}")

    total_diffs = 0
    all_details = []

    for filepath in files:
        basename = os.path.basename(filepath)

        if filepath not in ast_object.pre_result:
            print(f"\n❌ {basename}: 解析失败")
            continue

        # ── 旧引擎 ──
        grep_sinks = find_sink_grep_results(filepath)
        old_results = {}
        seen = set()
        for lineno, sink_name in grep_sinks:
            if lineno in seen: continue
            seen.add(lineno)
            code = run_old_engine_single(filepath, lineno, sink_name)
            if code is not None:
                key = (lineno, sink_name)
                if key not in old_results or _code_rank(code) > _code_rank(old_results[key]):
                    old_results[key] = code

        # ── 新引擎: 独立解析 + 构建图 ──
        new_results = run_new_engine_single(filepath)
        if isinstance(new_results, dict) and 'error' in new_results:
            print(f"\n❌ {basename}: {new_results['error']}")
            continue

        # ── 对比 ──
        all_keys = set(old_results.keys()) | set(new_results.keys())
        file_diffs = []

        for key in sorted(all_keys):
            oc = old_results.get(key)
            nc = new_results.get(key, {}).get('code') if isinstance(new_results.get(key), dict) else None

            if oc == nc:
                continue

            diff_type = 'code_mismatch'
            if oc and oc > 0 and (nc is None or nc <= 0):
                diff_type = 'missed_by_new'
            elif (oc is None or oc <= 0) and nc == 1:
                diff_type = 'extra_in_new'

            file_diffs.append({
                'lineno': key[0], 'sink': key[1],
                'old_code': oc, 'new_code': nc,
                'new_reason': new_results.get(key, {}).get('reason', ''),
                'type': diff_type,
            })
            total_diffs += 1

        old_vuln = sum(1 for c in old_results.values() if c and c > 0)
        new_vuln = sum(1 for r in new_results.values() if isinstance(r, dict) and r.get('code') == 1)

        if file_diffs:
            print(f"\n🔴 {basename}: {len(file_diffs)} 差异 (旧={old_vuln} 新={new_vuln})")
            for d in file_diffs:
                label = {'missed_by_new': '漏报', 'extra_in_new': '多报', 'code_mismatch': '不一致'}[d['type']]
                print(f"  L{d['lineno']} {d['sink']}: 旧={d['old_code']} 新={d['new_code']} → {label}")
                if d.get('new_reason'):
                    print(f"         新: {d['new_reason']}")
        else:
            print(f"\n✅ {basename}: 一致 (检出={old_vuln})")

        for (ln, name), code in sorted(old_results.items()):
            if code and code > 0:
                print(f"  [旧] L{ln} {name}: code={code}")
        for key, r in sorted(new_results.items()):
            if isinstance(r, dict) and r.get('code') == 1:
                print(f"  [新] L{r['lineno']} {r['name']}: code={r['code']} ({r['reason'][:60]})")

        all_details.append({
            'file': basename, 'old_vuln': old_vuln, 'new_vuln': new_vuln,
            'diffs': len(file_diffs), 'diff_details': file_diffs,
        })

    # ── 总结 ──
    print(f"\n{'='*70}")
    total_old = sum(d['old_vuln'] for d in all_details)
    total_new = sum(d['new_vuln'] for d in all_details)
    print(f"总计: {len(all_details)} 文件 | 旧={total_old} 新={total_new} | 差异={total_diffs}")
    if total_diffs == 0:
        print("🎉 完全一致!")
    else:
        missed = sum(1 for d in all_details for dd in d['diff_details'] if dd['type'] == 'missed_by_new')
        extra = sum(1 for d in all_details for dd in d['diff_details'] if dd['type'] == 'extra_in_new')
        mismatch = sum(1 for d in all_details for dd in d['diff_details'] if dd['type'] == 'code_mismatch')
        print(f"  漏报: {missed} | 多报: {extra} | 不一致: {mismatch}")

    out = os.path.join(PROJECT_ROOT, 'tests', '_dual_mode_result.json')
    with open(out, 'w') as f:
        json.dump(all_details, f, indent=2, ensure_ascii=False)
    print(f"结果已保存: {out}")


if __name__ == '__main__':
    main()
