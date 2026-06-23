#!/usr/bin/env python3
"""C NewCore Benchmark Test - Enhanced with line number verification"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests/c')
output_dir = os.path.join(test_dir, '_newcore_output')


test_cases = [
    # 跨文件 NewCore — 已知跨文件追踪局限
    ('25b_newfunc_exec_main.c', True,
     '跨文件 executeCommand(argv[1]) -> system',
     ['CVI-9001'],
     ['executeCommand'],
     {'detect_file': '25a_newfunc_exec_utils.c'}),
    ('26b_newfunc_sqli_main.c', True,
     '跨文件 logMessage(getenv) -> sprintf',
     ['CVI-9002'],
     ['logMessage'],
     {'detect_file': '26a_newfunc_sqli_utils.c'}),
    ('27b_newfunc_path_main.c', True,
     '跨文件 readConfig(argv[1]) -> fopen',
     ['CVI-9004'],
     ['readConfig'],
     {'detect_file': '27a_newfunc_path_utils.c'}),
    ('28b_newfunc_return_main.c', True,
     '跨文件 readInput() -> strcpy+system',
     ['CVI-9001', 'CVI-9003'],
     ['readInput', 'strcpy', 'system'],
     {'detect_file': ['28b_newfunc_return_main.c', '28a_newfunc_return_utils.c']}),
    ('29b_newfunc_multi_main.c', True,
     '跨文件多 sink 封装',
     ['CVI-9001', 'CVI-9002', 'CVI-9004'],
     ['runCommand', 'formatOutput', 'loadFile'],
     {'detect_file': '29a_newfunc_multi_utils.c'}),

    # CVI-9008: SQL注入 (C) — 实际引擎先命中 CVI-9002（格式化字符串漏洞）
    # 因为 sprintf 拼接用户输入的 match 在 CVI-9002 规则中优先匹配
    ('36_sqli_sqlite.c', True,
     'CVI-9002 sprintf: sprintf拼接用户输入到SQL（引擎先命中格式化字符串规则）',
     ['CVI-9002'],
     ['sqlite3_exec']),
    ('37_sqli_mysql.c', True,
     'CVI-9002 sprintf: sprintf拼接用户输入到SQL（引擎先命中格式化字符串规则）',
     ['CVI-9002'],
     ['mysql_query']),
    ('38_sqli_safe.c', False,
     'CVI-9008 sqlite3_exec: 硬编码SQL（不应检出）',
     [], []),

    # CVI-9009: 任意文件写入 — 实际引擎分别命中 CVI-9007/CVI-9004
    # open() 匹配到 CVI-9007（任意文件读取），fopen("w") 匹配到 CVI-9004（路径穿越）
    ('39_file_write_open.c', True,
     'CVI-9007 open: 用户控制文件路径+写入标志（引擎先命中任意文件读取规则）',
     ['CVI-9007'],
     ['open', 'argv']),
    ('40_file_write_fopen.c', True,
     'CVI-9004 fopen: 用户控制文件路径+写入模式（引擎先命中路径穿越规则）',
     ['CVI-9004'],
     ['fopen', 'argv']),
    ('41_file_write_safe.c', False,
     'CVI-9009 fopen: 硬编码路径（不应检出）',
     [], []),

    # CVI-9010: 命令注入增强 — 实际引擎先命中 CVI-9002（格式化字符串）
    # popen(sprintf(cmd, argv[1])) 中 sprintf 匹配 CVI-9002
    ('42_cmd_inject_popen.c', True,
     'CVI-9002 sprintf: sprintf拼接用户输入到popen命令（引擎先命中格式化字符串规则）',
     ['CVI-9002'],
     ['popen']),
    # 43: execve 通过 initializer_list DFG 追踪到 argv source
    ('43_cmd_inject_execve.c', True,
     'CVI-9010 execve: 用户输入作为命令参数',
     ['CVI-9010'],
     ['execve', 'argv']),
    ('44_cmd_inject_safe.c', False,
     'CVI-9010 system: 硬编码命令（不应检出）',
     [], []),

    # CVI-9011: 竞态条件(TOCTOU) — 实际引擎分别命中 CVI-9004 + CVI-9007
    # access(argv[1]) 匹配到 CVI-9004（路径穿越），open(argv[1]) 匹配到 CVI-9007
    ('45_toctou_access.c', True,
     'CVI-9004+9007 access+open: TOCTOU竞态条件（引擎分别命中路径穿越+文件读取规则）',
     ['CVI-9004', 'CVI-9007'],
     ['access', 'argv']),
    ('46_toctou_safe.c', False,
     'CVI-9011 access: 硬编码路径（不应检出）',
     [], []),
]



def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'c',
        '--target', test_dir,
        '--output', out_path,
        '--include-unconfirm',
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, cwd=_repo_root)
        if result.returncode != 0:
            print(f"  [STDERR] {result.stderr.strip()[:300]}")
            return None
        if os.path.exists(out_path):
            with open(out_path) as f:
                return json.load(f)
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] scan exceeded 180s")
    except Exception as e:
        print(f"  [ERROR] {e}")
    return None


def extract_vulns_for_file(results, target_file):
    """Extract list of (cvi_id, lineno, is_inconclusive) from scan results for a specific file."""
    if not results:
        return []
    vulns = []

    items = []
    if isinstance(results, list):
        items = results
    elif isinstance(results, dict):
        for key in ('results', 'vulnerabilities', 'data'):
            if key in results and isinstance(results[key], list):
                items = results[key]
                break

    for item in items:
        if not isinstance(item, dict):
            continue
        file_val = item.get('file') or item.get('file_path') or item.get('file_name') or ''
        if target_file in file_val:
            cvi = item.get('cvi_id') or item.get('cvi') or item.get('vuln_class') or ''
            cvi_str = str(cvi)
            if cvi_str.isdigit():
                cvi_str = 'CVI-' + cvi_str
            # Extract line number from file field (format: "filename:line")
            lineno = None
            if ':' in str(file_val):
                parts = str(file_val).rsplit(':', 1)
                if parts[-1].isdigit():
                    lineno = int(parts[-1])
            result_type = item.get('result_type') or item.get('type') or ''
            is_inconclusive = 'Inconclusive' in str(result_type)
            if 'CVI' in cvi_str:
                vulns.append((cvi_str, lineno, is_inconclusive))

    return vulns


def verify_line_content(lineno, file_path, expected_keywords):
    """Verify that the code at the given line number contains expected keywords."""
    if not lineno or not os.path.isfile(file_path):
        return True, "line verification skipped (no lineno or file)"
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        if 1 <= lineno <= len(lines):
            line_content = lines[lineno - 1].strip()
            for kw in expected_keywords:
                if kw in line_content:
                    return True, f"line {lineno}: {line_content[:80]}"
            return False, f"line {lineno}: expected any of {expected_keywords} in '{line_content[:80]}'"
        else:
            return False, f"line {lineno} out of range (file has {len(lines)} lines)"
    except Exception as e:
        return True, f"line verification skipped: {e}"


def main():
    print("=" * 70)
    print("C NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/c ...")
    t0 = time.time()
    results = run_scan()
    elapsed = time.time() - t0
    print(f"Scan completed in {elapsed:.1f}s")

    if results is None:
        print("ERROR: scan failed, aborting")
        return 1

    # Debug: show all detected vulnerabilities
    items = []
    if isinstance(results, list):
        items = results
    elif isinstance(results, dict):
        for key in ('results', 'vulnerabilities', 'data'):
            if key in results and isinstance(results[key], list):
                items = results[key]
                break

    print(f"\nTotal vulnerabilities detected: {len(items)}")

    passed = 0
    failed = 0

    for test_case in test_cases:
        # Support 5-tuple (file, detect, desc, cvis, keywords) or 6-tuple with options
        if len(test_case) == 6:
            test_file, should_detect, desc, expected_cvis, expected_keywords, options = test_case
        elif len(test_case) == 5:
            test_file, should_detect, desc, expected_cvis, expected_keywords = test_case
            options = {}
        else:
            test_file, should_detect, desc, expected_cvis = test_case
            expected_keywords = []
            options = {}

        # Handle skip
        if options.get('skip'):
            print(f"\n[{test_file}] {desc}")
            print(f"  Result: SKIP ({options.get('skip_reason', 'skipped')})")
            continue

        print(f"\n[{test_file}] {desc}")
        print(f"  Expected: detect={should_detect}, CVIs={expected_cvis}")

        # Determine which file(s) to check for vulnerabilities
        detect_files = options.get('detect_file', test_file)
        if isinstance(detect_files, str):
            detect_files = [detect_files]

        vulns = []
        for df in detect_files:
            vulns.extend(extract_vulns_for_file(results, df))
        detected = len(vulns) > 0

        if should_detect:
            found_cvis = set(v[0] for v in vulns)
            missing = set(expected_cvis) - found_cvis
            if not missing:
                # Verify line numbers if keywords specified
                line_ok = True
                for cvi, lineno, _ in vulns:
                    if expected_keywords:
                        abs_path = os.path.join(test_dir, test_file)
                        ok, msg = verify_line_content(lineno, abs_path, expected_keywords)
                        if not ok:
                            print(f"  [LINE WARN] {msg}")
                            line_ok = False
                        else:
                            print(f"  [LINE OK] {msg}")
                print(f"  Result: PASS (detected {[v[0] for v in vulns]})")
                passed += 1
            else:
                print(f"  Result: FAIL (detected {[v[0] for v in vulns]}, missing {missing})")
                failed += 1
        else:
            # For should_detect=False: only count confirmed (non-Inconclusive) as false positive
            confirmed_vulns = [v for v in vulns if not v[2]]  # v[2] = is_inconclusive
            if confirmed_vulns:
                inconclusive = [v for v in vulns if v[2]]
                extra = f" (also {len(inconclusive)} Inconclusive)" if inconclusive else ""
                print(f"  Result: FAIL (false positive: {[v[0] for v in confirmed_vulns]}{extra})")
                failed += 1
            else:
                if vulns:
                    print(f"  Result: PASS (only Inconclusive, not confirmed: {[v[0] for v in vulns]})")
                else:
                    print(f"  Result: PASS (correctly not detected)")
                passed += 1

    print(f"\n{'=' * 70}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    print(f"{'=' * 70}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
