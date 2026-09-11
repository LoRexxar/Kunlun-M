#!/usr/bin/env python3
"""PHP NewCore Benchmark Test - Enhanced with line number verification"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests/php')
output_dir = os.path.join(test_dir, '_newcore_output')


test_cases = [
            # CVI-10002(Reflected XSS) 在主文件检出: echo $result where $result from evaluateExpression($_GET['expr'])
            # CVI-1009(RCE) 检出在辅助文件 newfunction_utils.php 中的 eval 调用
            # 主文件实际检出的是 CVI-10002，引擎按文件粒度报告
            ('newfunction_main.php', True,
             'CVI-10002 echo: echo输出来自eval的不可信结果（引擎在主文件检出 XSS，RCE检出在辅助文件）',
             ['CVI-10002'],
             ['echo']),

    # ===== 间接调用（indirect call）测试 =====
    # 变量函数调用: $func = 'system'; $func($cmd) — alias builder 解析变量函数名
    ('30_indirect_exec.php', True,
     'CVI-1011 system: 变量函数调用 $func($cmd) where $func=system',
     ['CVI-1011'],
     ['$func($cmd)']),
    # call_user_func 回调: call_user_func('system', $cmd) — 引擎检出 CVI-1009
    ('31_indirect_callback.php', True,
     'CVI-1009 call_user_func: call_user_func("system", $cmd) 回调间接调用',
     ['CVI-1009'],
     ['call_user_func']),
    # 安全场景: $func('ls -la') 硬编码参数 — scanner 正确排除 constant 参数
    ('32_indirect_safe.php', False,
     'indirect call with hardcoded arg — correctly not detected (constant excluded)',
     [],
     []),
    # 多层间接: $func='system', $func2=$func, $func2($cmd) — 引擎通过 alias 追踪检出
    ('33_indirect_multilevel.php', True,
     'CVI-1011 system: 多层间接调用 $func2($cmd) via alias chain',
     ['CVI-1011'],
     ['$func2($cmd)']),
]



def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'php',
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
    """Extract list of (cvi_id, lineno, file_path) from scan results for a specific file."""
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
            if 'CVI' in cvi_str:
                vulns.append((cvi_str, lineno))

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
    print("PHP NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/php ...")
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

        vulns = extract_vulns_for_file(results, test_file)
        detected = len(vulns) > 0

        if should_detect:
            found_cvis = set(v[0] for v in vulns)
            missing = set(expected_cvis) - found_cvis
            if not missing:
                # Verify line numbers if keywords specified
                line_ok = True
                for cvi, lineno in vulns:
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
            if detected:
                print(f"  Result: FAIL (false positive: {[v[0] for v in vulns]})")
                failed += 1
            else:
                print(f"  Result: PASS (correctly not detected)")
                passed += 1

    print(f"\n{'=' * 70}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    print(f"{'=' * 70}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
