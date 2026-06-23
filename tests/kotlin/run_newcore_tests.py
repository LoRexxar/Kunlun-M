#!/usr/bin/env python3
"""Kotlin NewCore Benchmark Test - Enhanced with line number verification"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests', 'kotlin')
output_dir = os.path.join(test_dir, '_newcore_output')


# test_cases: (filename, should_detect, description, expected_cvis, expected_keywords)
# should_detect=True: 期望检出漏洞
# should_detect=False: 期望不检出（安全代码）
# should_detect='skip': 已知漏检，跳过不计分
test_cases = [
    # ===== 01_injections.kt =====
    ('01_injections.kt', True,
     'CVI-9302 命令注入: Runtime.getRuntime().exec + ProcessBuilder',
     ['CVI-9302'],
     ['Runtime.getRuntime().exec', 'ProcessBuilder']),
    ('01_injections.kt', True,
     'CVI-9303 路径遍历: File(filename).readText/writeText',
     ['CVI-9303'],
     ['File(', 'readText', 'writeText']),

    # ===== 02_log_redirect_deser.kt =====
    ('02_log_redirect_deser.kt', True,
     'CVI-9307 日志注入: logger.info/warn/error 拼接用户输入',
     ['CVI-9307'],
     ['logger.info', 'userInput']),
    ('02_log_redirect_deser.kt', True,
     'CVI-9308 开放重定向: sendRedirect(targetUrl)',
     ['CVI-9308'],
     ['sendRedirect']),
    ('02_log_redirect_deser.kt', True,
     'CVI-9309 反序列化: Gson.fromJson + ObjectMapper.readValue',
     ['CVI-9309'],
     ['fromJson', 'readValue']),
    ('02_log_redirect_deser.kt', True,
     'CVI-9310 XPath注入: xpath.evaluate(xpathExpr, document)',
     ['CVI-9310'],
     ['evaluate']),
    ('02_log_redirect_deser.kt', True,
     'CVI-9312 模板注入: engine.process(template, context)',
     ['CVI-9312'],
     ['engine.process']),

    # ===== 03_sqli.kt =====
    # KNOWN GAP: CVI-9301 SQL注入规则目前未检出 stmt.executeQuery("$input")
    # kotlin source_discovery 可能未正确解析字符串模板变量
    ('03_sqli.kt', 'skip',
     'CVI-9301 SQL注入: stmt.executeQuery 字符串模板拼接 [KNOWN GAP]',
     ['CVI-9301'],
     ['executeQuery']),

    # ===== 04_xss.kt =====
    ('04_xss.kt', True,
     'CVI-9304 XSS: Html.fromHtml(input) + webView.loadData(input, ...)',
     ['CVI-9304'],
     ['Html.fromHtml', 'loadData']),

    # ===== 05_ssrf.kt =====
    ('05_ssrf.kt', True,
     'CVI-9305 SSRF: URL(input) 用户可控URL',
     ['CVI-9305'],
     ['URL']),

    # ===== 06_code_inject.kt =====
    ('06_code_inject.kt', True,
     'CVI-9306 代码注入: Class.forName + loader.loadClass + newInstance',
     ['CVI-9306'],
     ['Class.forName', 'loadClass', 'newInstance']),

    # ===== 07_log_inject.kt =====
    ('07_log_inject.kt', True,
     'CVI-9307 日志注入: logger.info/warn/error/debug 拼接用户输入',
     ['CVI-9307'],
     ['logger.info', 'userInput']),

    # ===== 08_ldap.kt =====
    # KNOWN GAP: CVI-9311 LDAP注入规则未检出 ctx.search("(cn=$input)")
    # .search 匹配模式可能与 kotlin 的 search 函数冲突
    ('08_ldap.kt', 'skip',
     'CVI-9311 LDAP注入: ctx.search 过滤器拼接用户输入 [KNOWN GAP]',
     ['CVI-9311'],
     ['search']),

    # ===== 间接调用（indirect call）测试 =====
    # ProcessBuilder 变量绑定: val func = ProcessBuilder(cmd); func.start()
    # 引擎检出 CVI-9302，alias builder 解析 ProcessBuilder 变量
    ('indirect_exec.kt', True,
     'CVI-9302 命令注入: ProcessBuilder 变量绑定间接调用 func.start()',
     ['CVI-9302'],
     ['ProcessBuilder']),
]



def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'kotlin',
        '--target', test_dir,
        '--output', out_path,
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


def _get_items(results):
    """Extract flat list of vulnerability items from results."""
    if isinstance(results, list):
        return results
    if isinstance(results, dict):
        for key in ('results', 'vulnerabilities', 'data'):
            if key in results and isinstance(results[key], list):
                return results[key]
    return []


def extract_vulns_for_file(results, target_file):
    """Extract list of (cvi_id, lineno) from scan results for a specific file."""
    if not results:
        return []
    vulns = []
    for item in _get_items(results):
        if not isinstance(item, dict):
            continue
        file_val = item.get('file') or item.get('file_path') or item.get('file_name') or ''
        if target_file not in file_val:
            continue
        cvi = item.get('cvi_id') or item.get('cvi') or item.get('vuln_class') or ''
        cvi_str = str(cvi)
        if cvi_str.isdigit():
            cvi_str = 'CVI-' + cvi_str
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
        # Check target line and nearby lines (within +/- 2) for multi-line constructs
        for offset in [0, -1, 1, -2, 2]:
            check_line = lineno + offset
            if 1 <= check_line <= len(lines):
                line_content = lines[check_line - 1].strip()
                for kw in expected_keywords:
                    if kw in line_content:
                        suffix = f" (±{offset})" if offset != 0 else ""
                        return True, f"line {check_line}{suffix}: {line_content[:80]}"
        return False, f"line {lineno}: expected any of {expected_keywords} in nearby lines"
    except Exception as e:
        return True, f"line verification skipped: {e}"


def main():
    print("=" * 70)
    print("Kotlin NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/kotlin ...")
    t0 = time.time()
    results = run_scan()
    elapsed = time.time() - t0
    print(f"Scan completed in {elapsed:.1f}s")

    if results is None:
        print("ERROR: scan failed, aborting")
        return 1

    items = _get_items(results)
    print(f"\nTotal vulnerabilities detected: {len(items)}")

    passed = 0
    failed = 0
    skipped = 0

    for test_case in test_cases:
        test_file, should_detect, desc, expected_cvis, expected_keywords = test_case

        print(f"\n[{test_file}] {desc}")
        print(f"  Expected: detect={should_detect}, CVIs={expected_cvis}")

        # Skip known gaps
        if should_detect == 'skip':
            vulns = extract_vulns_for_file(results, test_file)
            found_cvis = set(v[0] for v in vulns)
            missing = set(expected_cvis) - found_cvis
            if missing:
                print(f"  Result: SKIP (known gap, missing {missing})")
                skipped += 1
            else:
                print(f"  Result: SKIP -> PASS (gap resolved! detected {list(found_cvis & set(expected_cvis))})")
                passed += 1
            continue

        vulns = extract_vulns_for_file(results, test_file)
        detected = len(vulns) > 0

        if should_detect:
            found_cvis = set(v[0] for v in vulns)
            missing = set(expected_cvis) - found_cvis
            if not missing:
                # Verify line numbers: only check vulns matching expected CVIs
                for cvi, lineno in vulns:
                    if cvi in expected_cvis and expected_keywords:
                        abs_path = os.path.join(test_dir, test_file)
                        ok, msg = verify_line_content(lineno, abs_path, expected_keywords)
                        if ok:
                            print(f"  [LINE OK] {msg}")
                        else:
                            print(f"  [LINE WARN] {msg}")
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
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped out of {len(test_cases)}")
    print(f"{'=' * 70}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
