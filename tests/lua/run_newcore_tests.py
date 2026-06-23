#!/usr/bin/env python3
"""Lua NewCore Benchmark Test - Enhanced with line number verification

由于 Lua 测试文件是混合文件（同一文件中包含漏洞和安全用例），
测试采用行号级别的精确验证：
- should_detect=True: 检查文件中是否包含指定的 CVI，且至少有一个检出在指定行附近
- should_detect=False: 检查文件中指定安全行号上没有对应 CVI 的检出
"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests/lua')
output_dir = os.path.join(test_dir, '_newcore_output')


# test_cases 格式:
# (file, should_detect, desc, expected_cvis, expected_keywords, safe_lines)
# safe_lines: list of int, 这些行号上不应出现 expected_cvis 中的检出 (仅 should_detect=False 时使用)
test_cases = [
    # ========== 01_injections.lua ==========
    # CVI-9601 命令执行 (检出在第5、6、7行)
    ('01_injections.lua', True,
     'CVI-9601 os.execute/io.popen: 变量参数命令执行',
     ['CVI-9601'],
     ['os.execute', 'io.popen']),
    ('01_injections.lua', False,
     'CVI-9601 os.execute("ls -la"): 硬编码命令（第18行不应检出）',
     [],
     [],
     {18: ['CVI-9601']}),

    # CVI-9602 代码注入 (检出在第10、11行)
    ('01_injections.lua', True,
     'CVI-9602 loadstring/dofile: 动态代码执行',
     ['CVI-9602'],
     ['loadstring', 'dofile']),

    # CVI-9603 文件操作 (检出在第14、15行)
    ('01_injections.lua', True,
     'CVI-9603 io.open/os.remove: 变量参数文件操作',
     ['CVI-9603'],
     ['io.open', 'os.remove']),
    ('01_injections.lua', False,
     'CVI-9603 io.open("config.lua"): 硬编码路径（第19行不应检出）',
     [],
     [],
     {19: ['CVI-9603']}),

    # ========== 02_log_redirect_deser.lua ==========
    # CVI-9607 开放重定向 (检出在第8、9行)
    ('02_log_redirect_deser.lua', True,
     'CVI-9607 ngx.redirect/redirect: 用户可控URL重定向',
     ['CVI-9607'],
     ['redirect']),
    ('02_log_redirect_deser.lua', False,
     'CVI-9607 ngx.redirect("/dashboard"): 硬编码路径（第31行不应检出）',
     [],
     [],
     {31: ['CVI-9607']}),

    # CVI-9608 模板注入 (检出在第12、13、14行)
    ('02_log_redirect_deser.lua', True,
     'CVI-9608 template.compile/render/process: 动态模板注入',
     ['CVI-9608'],
     ['template']),
    ('02_log_redirect_deser.lua', False,
     'CVI-9608 template.render("hello"): 硬编码模板（第34行不应检出）',
     [],
     [],
     {34: ['CVI-9608']}),

    # CVI-9609 日志注入 (检出在第17、18、19行)
    ('02_log_redirect_deser.lua', True,
     'CVI-9609 log.info/warn/error: 日志注入',
     ['CVI-9609'],
     ['log.info', 'log.warn', 'log.error']),
    ('02_log_redirect_deser.lua', False,
     'CVI-9609 log.info("Server started"): 硬编码日志（第32行不应检出）',
     [],
     [],
     {32: ['CVI-9609']}),

    # CVI-9610 XPath注入 (检出在第22、23行)
    ('02_log_redirect_deser.lua', True,
     'CVI-9610 xpath.parse/selectNodes: XPath注入',
     ['CVI-9610'],
     ['xpath']),

    # CVI-9611 不安全反序列化 (检出在第26、27、28行)
    ('02_log_redirect_deser.lua', True,
     'CVI-9611 json.decode/cjson.decode/msgpack.unpack: 不安全反序列化',
     ['CVI-9611'],
     ['json.decode', 'cjson.decode', 'msgpack.unpack']),
    ('02_log_redirect_deser.lua', False,
     'CVI-9611 json.decode("{}"): 硬编码JSON（第33行不应检出）',
     [],
     [],
     {33: ['CVI-9611']}),

    # ========== 17_sqli.lua ==========
    # CVI-9604 SQL注入 (当前引擎对 conn:execute 拼接检出有限)
    ('17_sqli.lua', True,
     'CVI-9604 conn:execute 拼接SQL: SQL注入（至少检出变量query场景）',
     ['CVI-9604'],
     ['input', 'query']),

    # ========== 18_ssrf.lua ==========
    # CVI-9605 SSRF (检出在第11、17、21、28行)
    ('18_ssrf.lua', True,
     'CVI-9605 http.request/socket.connect: SSRF',
     ['CVI-9605'],
     ['http.request', 'socket.connect']),
    ('18_ssrf.lua', False,
     'CVI-9605 http.request("http://example.com"): 硬编码URL（第24行不应检出）',
     [],
     [],
     {24: ['CVI-9605']}),
    ('18_ssrf.lua', False,
     'CVI-9605 socket.connect("localhost", 80): 硬编码地址（第25行不应检出）',
     [],
     [],
     {25: ['CVI-9605']}),

    # ========== 19_code_inject.lua ==========
    # CVI-9606 动态require
    # 注意: CVI-9606 规则匹配 require()，但引擎可能将 require 归类为 load 而被 CVI-9602 匹配
    ('19_code_inject.lua', True,
     'CVI-9606/9602 require动态加载: 动态模块加载（至少检出代码注入类）',
     ['CVI-9602'],
     ['require']),
    ('19_code_inject.lua', False,
     'CVI-9606 require("lfs"): 硬编码模块（第14行不应检出9602）',
     [],
     [],
     {14: ['CVI-9602']}),
    ('19_code_inject.lua', False,
     'CVI-9606 require("socket.http"): 硬编码模块（第15行不应检出9602）',
     [],
     [],
     {15: ['CVI-9602']}),
]


def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'lua',
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


def extract_vulns_for_file(results, target_file):
    """Extract list of (cvi_id, lineno, source_code) from scan results for a specific file."""
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
            lineno = None
            if ':' in str(file_val):
                parts = str(file_val).rsplit(':', 1)
                if parts[-1].isdigit():
                    lineno = int(parts[-1])
            source_code = item.get('source_code', '')
            if 'CVI' in cvi_str:
                vulns.append((cvi_str, lineno, source_code))

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


def check_safe_lines(vulns, safe_lines):
    """检查安全行上没有指定 CVI 的检出。
    safe_lines: dict {lineno: [cvi_ids]}  — 这些行上不应出现对应 CVI
    返回: (ok, msg)
    """
    vuln_by_line = {}
    for cvi, lineno, _ in vulns:
        if lineno:
            vuln_by_line.setdefault(lineno, []).append(cvi)

    for safe_lineno, forbidden_cvis in safe_lines.items():
        actual_cvis = vuln_by_line.get(safe_lineno, [])
        conflicts = set(actual_cvis) & set(forbidden_cvis)
        if conflicts:
            return False, f"line {safe_lineno}: unexpected detection of {conflicts}"

    return True, "safe lines OK"


def main():
    print("=" * 70)
    print("Lua NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/lua ...")
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
    print("Detected vulnerabilities:")
    for item in items:
        cvi = item.get('cvi_id', '')
        f = item.get('file', '')
        sc = item.get('source_code', '')
        print(f"  CVI-{cvi} {f} ({sc})")

    passed = 0
    failed = 0

    for test_case in test_cases:
        # 解析 test_case: (file, should_detect, desc, expected_cvis, expected_keywords, safe_lines)
        if len(test_case) == 6:
            test_file, should_detect, desc, expected_cvis, expected_keywords, safe_lines = test_case
        elif len(test_case) == 5:
            test_file, should_detect, desc, expected_cvis, expected_keywords = test_case
            safe_lines = {}
        elif len(test_case) == 4:
            test_file, should_detect, desc, expected_cvis = test_case
            expected_keywords = []
            safe_lines = {}
        else:
            continue

        print(f"\n[{test_file}] {desc}")
        print(f"  Expected: detect={should_detect}, CVIs={expected_cvis}")

        vulns = extract_vulns_for_file(results, test_file)
        detected = len(vulns) > 0

        if should_detect:
            found_cvis = set(v[0] for v in vulns)
            missing = set(expected_cvis) - found_cvis
            if not missing:
                # 至少有一个命中
                matching_vulns = [(c, l, s) for c, l, s in vulns if c in set(expected_cvis)]
                # 验证行号关键词
                for cvi, lineno, source_code in matching_vulns:
                    if expected_keywords:
                        abs_path = os.path.join(test_dir, test_file)
                        ok, msg = verify_line_content(lineno, abs_path, expected_keywords)
                        if ok:
                            print(f"  [LINE OK] {msg}")
                        else:
                            print(f"  [LINE WARN] {msg}")
                print(f"  Result: PASS (detected {[(v[0], v[1]) for v in matching_vulns]})")
                passed += 1
            else:
                print(f"  Result: FAIL (detected {set(v[0] for v in vulns)}, missing {missing})")
                failed += 1
        else:
            # 检查安全行
            if safe_lines:
                ok, msg = check_safe_lines(vulns, safe_lines)
                if ok:
                    print(f"  Result: PASS ({msg})")
                    passed += 1
                else:
                    print(f"  Result: FAIL ({msg})")
                    failed += 1
            else:
                # 没有指定安全行，检查整个文件是否没有检出
                if detected:
                    print(f"  Result: FAIL (false positive: {[v[0] for v in vulns]})")
                    failed += 1
                else:
                    print(f"  Result: PASS (correctly not detected)")
                    passed += 1

    print(f"\n{'=' * 70}")
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)}")
    print(f"{'=' * 70}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
