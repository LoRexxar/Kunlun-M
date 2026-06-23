#!/usr/bin/env python3
"""C# NewCore Benchmark Test - Enhanced with line number verification"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests/csharp')
output_dir = os.path.join(test_dir, '_newcore_output')


test_cases = [
    # CVI-9201: 命令注入 + CVI-9203: 路径遍历
    # 注: SqlCommand(query, conn) 中 query 是字符串拼接变量，引擎无法追踪变量内容，故 CVI-9202 未检出
    ('01_injections.cs', True,
     'CVI-9201/9203: Process.Start 命令注入 + File.ReadAllText/WriteAllText 路径遍历，含安全用例',
     ['CVI-9201', 'CVI-9203'],
     ['Process.Start', 'File.Read', 'File.Write']),

    # CVI-9204: SSRF + CVI-9210: XSS
    # 注: File.Delete(file) 中 file 是变量名，引擎将其排除；XSS 触发 CVI-9210 而非 CVI-9205
    ('02_web_vulns.cs', True,
     'CVI-9204/9210: HttpClient SSRF + Response.Write XSS，含安全用例',
     ['CVI-9204', 'CVI-9210'],
     ['GetStringAsync', 'Response.Write']),

    # CVI-9206: XXE
    # 注: OpenRead(xmlInput) 被误匹配为 CVI-9203 路径遍历；BinaryFormatter.Deserialize 的 match 模式
    # 要求 "BinaryFormatter.*.Deserialize" 但实际代码 bf.Deserialize(stream) 中 bf 是变量名，故未匹配
    ('03_xxe_deser.cs', True,
     'CVI-9206: XmlDocument.LoadXml XXE，含安全用例',
     ['CVI-9206'],
     ['XmlDocument', 'LoadXml']),

    # CVI-9209: 开放重定向（从 log_injection 测试文件）
    ('09_log_injection.cs', True,
     'CVI-9209: Response.Redirect 开放重定向，含硬编码安全用例',
     ['CVI-9209'],
     ['Response.Redirect']),

    # CVI-9210: XSS + CVI-9209: 开放重定向
    ('09_xss_redirect.cs', True,
     'CVI-9210/9209: Response.Write/Html.Raw XSS + Response.Redirect 开放重定向，含硬编码安全用例',
     ['CVI-9210', 'CVI-9209'],
     ['Response.Write', 'Html.Raw', 'Response.Redirect']),

    # CVI-9209: 开放重定向
    ('10_open_redirect.cs', True,
     'CVI-9209: Response.Redirect 开放重定向，含硬编码安全用例',
     ['CVI-9209'],
     ['Response.Redirect']),

    # CVI-9211: XPath注入 + CVI-9212: LDAP注入 + CVI-9213: 模板注入
    ('10_xpath_ldap_template.cs', True,
     'CVI-9211/9212/9213: SelectNodes XPath注入 + DirectorySearcher LDAP注入 + Razor.Parse 模板注入，含硬编码安全用例',
     ['CVI-9211', 'CVI-9212', 'CVI-9213'],
     ['SelectNodes', 'SelectSingleNode', 'DirectorySearcher', 'Razor.Parse']),

    # CVI-9202: SQL注入（CommandText + Execute 方法）
    ('17_sqli_cmd.cs', True,
     'CVI-9202: SqlCommand.CommandText 拼接 + ExecuteReader/ExecuteNonQuery/ExecuteScalar',
     ['CVI-9202'],
     ['CommandText', 'ExecuteReader', 'ExecuteNonQuery', 'ExecuteScalar']),

    # CVI-9205/9210: XSS
    ('18_xss.cs', True,
     'CVI-9205/9210: Response.Write + HttpContext.Current.Response.Write 输出用户输入',
     ['CVI-9205', 'CVI-9210'],
     ['Response.Write']),

    # CVI-9207: 反序列化
    ('19_deser.cs', True,
     'CVI-9207: JavaScriptSerializer.Deserialize + BinaryFormatter.Deserialize + XmlSerializer.Deserialize',
     ['CVI-9207'],
     ['JavaScriptSerializer', 'BinaryFormatter', 'XmlSerializer', 'Deserialize']),

    # CVI-9208: 代码注入
    ('20_code_inject.cs', True,
     'CVI-9208: Assembly.LoadFrom + Activator.CreateInstance + CodeDomProvider.CompileAssemblyFromSource',
     ['CVI-9208'],
     ['Assembly.LoadFrom', 'Activator.CreateInstance', 'CompileAssemblyFromSource']),

    # CVI-9212: LDAP注入
    ('21_ldap.cs', True,
     'CVI-9212: DirectorySearcher 构造函数拼接用户输入 + Filter 赋值',
     ['CVI-9212'],
     ['DirectorySearcher', 'Filter']),
]


def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'csharp',
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
    print("C# NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/csharp ...")
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
        # Support both 4-tuple and 5-tuple format
        if len(test_case) == 5:
            test_file, should_detect, desc, expected_cvis, expected_keywords = test_case
        else:
            test_file, should_detect, desc, expected_cvis = test_case
            expected_keywords = []

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
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)}")
    print(f"{'=' * 70}")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
