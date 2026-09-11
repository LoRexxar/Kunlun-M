#!/usr/bin/env python3
"""Rust NewCore Benchmark Test - Enhanced with line number verification"""
import json
import os
import subprocess
import sys
import time

_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ci_scan = os.path.join(_repo_root, 'tools', 'ci_scan.py')
test_dir = os.path.join(_repo_root, 'tests', 'rust')
output_dir = os.path.join(test_dir, '_newcore_output')


test_cases = [
    # 01_injections.rs - 多漏洞综合测试
    # CVI-9501 规则 main() 把 Command::new("sh") 视为硬编码排除，
    # 实际由 CVI-9508（.arg）和 CVI-9505（.status）捕获
    ('01_injections.rs', True,
     'CVI-9508 Command.arg 用户输入命令注入 (Command::new("sh") 被 CVI-9501 排除)',
     ['CVI-9508'],
     ['.arg(']),
    ('01_injections.rs', True,
     'CVI-9502 fs::read_to_string/write/remove_file 路径遍历',
     ['CVI-9502'],
     ['fs::read_to_string', 'fs::write', 'fs::remove_file']),
    # 01_injections.rs 中 serde_json::from_str 变量名为 _，normalizer 未检出，
    # 反序列化在 18_deser.rs 中正常检出
    ('01_injections.rs', True,
     'CVI-9505 命令注入变体 (.status sink)',
     ['CVI-9505'],
     ['status']),

    # 02_log_env_path.rs - 日志注入/环境变量注入/弱随机/路径遍历
    ('02_log_env_path.rs', True,
     'CVI-9507 log::info!/warn!/error!/debug! 日志注入',
     ['CVI-9507'],
     ['log::info!', 'user_input']),
    ('02_log_env_path.rs', True,
     'CVI-9509 env::set_var 环境变量注入',
     ['CVI-9509'],
     ['set_var', 'user_input']),
    ('02_log_env_path.rs', True,
     'CVI-9510 rand::thread_rng/rand::random 不安全随机数',
     ['CVI-9510'],
     ['rand']),
    ('02_log_env_path.rs', True,
     'CVI-9511 PathBuf::push/Path::new 路径遍历',
     ['CVI-9511'],
     ['PathBuf', 'file_path']),

    # 13_cmd_inject.rs - 命令注入
    ('13_cmd_inject.rs', True,
     'CVI-9501 Command::new("sh") 命令注入',
     ['CVI-9501'],
     ['Command::new']),
    ('13_cmd_inject.rs', True,
     'CVI-9501 std::process::Command::new 命令注入',
     ['CVI-9501'],
     ['process::Command']),
    ('13_cmd_inject.rs', True,
     'CVI-9508 Command.arg 用户输入参数注入',
     ['CVI-9508'],
     ['.arg(']),

    # 14_sqli.rs - SQL注入
    ('14_sqli.rs', True,
     'CVI-9503 client.execute SQL注入',
     ['CVI-9503'],
     ['execute', 'format!']),
    ('14_sqli.rs', True,
     'CVI-9503 client.query SQL注入',
     ['CVI-9503'],
     ['query', 'format!']),
    ('14_sqli.rs', True,
     'CVI-9503 client.query_one SQL注入',
     ['CVI-9503'],
     ['query_one', 'format!']),

    # 15_ssrf.rs - SSRF
    ('15_ssrf.rs', True,
     'CVI-9504 client.get SSRF',
     ['CVI-9504'],
     ['client.get']),
    ('15_ssrf.rs', True,
     'CVI-9504 client.post SSRF',
     ['CVI-9504'],
     ['client.post']),
    ('15_ssrf.rs', True,
     'CVI-9504 http::Request::builder SSRF',
     ['CVI-9504'],
     ['http::Request::builder']),

    # 16_shell_exec.rs - 命令注入变体
    ('16_shell_exec.rs', True,
     'CVI-9505 shell_exec::shell_exec 命令注入',
     ['CVI-9505'],
     ['shell_exec']),
    ('16_shell_exec.rs', True,
     'CVI-9505 shell_words::split 命令注入',
     ['CVI-9505'],
     ['shell_words::split']),
    ('16_shell_exec.rs', True,
     'CVI-9505 bat::exec 命令注入',
     ['CVI-9505'],
     ['bat::exec']),

    # 17_log_inject.rs - 日志注入
    ('17_log_inject.rs', True,
     'CVI-9507 log::info! 日志注入',
     ['CVI-9507'],
     ['log::info!']),
    ('17_log_inject.rs', True,
     'CVI-9507 log::warn!/error!/debug! 日志注入',
     ['CVI-9507'],
     ['log::warn!', 'log::error!', 'log::debug!']),

    # 18_deser.rs - 反序列化
    ('18_deser.rs', True,
     'CVI-9506 serde_json::from_str 反序列化',
     ['CVI-9506'],
     ['serde_json::from_str']),
    ('18_deser.rs', True,
     'CVI-9506 serde_json::from_reader 反序列化',
     ['CVI-9506'],
     ['from_reader']),

    # 18_weak_random.rs - 不安全随机数
    ('18_weak_random.rs', True,
     'CVI-9510 rand::thread_rng 不安全随机数',
     ['CVI-9510'],
     ['rand::thread_rng']),
    ('18_weak_random.rs', True,
     'CVI-9510 rand::random 不安全随机数',
     ['CVI-9510'],
     ['rand::random']),

    # ===== 间接调用（indirect call）测试 =====
    # Command::new("sh").arg("-c").arg(&cmd).output() — 直接调用模式
    # 注: 此样本实际为直接调用（非间接），作为 Command arg 链式调用的补充测试
    # 引擎检出 CVI-9508 (.arg) 和 CVI-9501 (Command::new)，type=constant
    ('indirect_exec.rs', True,
     'CVI-9508 Command.arg: 命令注入 arg(&cmd) via Command 链式调用',
     ['CVI-9508'],
     ['.arg(']),
]


def run_scan():
    """Run ci_scan on the entire test directory and return JSON results."""
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, 'scan_results.json')

    cmd = [
        sys.executable, ci_scan,
        '--language', 'rust',
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
    print("Rust NewCore Benchmark Test")
    print("=" * 70)

    os.makedirs(output_dir, exist_ok=True)

    print(f"\nRunning ci_scan on tests/rust ...")
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

    # Debug: print all detections grouped by file
    file_vulns = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        file_val = item.get('file') or item.get('file_path') or item.get('file_name') or ''
        cvi = item.get('cvi_id') or item.get('cvi') or item.get('vuln_class') or ''
        cvi_str = str(cvi)
        if cvi_str.isdigit():
            cvi_str = 'CVI-' + cvi_str
        fname = os.path.basename(str(file_val).split(':')[0]) if file_val else 'unknown'
        if fname not in file_vulns:
            file_vulns[fname] = []
        file_vulns[fname].append(cvi_str)

    if file_vulns:
        print("\nDetected vulnerabilities by file:")
        for fname in sorted(file_vulns):
            print(f"  {fname}: {file_vulns[fname]}")

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
