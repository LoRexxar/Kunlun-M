#!/usr/bin/env python3
"""CVE mini-repro regression gate — structural fix item #3 (2026-11).

Six CVE campaigns kept rediscovering the same engine blind spots because
each fix's minimal repro lived in /tmp and vanished. This gate freezes
those repros under ci_cases/cve_regressions/ with their EXPECTED findings
and asserts them after every engine change — an accident becomes an
invariant.

Usage (from the Kunlun-M repo root, venv active):
    python3 ci_cases/run_cve_regressions.py

Each case declares: file → expected (rule, count) pairs. A scan of the
whole cve_regressions dir runs once; results are read back from the DB by
scan_task_id (CLI tail tables are cumulative and unusable for this).

Adding a case: copy the minimized repro here, scan once manually, record
the expected rows below, commit both. NEVER weaken an expectation to make
a failing engine pass — investigate instead.
"""
import os
import glob
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cve_regressions')

# file basename → {cvi_id: min_count}
EXPECTATIONS = {
    # Fix 55: top-level (file-scope) calls must produce cg edges so the
    # callee escapes the dead-code gate. Was 0 rows before Fix 55.
    'CVE-2026-121429_top_level_cg.php': {'1011': 1},
    # Fix 67: symfony 1.x form proxy — $form->bind($request->getParameter(...))
    # taints the form object; $form['x']->getValue() reads are sources.
    'CVE-2020-7246_sf1_form_unlink.php': {'1017': 1},
    # Fix 68: Java deserialization chain — request.getInputStream() → new
    # ObjectInputStream(...) → readObject(); and IIOP SkeletonStrategy
    # .readParams before auth (CVE-2026-15564, WildFly EjbCorbaServant).
    'CVE-2026-15564_iiop_readparams.java': {'6035': 1},
    # Fix 69: WP posts_where filter SQLi — $_REQUEST → WP_Query param →
    # $wp_query->get() source → $wpdb->esc_like() concat (CVE-2026-114189).
    'CVE-2026-114189_wp_posts_where.php': {'1006': 1},
    # Fix 70: sprintf SQL-literal-concat sentinel — craft.search term value
    # interpolated unescaped into '%s' (CVE-2026-115934 Craft CMS).
    'CVE-2026-115934_craft_sprintf_sql.php': {'1006': 1},
    # Fix 71: PDO generic DB layer — $_GET['id'] interpolated into
    # $dbh->query("... id=$id") (CVE-2026-93997 SourceCodester Drug
    # Recommendation System /Admin/edit_symptom.php). Safe contrast in the
    # same file (prepare+bound execute) must NOT fire.
    'CVE-2026-93997_pdo_query_sqli.php': {'1005': 1},
    # Fix 73: PHP include/require language-construct sinks (SuiteCRM,
    # CVE-2026-71550) — $_REQUEST['aow_action'] concat → require_once
    # dynamic file inclusion.  Both the custom/ and modules/ branches.
    'CVE-2026-71550_aow_require_once.php': {'1007': 2},
    # Fix 72: config-file source chain (Siemens meta-iot2050,
    # CVE-2026-109830) — json.load → getConfig summary → getter summary →
    # subprocess.call("... " + initMode, shell=True). Safe contrast
    # (argument-list reboot, no config input) must NOT fire.
    'board-bootup-conf.py': {'7000': 1},
    # Engine array-writeback fix (getSuggestion array item write-back):
    # taint must survive through array store → return → consumer.
    'CVE-2026-62007_array_writeback.php': {'1000': 1},
    # Fix 59: Slim route closures are framework dispatch entries (ast
    # in-edge), NOT dead code; $request->getQueryParams() is a source.
    # Blind before Fix 59 (dead-code gate + no slim framework config).
    'Fix59_slim_route_closure.php': {'1011': 1},
    # Fix 74: a repair verdict on ONE concat operand must not kill the
    # whole trace — dirname(__DIR__,2) judged repair, sprintf($iso) side
    # never visited.  $_SERVER['HTTP_ACCEPT_LANGUAGE'] → sprintf →
    # require (CVE-2026-41228, froxlor 2.3.5 Language.php RFI).
    'CVE-2026-41228_lang_accept_require.php': {'1007': 1},
    # Fix 75/76/76b/77 chain: php://input literal source → ApiParameter
    # ctor $this->prop store → getParam read bridge → new-site ctor arg →
    # file_put_contents path-literal-.php content traced (CVE-2026-41229,
    # froxlor API writes lib/userdata.inc.php).  3-file repro in
    # php-generic/ (helpers renamed to avoid bare-callee hijack).
    'CVE-2026-41229_froxlor_mysqlserver.php': {'1017': 1},
    # Fix 78 chain (CVE-2026-41478 Saltcorn sync.js): req.body →
    # ObjectPattern destructure → closure capture → for-of
    # ArrayPattern over Object.entries → helper call arg → param →
    # template literal → db.query.  Three GT sinks (L53/L80/L173).
    'sync.js': {'3104': 3},
    # Fix 79 (CVE-2026-32613 Spinnaker echo SpEL RCE): user-authored
    # pipeline expectedArtifacts (TYPE-qualified source
    # Pipeline.getExpectedArtifacts) → null-check weak re-assign →
    # enhanced-for loop var → ExpressionTransform.transformMap →
    # parser.parseExpression under unrestricted StandardEvaluationContext.
    'ExpressionTransform.java': {'6012': 1},
}


def main() -> int:
    # sys.path[0] is the script's dir (ci_cases/), not the repo root —
    # django needs the repo root importable for Kunlun_M.settings.
    if REPO not in sys.path:
        sys.path.insert(0, REPO)
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
    import django
    django.setup()
    from web.index.models import ScanTask, ScanResultTask

    def _case_exists(fname: str) -> bool:
        if os.path.exists(os.path.join(CASES_DIR, fname)):
            return True
        # Fix 67: framework-scoped subdirs
        for d in os.listdir(CASES_DIR):
            sub = os.path.join(CASES_DIR, d, fname)
            if os.path.isdir(os.path.join(CASES_DIR, d)) and os.path.exists(sub):
                return True
        # Fix 78: deep repro trees (nodejs/CVE-…/packages/server/routes/)
        if glob.glob(os.path.join(CASES_DIR, '**', fname), recursive=True):
            return True
        return False

    missing = [f for f in EXPECTATIONS if not _case_exists(f)]
    if missing:
        print('GATE FAIL: expectation references missing case files:', missing)
        return 2

    # Fix 67: framework-scoped repros live in framework subdirectories
    # (e.g. symfony1/ carries its own core/lib/symfony marker so
    # detect_framework resolves per-subdir, not per-mixed-root).  Scan the
    # root (framework-agnostic repros) plus each framework subdir.
    scan_dirs = [CASES_DIR] + sorted(
        os.path.join(CASES_DIR, d) for d in os.listdir(CASES_DIR)
        if os.path.isdir(os.path.join(CASES_DIR, d)) and not d.startswith(('.'))
    )
    env = dict(os.environ, PYTHONPATH=REPO)
    task_ids = []
    for scan_dir in scan_dirs:
        print(f'[cve-repro-gate] scanning {scan_dir} ...')
        # Fix 68: repros span languages (php root + java repros) — scan all
        # languages so java cases enter the graph; php-file semantics are
        # unchanged (their rules are php-scoped).  Root dir only; framework
        # subdirs (symfony1/) stay php-scoped as before.
        _lang68 = 'all' if scan_dir == CASES_DIR else 'php'
        # Fix 72: python repro subdirs (iot2050 config-file chain) scan as
        # python — the php default silently skipped them and the gate read 0.
        if scan_dir != CASES_DIR and glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True):
            _lang68 = 'python'
        # Fix 78 (CVE-2026-41478): nodejs repro subdir scans as js — same
        # silent-skip trap as python above (php default → 0 rows → the
        # saltcorn expectation would read as an engine regression).
        if (scan_dir != CASES_DIR
                and not glob.glob(os.path.join(scan_dir, '**', '*.php'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True)
                and glob.glob(os.path.join(scan_dir, '**', '*.js'), recursive=True)):
            _lang68 = 'js'
        # Fix 79 (CVE-2026-32613): java repro subdir scans as 'all' — the
        # php default silently skips .java files (same trap as python/js
        # above).  'all' keeps the root-scan semantics for the subdir.
        if (scan_dir != CASES_DIR
                and not glob.glob(os.path.join(scan_dir, '**', '*.php'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.py'), recursive=True)
                and not glob.glob(os.path.join(scan_dir, '**', '*.js'), recursive=True)
                and glob.glob(os.path.join(scan_dir, '**', '*.java'), recursive=True)):
            _lang68 = 'all'
        proc = subprocess.run(
            [sys.executable, os.path.join(REPO, 'kunlun.py'), 'scan',
             '-t', scan_dir, '--yes', '-lan', _lang68, '--no-cache'],
            cwd=REPO, capture_output=True, text=True, env=env, timeout=900)
        m = None
        for line in (proc.stdout + '\n' + proc.stderr).splitlines():
            if 'TaskID' in line:
                m = line.split('TaskID:')[1].strip().split()[0]
                m = m.replace('\x1b[0m', '').strip()
        if not m:
            print('GATE FAIL: could not read TaskID from scan output for', scan_dir)
            print(proc.stdout[-800:], proc.stderr[-400:])
            return 2
        task_ids.append(int(m))

    by_file = {}
    for task_id in task_ids:
        for r in ScanResultTask.objects.filter(scan_task_id=task_id):
            # vulfile_path may be stored relative AND suffixed ':lineno'
            # (e.g. 'CVE-...php:17') — strip both before basename matching.
            base = os.path.basename(str(r.vulfile_path).split(':')[0])
            by_file.setdefault(base, {}).setdefault(str(r.cvi_id), 0)
            by_file[base][str(r.cvi_id)] += 1

    failures = []
    for fname, expect in sorted(EXPECTATIONS.items()):
        got = by_file.get(fname, {})
        for cvi, want in sorted(expect.items()):
            have = got.get(cvi, 0)
            status = 'ok' if have >= want else 'FAIL'
            print(f'  [{status}] {fname}: CVI {cvi} expected>={want} got {have}')
            if have < want:
                failures.append(f'{fname}:{cvi}')
    if failures:
        print(f'GATE FAIL: {len(failures)} expectation(s) not met: {failures}')
        print('→ investigate the engine change; do NOT lower the expectation')
        return 1
    print('GATE PASS: all CVE mini-repro expectations met')
    return 0


if __name__ == '__main__':
    sys.exit(main())
