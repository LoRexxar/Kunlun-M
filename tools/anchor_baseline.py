#!/usr/bin/env python3
"""Anchor baseline runner — full-corpus ground-truth comparison (Fix 66).

Complements tools/ci_scan.py (mini-repros) with whole-project anchors:
each anchor is a real target from a past CVE campaign, its expected
findings frozen in ci_cases/anchor_baseline.json (per-task DB rows,
deduped set semantics). The runner re-scans each anchor (no cache) and
fails on ANY set difference — additions AND losses — so both false
regressions and silent recall drops are caught.

Usage:
  python tools/anchor_baseline.py            # all anchors
  python tools/anchor_baseline.py yeti       # single anchor

Requires corpus dirs on disk (see baseline 'target' fields) and a DB.
Rebaseline after a *deliberate* behavior change:
  python tools/anchor_baseline.py --regen    # rewrites the json from fresh scans
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / 'ci_cases' / 'anchor_baseline.json'


def query_rows(frag):
    """Latest task for target fragment -> deduped (cvi, loc) set."""
    import os
    import sys
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
    sys.path.insert(0, str(ROOT))
    import django
    django.setup()
    from web.index.models import ScanTask, ScanResultTask
    t = ScanTask.objects.filter(target_path__icontains=frag).latest('id')
    rows = set(ScanResultTask.objects.filter(scan_task_id=t.id).values_list('cvi_id', 'vulfile_path'))
    return t.id, rows


def run_anchor(name, cfg):
    log = f'/tmp/anchor_{name}.log'
    cmd = [sys.executable, 'kunlun.py', 'scan', '-t', cfg['target'],
           '--yes', '-lan', cfg['language'], '--no-cache']
    with open(log, 'w') as fh:
        r = subprocess.run(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT, timeout=1800)
    if r.returncode != 0:
        print(f'  [{name}] scan FAILED exit={r.returncode} (see {log})')
        return None
    task_id, rows = query_rows(name if name != 'azuracast-backend' else 'AzuraCast-0.23.8/backend')
    return task_id, rows


def main():
    regen = '--regen' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    data = json.loads(BASELINE.read_text())
    anchors = {k: v for k, v in data.items() if not k.startswith('_')}
    if args:
        anchors = {k: v for k, v in anchors.items() if k in args}

    new_baseline = {k: v for k, v in data.items() if k.startswith('_')}
    failures = []
    for name, cfg in anchors.items():
        target = Path(cfg['target'])
        if not target.exists():
            print(f'  [{name}] SKIP — corpus missing: {target}')
            continue
        res = run_anchor(name, cfg)
        if res is None:
            failures.append(name)
            continue
        task_id, rows = res
        got = {(str(c), str(p)) for c, p in rows}
        if regen:
            kept = {k: v for k, v in cfg.items() if k not in ('task_id', 'count', 'findings')}
            new_baseline[name] = {**kept, 'task_id': task_id, 'count': len(got),
                                  'findings': [{'cvi': c, 'loc': p} for c, p in sorted(got)]}
            print(f'  [{name}] regenerated: {len(got)} findings (task {task_id})')
            continue
        want = {(f['cvi'], f['loc']) for f in cfg['findings']}
        flaky = {p for p in cfg.get('known_flaky_locs', [])}
        added = {x for x in got - want if x[1] not in flaky}
        lost = {x for x in want - got if x[1] not in flaky}
        flaky_seen = {x for x in (got ^ want) if x[1] in flaky}
        if added or lost:
            failures.append(name)
            print(f'  [{name}] FAIL — task {task_id}: +{len(added)} / -{len(lost)}')
            for c, p in sorted(added)[:5]:
                print(f'      + {c} {p}')
            for c, p in sorted(lost)[:5]:
                print(f'      - {c} {p}')
        else:
            extra = f' ({len(flaky_seen)} known-flaky flips tolerated)' if flaky_seen else ''
            print(f'  [{name}] PASS — {len(got)} findings exact (task {task_id}){extra}')
    if regen:
        BASELINE.write_text(json.dumps(new_baseline, indent=1, ensure_ascii=False))
        print('baseline rewritten.')
        return 0
    if failures:
        print(f'ANCHOR BASELINE FAIL: {failures}')
        return 1
    print('ANCHOR BASELINE PASS: all anchors exact')
    return 0


if __name__ == '__main__':
    sys.exit(main())
