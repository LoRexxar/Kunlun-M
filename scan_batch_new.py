#!/usr/bin/env python3
import json, subprocess, os, sys, shutil, time

KDIR = '/home/ubuntu/.hermes/hermes-agent/Kunlun-M'
VENV = '/home/ubuntu/Kunlun-M-venv'
DLDIR = '/home/ubuntu/realworld_scan_redownload'
PROXIES = ['https://ghfast.top', 'https://ghproxy.net']
LOG = '/tmp/batch_new_scan.log'

os.makedirs(DLDIR, exist_ok=True)

with open(LOG, 'w') as _: pass  # clear log

with open(LOG, 'a') as logf:
    def log(msg):
        print(msg)
        logf.write(msg + '\n')
        logf.flush()

    with open('/tmp/batch_new.json') as f:
        projects = json.load(f)

    total = ok = fail_dl = fail_scan = skip = 0

    for p in projects:
        repo = p['repo']
        branch = p['branch']
        lang = p['lang']
        task_name = p['task_name']
        stars = p.get('stars', 0)
        note = p.get('note', '')

        if stars > 80000:
            log(f'[SKIP-LARGE] {repo} ({stars} stars)')
            skip += 1
            continue
        if 'skip if timeout' in note:
            log(f'[SKIP-KNOWN] {repo}')
            skip += 1
            continue

        target = os.path.join(DLDIR, task_name)
        if os.path.exists(target):
            shutil.rmtree(target)
        os.makedirs(target, exist_ok=True)

        # Download
        dl_ok = False
        tar_path = f'/tmp/{task_name}.tar.gz'
        for proxy in PROXIES:
            url = f'{proxy}/https://github.com/{repo}/archive/{branch}.tar.gz'
            r = subprocess.run(['curl', '-sL', '--connect-timeout', '10', '--max-time', '120', url, '-o', tar_path], capture_output=True, timeout=180)
            if r.returncode == 0 and os.path.exists(tar_path) and os.path.getsize(tar_path) > 1000:
                dl_ok = True
                break
            time.sleep(1)

        if not dl_ok:
            log(f'[FAIL-DL] {repo}')
            fail_dl += 1
            for p2 in [tar_path, target]:
                if os.path.exists(p2):
                    shutil.rmtree(p2) if os.path.isdir(p2) else os.remove(p2)
            continue

        # Extract
        r = subprocess.run(['tar', 'xzf', tar_path, '-C', target, '--strip-components=1'], capture_output=True, timeout=120)
        if os.path.exists(tar_path): os.remove(tar_path)
        if r.returncode != 0:
            log(f'[FAIL-EXTRACT] {repo}')
            fail_dl += 1
            shutil.rmtree(target, ignore_errors=True)
            continue

        # Count files
        file_count = sum(1 for _ in os.walk(target) for __ in _[2])
        if file_count > 3000:
            log(f'[SKIP-TOO-BIG] {repo} ({file_count} files)')
            shutil.rmtree(target, ignore_errors=True)
            skip += 1
            continue

        log(f'[SCAN] {repo} ({file_count} files, lang={lang})')
        timeout = 3600 if file_count > 1500 else 1800

        scan_cmd = [f'{VENV}/bin/python3', f'{KDIR}/kunlun.py', 'scan', '-t', target, '--yes', '-lan', lang, '--no-cache']
        try:
            r = subprocess.run(scan_cmd, capture_output=True, timeout=timeout, cwd=KDIR)
            if r.returncode == 0:
                log(f'  [OK]')
                ok += 1
            else:
                log(f'  [FAIL] exit={r.returncode}')
                fail_scan += 1
        except subprocess.TimeoutExpired:
            log(f'  [TIMEOUT] {timeout}s')
            fail_scan += 1
        except Exception as e:
            log(f'  [ERROR] {e}')
            fail_scan += 1

        shutil.rmtree(target, ignore_errors=True)
        total += 1
        log(f'  Progress: {total} done, {ok} ok, {fail_dl} dl-fail, {fail_scan} scan-fail, {skip} skipped')
        log('---')

    log(f'')
    log(f'=== FINAL: {total} total, {ok} ok, {fail_dl} dl-fail, {fail_scan} scan-fail, {skip} skipped ===')
