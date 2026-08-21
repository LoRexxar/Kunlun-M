import argparse
import importlib
import json
import os
import sys
import time
import traceback


_repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


def _severity_rank(name):
    order = {
        'none': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4,
    }
    return order.get((name or '').lower().strip(), 0)


def _safe_makedirs(p):
    if not p:
        return
    os.makedirs(p, exist_ok=True)


def _coerce_bool(v):
    if isinstance(v, bool):
        return v
    s = (v or '').strip().lower()
    return s in ('1', 'true', 'yes', 'y', 'on')


def _load_rule_meta():
    meta = {}
    rules_root = os.path.join(_repo_root, 'rules')
    if not os.path.isdir(rules_root):
        return meta

    for lan in os.listdir(rules_root):
        lan_path = os.path.join(rules_root, lan)
        if not os.path.isdir(lan_path):
            continue
        if lan in ('tamper', 'test'):
            continue
        for fn in os.listdir(lan_path):
            if not (fn.startswith('CVI_') and fn.endswith('.py')):
                continue
            mod_name = 'rules.{lan}.{name}'.format(lan=lan, name=fn[:-3])
            try:
                mod = importlib.import_module(mod_name)
                cls = getattr(mod, fn[:-3])
                inst = cls()
                svid = str(getattr(inst, 'svid', '')).strip()
                if not svid:
                    continue
                meta[svid] = {
                    'rule_name': getattr(inst, 'vulnerability', '') or getattr(inst, 'rule_name', '') or fn[:-3],
                    'level': int(getattr(inst, 'level', 1)),
                    'language': getattr(inst, 'language', lan),
                }
            except Exception:
                continue
    return meta


def _iter_rule_files():
    rules_root = os.path.join(_repo_root, 'rules')
    if not os.path.isdir(rules_root):
        return
    for root, _dirs, files in os.walk(rules_root):
        for fn in files:
            if fn.startswith('CVI_') and fn.endswith('.py'):
                yield os.path.join(root, fn)


def _ensure_rules_present():
    for _ in _iter_rule_files():
        return
    raise RuntimeError('no rules found under rules/**/CVI_*.py')


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', default='.', help='scan target path')
    parser.add_argument('--output', default='artifacts/kunlun-ci.json', help='output report file')
    parser.add_argument('--fail-on', default=os.environ.get('KUNLUN_FAIL_ON', 'none'), help='none|low|medium|high|critical')
    parser.add_argument('--include-unconfirm', action='store_true', default=_coerce_bool(os.environ.get('KUNLUN_INCLUDE_UNCONFIRM', '0')))
    parser.add_argument('--with-vendor', action='store_true', default=_coerce_bool(os.environ.get('KUNLUN_WITH_VENDOR', '0')))
    parser.add_argument('--without-vendor', action='store_true', default=False)
    parser.add_argument('--rule', dest='special_rules', default=None)
    parser.add_argument('--language', default=None)
    parser.add_argument('--blackpath', dest='black_path', default=None)
    parser.add_argument('--tamper', dest='tamper_name', default=None)
    parser.add_argument('--unprecom', action='store_true', default=False)
    parser.add_argument('--settings-module', default=os.environ.get('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings_ci'))
    args = parser.parse_args(argv)

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', args.settings_module)

    # 将 Kunlun logger 输出到 stdout，方便 CI 查看完整扫描日志
    import logging
    _ci_handler = logging.StreamHandler(sys.stdout)
    _ci_handler.setLevel(logging.DEBUG)
    _ci_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))

    try:
        m = importlib.import_module(args.settings_module)
        sys.modules['Kunlun_M.settings'] = m
    except Exception:
        pass

    try:
        args.output = os.path.abspath(args.output)
        if not args.target or not str(args.target).strip():
            raise ValueError('target is empty')
        if not os.path.exists(args.target):
            raise FileNotFoundError('target not found: {t}'.format(t=args.target))
        _ensure_rules_present()

        import django
        django.setup()
        from django.core.management import call_command

        # 挂 CI stdout handler 到 KunlunLog，输出完整扫描日志
        logging.getLogger('KunlunLog').addHandler(_ci_handler)

        call_command('migrate', interactive=False, verbosity=0, run_syncdb=True)

        import Kunlun_M.settings as settings
        settings.WITH_VENDOR = bool(args.with_vendor) and (not args.without_vendor)

        from django.utils import timezone
        from web.index.models import ScanTask, Rules, VendorVulns, get_and_check_scantask_project_id, get_and_check_scanresult
        from core import cli as core_cli
        from Kunlun_M.const import VUL_LEVEL, VENDOR_VUL_LEVEL

        target = args.target
        target = os.path.abspath(target)  # 立即转绝对路径，防止扫描引擎改变 cwd 后失效
        started_at = time.time()
        rule_meta = _load_rule_meta()

        task_name = 'ci_' + str(int(started_at)) + '_' + str(os.getpid())
        parameter_config = {
            'argv': sys.argv,
            'fail_on': args.fail_on,
            'include_unconfirm': bool(args.include_unconfirm),
            'with_vendor': bool(settings.WITH_VENDOR),
        }
        s = ScanTask(task_name=task_name, target_path=target, parameter_config=json.dumps(parameter_config, ensure_ascii=False))
        s.last_scan_time = timezone.now()
        s.is_finished = 2
        s.started_at = timezone.now()
        s.finished_at = None
        s.exit_code = None
        s.error_message = None
        s.save()

        from core.engine import Running
        Running(str(s.id)).status({'status': 'running', 'report': ''})

        try:
            # CI must scan all languages in target, not just the primary one.
            # When --language is not specified, use 'all' to detect and scan
            # every language found (expected.json contains multi-lang vulns).
            scan_lang = args.language if args.language else 'all'
            core_cli.start(
                target,
                'json',
                '',
                args.special_rules,
                str(s.id),
                scan_lang,
                args.tamper_name,
                args.black_path,
                bool(args.include_unconfirm),
                bool(args.unprecom),
                None,   # template_path
                True,   # no_cache — always rebuild graph in CI
            )
        except Exception as e:
            s.is_finished = 0
            s.finished_at = timezone.now()
            s.exit_code = 1
            s.error_message = str(e)[:2000]
            s.save()
            raise

        s.is_finished = 1
        s.finished_at = timezone.now()
        s.exit_code = 0
        s.save()

        project_id = get_and_check_scantask_project_id(s.id)
        qs = get_and_check_scanresult(s.id).objects.filter(scan_project_id=project_id, is_active=True)
        if not args.include_unconfirm:
            qs = qs.filter(is_unconfirm=False)
        results = list(qs)

        vul_list = []
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        max_sev = 'none'
        max_rank = 0

        for sr in results:
            sev = 'low'
            rule_name = 'Unknown Rule'

            if str(sr.cvi_id) == '9999':
                try:
                    vendor_vuls_id = int(str(sr.vulfile_path).split(':')[-1])
                except Exception:
                    vendor_vuls_id = None
                if vendor_vuls_id:
                    vv = VendorVulns.objects.filter(id=vendor_vuls_id).first()
                else:
                    vv = None
                if vv:
                    rule_name = vv.title
                    sev = VENDOR_VUL_LEVEL[int(vv.severity)]
                else:
                    rule_name = 'SCA Scan'
                    sev = VENDOR_VUL_LEVEL[1]
            else:
                rm = rule_meta.get(str(sr.cvi_id))
                if rm:
                    rule_name = rm.get('rule_name') or rule_name
                    sev = VUL_LEVEL[int(rm.get('level', 1))]
                else:
                    rule = Rules.objects.filter(svid=sr.cvi_id).first()
                    if rule:
                        rule_name = rule.rule_name
                        sev = VUL_LEVEL[int(rule.level)]
                    else:
                        sev = VUL_LEVEL[1]

            rnk = _severity_rank(sev)
            if rnk > max_rank:
                max_rank = rnk
                max_sev = sev
            if sev in counts:
                counts[sev] += 1

            vul_list.append({
                'id': sr.id,
                'cvi_id': sr.cvi_id,
                'rule_name': rule_name,
                'severity': sev,
                'language': sr.language,
                'file': sr.vulfile_path,
                'is_unconfirm': bool(sr.is_unconfirm),
                'result_type': sr.result_type,
                'source_code': sr.source_code,
            })

        # 检查 target 下是否存在 expected.json，优先使用对比逻辑
        expected_path = os.path.join(target, 'expected.json') if os.path.isdir(target) else None
        expected_data = None
        if expected_path and os.path.isfile(expected_path):
            try:
                with open(expected_path, 'r', encoding='utf-8') as ef:
                    expected_data = json.load(ef)
            except Exception:
                expected_data = None

        exit_code = 0
        reason = 'ok'

        if expected_data and isinstance(expected_data.get('expected'), list):
            # 对比模式：实际结果 vs expected.json
            expected_list = expected_data['expected']
            # 提取实际检出中 file 的 basename 用于匹配（去掉 :行号 后缀）
            actual_set = set()
            for v in vul_list:
                actual_file = os.path.basename(v.get('file', '')).split(':')[0]
                actual_set.add((actual_file, str(v.get('cvi_id', ''))))

            missing = []
            for exp in expected_list:
                exp_file = os.path.basename(exp.get('file', '')).split(':')[0]
                exp_cvi = str(exp.get('cvi_id', ''))
                if (exp_file, exp_cvi) not in actual_set:
                    missing.append(exp)

            unexpected = []
            expected_set = set()
            for exp in expected_list:
                expected_set.add((os.path.basename(exp.get('file', '')).split(':')[0], str(exp.get('cvi_id', ''))))
            for v in vul_list:
                actual_file = os.path.basename(v.get('file', '')).split(':')[0]
                actual_cvi = str(v.get('cvi_id', ''))
                if (actual_file, actual_cvi) not in expected_set:
                    unexpected.append(v)

            if missing:
                exit_code = 1
                reason = 'expected_vulns_missing'

            # Check forbidden: expected-to-be-absent vulns that MUST NOT appear
            forbidden_list = expected_data.get('forbidden', [])
            forbidden_violations = []
            for fb in forbidden_list:
                fb_file = os.path.basename(fb.get('file', '')).split(':')[0]
                fb_cvi = str(fb.get('cvi_id', ''))
                if (fb_file, fb_cvi) in actual_set:
                    forbidden_violations.append(fb)
            if forbidden_violations:
                if exit_code == 0:
                    exit_code = 1
                    reason = 'forbidden_vuln_detected'
                else:
                    reason = reason + '+forbidden_vuln_detected'

            report = {
                'meta': {
                    'target': target,
                    'task_id': s.id,
                    'project_id': project_id,
                    'started_at': s.started_at.isoformat() if s.started_at else None,
                    'finished_at': s.finished_at.isoformat() if s.finished_at else None,
                    'fail_on': args.fail_on,
                    'include_unconfirm': bool(args.include_unconfirm),
                    'with_vendor': bool(settings.WITH_VENDOR),
                    'settings_module': args.settings_module,
                    'mode': 'expected_comparison',
                },
                'summary': {
                    'total': len(vul_list),
                    'by_severity': counts,
                    'max_severity': max_sev,
                    'expected_count': len(expected_list),
                    'missing_count': len(missing),
                    'unexpected_count': len(unexpected),
                    'forbidden_count': len(forbidden_violations),
                },
                'expected': expected_list,
                'missing': missing,
                'unexpected': unexpected,
                'forbidden': forbidden_violations,
                'vulnerabilities': vul_list,
                'exit': {
                    'code': exit_code,
                    'reason': reason,
                }
            }
        else:
            # 后备模式：无 expected.json，使用旧的 --fail-on 阈值逻辑
            fail_rank = _severity_rank(args.fail_on)
            if max_rank >= fail_rank and fail_rank > 0 and len(vul_list) > 0:
                exit_code = 2
                reason = 'threshold_reached'

            report = {
                'meta': {
                    'target': target,
                    'task_id': s.id,
                    'project_id': project_id,
                    'started_at': s.started_at.isoformat() if s.started_at else None,
                    'finished_at': s.finished_at.isoformat() if s.finished_at else None,
                    'fail_on': args.fail_on,
                    'include_unconfirm': bool(args.include_unconfirm),
                    'with_vendor': bool(settings.WITH_VENDOR),
                    'settings_module': args.settings_module,
                    'mode': 'threshold',
                },
                'summary': {
                    'total': len(vul_list),
                    'by_severity': counts,
                    'max_severity': max_sev,
                },
                'vulnerabilities': vul_list,
                'exit': {
                    'code': exit_code,
                    'reason': reason,
                }
            }

        out = args.output
        _safe_makedirs(os.path.dirname(out))
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        # 输出所有检出漏洞的详细信息（调试用）
        print('[CI] DEBUG: 检出漏洞列表:')
        for v in vul_list:
            print('  - file={} cvi={} lang={} unconfirm={} type={}'.format(
                v.get('file', '?'), v.get('cvi_id', '?'), v.get('language', '?'),
                v.get('is_unconfirm', '?'), v.get('result_type', '?')))

        # 输出对比结果摘要
        if expected_data and isinstance(expected_data.get('expected'), list):
            print('[CI] 对比模式：共检出 {} 个漏洞，预期 {} 个'.format(len(vul_list), len(expected_data['expected'])))
            if missing:
                print('[CI] MISSING: 以下预期漏洞未被检出:')
                for m in missing:
                    print('  - {} (CVI-{})'.format(m.get('file', '?'), m.get('cvi_id', '?')))
            else:
                print('[CI] 所有预期漏洞均已检出')
            if unexpected:
                print('[CI] INFO: 预期之外的额外检出 (不阻塞):')
                for u in unexpected:
                    print('  - {} (CVI-{}) [{}]'.format(
                        os.path.basename(u.get('file', '?')),
                        u.get('cvi_id', '?'),
                        u.get('severity', '?'),
                    ))
        else:
            if forbidden_violations:
                print('[CI] FORBIDDEN: 以下漏洞不应被检出 (sanitizer 误杀 or FP):')
                for fb in forbidden_violations:
                    print('  - {} (CVI-{}) reason={}'.format(
                        fb.get('file', '?'), fb.get('cvi_id', '?'),
                        fb.get('reason', 'N/A'),
                    ))
            print('[CI] 阈值模式：共检出 {} 个漏洞，最高严重级别: {}'.format(len(vul_list), max_sev))

        return exit_code
    except SystemExit:
        raise
    except Exception:
        out = args.output if 'args' in locals() else 'artifacts/kunlun-ci.json'
        _safe_makedirs(os.path.dirname(out))
        err = {
            'exit': {
                'code': 1,
                'reason': 'exception',
            },
            'error': traceback.format_exc(),
        }
        try:
            with open(out, 'w', encoding='utf-8') as f:
                json.dump(err, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
