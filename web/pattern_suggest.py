# -*- coding: utf-8 -*-
"""模式判例建议（P3）：基于人工判定历史给未判定漏洞生成"同类判例"建议。

三级匹配（由强到弱）：
  exact  — 同规则 + 同源码模式指纹，≥2 条人工结论完全一致
  module — 同规则 + 同源码模式 + 同模块目录（前两级路径），≥2 条一致
  rule   — 同规则整体结论倾向（样本 ≥10 且一致率 ≥90%）

只读、不落库：suggestion 不写 verification_status，仅供界面展示与一键采纳。
"""
import hashlib
import re
from collections import Counter, defaultdict

from web.index.models import ScanResultTask

_STALE = ('TP', 'tp', 'stale')


def _norm_pattern(code):
    """源码模式指纹：变量名/字面量/数字/空白归一。"""
    c = re.sub(r"'[^']*'|\"[^\"]*\"", 'STR', code or '')
    c = re.sub(r'\$\w+', '$V', c)
    c = re.sub(r'\b\d+\b', 'N', c)
    c = re.sub(r'\s+', ' ', c).strip()
    return hashlib.md5(c.encode()).hexdigest()


def _module_of(path):
    parts = (path or '').split('/')
    return '/'.join(parts[:2])


def build_suggestion_index():
    """一次扫描人工判定库，返回 {key: {verdict, n}} 两级索引 + 规则级倾向。"""
    exact = {}
    module = {}
    rule_stat = defaultdict(Counter)
    qs = (ScanResultTask.objects.filter(is_active=1)
          .exclude(verification_status='')
          .exclude(verification_status__in=_STALE)
          .values('cvi_id', 'source_code', 'vulfile_path', 'verification_status'))
    for v in qs:
        verdict = v['verification_status'].lower()
        if verdict not in ('tp', 'fp'):
            continue
        rule_stat[v['cvi_id']][verdict] += 1
        pat = _norm_pattern(v['source_code'])
        k1 = (v['cvi_id'], pat)
        exact.setdefault(k1, Counter())[verdict] += 1
        k2 = (v['cvi_id'], pat, _module_of(v['vulfile_path']))
        module.setdefault(k2, Counter())[verdict] += 1

    def _consistent(store, min_n=2):
        out = {}
        for k, c in store.items():
            verdict, n = c.most_common(1)[0]
            if n >= min_n:
                out[k] = {'verdict': verdict, 'n': n}
        return out

    rule_tilt = {}
    for svid, c in rule_stat.items():
        total = sum(c.values())
        if total >= 10:
            verdict, n = c.most_common(1)[0]
            if n * 10 >= total * 9:  # ≥90% 一致
                rule_tilt[svid] = {'verdict': verdict, 'n': total}

    return {
        'exact': _consistent(exact),
        'module': _consistent(module),
        'rule': rule_tilt,
    }


def suggest_for(v, index):
    """返回 suggestion dict 或 None。强→弱：exact > module > rule。"""
    pat = _norm_pattern(v.source_code)
    k1 = (v.cvi_id, pat)
    if k1 in index['exact']:
        d = index['exact'][k1]
        return {'level': 'exact', 'verdict': d['verdict'], 'n': d['n'],
                'reason': '同规则同代码模式已有 %d 例人工判定' % d['n']}
    k2 = (v.cvi_id, pat, _module_of(v.vulfile_path))
    if k2 in index['module']:
        d = index['module'][k2]
        return {'level': 'module', 'verdict': d['verdict'], 'n': d['n'],
                'reason': '同模块同模式已有 %d 例人工判定' % d['n']}
    if v.cvi_id in index['rule']:
        d = index['rule'][v.cvi_id]
        return {'level': 'rule', 'verdict': d['verdict'], 'n': d['n'],
                'reason': '该规则历史 %d 例人工判定 %s 占绝对多数' % (
                    d['n'], 'FP' if d['verdict'] == 'fp' else 'TP')}
    return None
