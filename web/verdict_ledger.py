# -*- coding: utf-8 -*-
"""判定事件账本：经验的本体层（append-only）。

原则：
- 每次判定 = 一条事件，永不 UPDATE/DELETE（撤销也是事件，不改历史）
- 当前状态是账本的投影（fold），派生视图（判例库/可信度/讨论件）可随时从账本重算
- 互斥结论以事件共存：判例冲突不被多数吞掉，而是显式暴露（contested 态）
"""
from collections import Counter, defaultdict

from django.utils import timezone

from web.index.models import ScanResultTask, VerdictEvent

# 参与经验提取的有效终态
_EFFECTIVE = ('tp', 'fp')


def record_event(vul_id, old_status, new_status, source, actor='',
                 notes='', vul=None):
    """写入一条判定事件。vul 传入可避免重复查询。"""
    if vul is None:
        vul = ScanResultTask.objects.filter(id=vul_id).first()
    from web.pattern_suggest import _norm_pattern
    pat = _norm_pattern(vul.source_code) if vul else ''
    return VerdictEvent.objects.create(
        vul_id=vul_id,
        old_status=old_status or '',
        new_status=new_status,
        source=source,
        actor=actor or '',
        notes=(notes or '')[:2000],
        cvi_id=vul.cvi_id if vul else '',
        scan_project_id=vul.scan_project_id if vul else 0,
        pattern_hash=pat,
    )


def genesis_backfill(batch_size=5000):
    """建账回填：把账本建立时已存在的判定状态补记为 genesis 事件（幂等）。"""
    have = set(VerdictEvent.objects.values_list('vul_id', flat=True))
    n = 0
    qs = (ScanResultTask.objects.filter(is_active=1)
          .exclude(verification_status='')
          .exclude(verification_status__in=('stale',)))
    for v in qs.iterator(chunk_size=batch_size):
        if v.id in have:
            continue
        # 回填来源：优先还原上一阶段批量操作的留痕
        if v.verified_by == 'ai-adjudication':
            src = 'ai-adjudication'
        elif v.verified_by == 'precedent-adoption':
            src = 'precedent-adoption'
        else:
            src = 'human'
        record_event(v.id, '', v.verification_status, src,
                     actor=v.verified_by or 'pre-ledger',
                     notes='genesis: 账本建立时的既有判定 %s' % (v.verification_notes or '')[:150],
                     vul=v)
        n += 1
    return n


def fold_status(vul_id):
    """回放某漏洞的账本得到当前态（校验投影一致性用）。"""
    evs = VerdictEvent.objects.filter(vul_id=vul_id).order_by('created_at')
    st = ''
    for e in evs:
        if e.source == 'undo':
            st = ''
        else:
            st = e.new_status
    return st


def pattern_verdict_mix(pattern_hash, cvi_id):
    """冲突感知的模式判例视图（核心：互斥结论共存，不被多数吞掉）。

    返回 {
      status: 'solid'|'contested'|'thin',
      major: 'fp', major_n: 49, minor_n: 5,
      recent_minor_events: [最近 3 条少数派事件（带依据）]
    }
    - solid:   n>=2 且少数派占比 <20%（或少数派为 0）
    - contested: n>=2 且少数派占比 >=20% —— 经验仍有效但需按项目上下文判
    - thin:    n<2 —— 不足为训
    """
    evs = VerdictEvent.objects.filter(
        pattern_hash=pattern_hash, cvi_id=cvi_id,
        new_status__in=_EFFECTIVE).order_by('-created_at')
    c = Counter(e.new_status for e in evs)
    total = sum(c.values())
    if total < 2:
        return {'status': 'thin', 'major': None, 'major_n': total, 'minor_n': 0,
                'recent_minor_events': []}
    verdict, major_n = c.most_common(1)[0]
    minor_n = total - major_n
    minor_v = 'fp' if verdict == 'tp' else 'tp'
    contested = minor_n * 5 >= total  # >=20%
    recent_minor = [
        {'vul_id': e.vul_id, 'actor': e.actor, 'notes': (e.notes or '')[:120],
         'at': e.created_at.strftime('%m-%d %H:%M')}
        for e in evs if e.new_status == minor_v][:3]
    return {
        'status': 'contested' if contested else 'solid',
        'major': verdict, 'major_n': major_n, 'minor_n': minor_n,
        'recent_minor_events': recent_minor,
    }


def ledger_stats():
    """账本全景（复盘用）。"""
    from django.db.models import Count
    total = VerdictEvent.objects.count()
    by_source = Counter(VerdictEvent.objects.values_list('source', flat=True))
    multi = (VerdictEvent.objects.values('vul_id')
             .annotate(n=Count('id')).filter(n__gt=1).count())
    return {'total_events': total, 'by_source': dict(by_source),
            'vuls_with_multiple_rounds': multi}
