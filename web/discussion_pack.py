# -*- coding: utf-8 -*-
"""复盘讨论件生成器：经验沉淀为人类可讨论的显式文档，全量存 DB（不落 git/磁盘）。

三类讨论件：lessons（判定经验教训）/ engine（引擎缺陷清单）/ log（裁决台账）。
generate_all() 幂等：每次调用生成新版本（带 created_at），历史版本保留可对照口径演进。
"""
from collections import Counter, defaultdict

from django.db.models import F
from django.utils import timezone

from web.index.models import ScanResultTask, TaintChain, Rules, DiscussionDoc


def _chain_mismatch(v):
    """AI 判 fp 且理由称链不匹配时，用存储链独立核实。True=实锤错配。"""
    r = v.ai_reasoning or ''
    if not ('不匹配' in r or '不符' in r or '未流' in r or '未到达' in r or '脱节' in r):
        return None
    chains = TaintChain.objects.filter(vul_result=v.id)
    if not chains.exists():
        return None
    vf = (v.vulfile_path or '').split(':')[0].split('/')[-1]
    cfs = set((c.file_path or '').split('/')[-1] for c in chains)
    return vf not in cfs


def _tag_desc(tag):
    return {
        'sanitizer': '存在净化/转义函数，污点被清洗',
        'double-arg-safe': 'API 带安全参数（如 parse_str 第二参、print_r true）',
        'var-rebind': '变量被 foreach/赋值重绑定，源头已换',
        'var-shadow': '同名变量遮蔽，链的源头不是声明的源',
        'unreachable': '代码路径不可达（die/exit 后、死代码）',
        'cli-only': '仅 CLI 上下文可达，HTTP 攻击面不成立',
        'parse_str': 'parse_str 用法安全',
        'urlencode-safe': 'urlencode 后拼接，特殊字符被编码',
        'cast': '强制类型转换截断污点',
        'whitelist': '白名单校验约束取值',
        'print_r-true': 'print_r 第二参 true 仅返回不输出',
        'const-src': '来源是常量而非用户输入',
        'no-filter': '全程无任何过滤，污点直达 sink',
        'direct-concat': '用户输入直接拼进危险函数',
        'unverified': '外部输入未经验证即使用',
        'controlled': '攻击者完全可控的关键参数',
        'passthrough': '中间层原样传递无净化',
    }.get(tag, '')


_KW_FP = [('净化函数', 'sanitizer'), ('第二参', 'double-arg-safe'), ('重绑定', 'var-rebind'),
          ('遮蔽', 'var-shadow'), ('不可达', 'unreachable'), ('CLI', 'cli-only'),
          ('parse_str', 'parse_str'), ('urlencode', 'urlencode-safe'), ('intval', 'cast'),
          ('白名单', 'whitelist'), ('print_r', 'print_r-true'), ('常量', 'const-src')]
_KW_TP = [('无过滤', 'no-filter'), ('直接拼接', 'direct-concat'), ('未验证', 'unverified'),
          ('可控', 'controlled'), ('原样', 'passthrough')]

_OPEN_QUESTIONS = [
    ('demo/示例代码算不算攻击面',
     '微信 sample 的 checkSignature 被人工判 FP（签名守卫不可伪造），AI 判 TP（访问控制非净化）。'
     '需要明确：第三方 SDK 的示例路由是否默认排除。'),
    ('老项目批量豁免是否持续有效',
     '"old CMS no filtering" 类项目级批量 TP 覆盖了引擎的链级判断，AI 复核发现其中部分链本身错配。'
     '项目级豁免应标注有效期/复核轮次。'),
    ('二阶注入算不算该规则的发现',
     '引擎把 SQL 注入链尾接到 unserialize sink，人工口径是"二阶需要额外前提，不算本规则的直接发现"。'
     'AI 已跟随此口径，建议成文。'),
]


def _collect():
    labeled = list(ScanResultTask.objects.filter(is_active=1).exclude(
        verification_status='').exclude(verification_status__in=('TP', 'tp', 'stale')))
    with_note = [v for v in labeled if len((v.verification_notes or '').strip()) > 20]
    rule_name = {r.svid: r.rule_name for r in Rules.objects.all().only('svid', 'rule_name')}
    return labeled, with_note, rule_name


def build_lessons(labeled, with_note, rule_name):
    by_rule = defaultdict(list)
    for v in with_note:
        by_rule[v.cvi_id].append(v)
    fp_pat, tp_pat = Counter(), Counter()
    for v in with_note:
        note = v.verification_notes or ''
        is_fp = v.verification_status.lower() == 'fp'
        for kw, tag in (_KW_FP if is_fp else _KW_TP):
            if kw in note:
                (fp_pat if is_fp else tp_pat)[tag] += 1

    out = ['# 判定经验教训', '',
           '> 本文档由审计数据自动汇总，供团队定期复盘讨论、修订后作为下一阶段的判定标准。',
           '> 数据基线：%d 条人工判定（其中 %d 条含实质备注）。' % (len(labeled), len(with_note)), '',
           '## 一、FP 高频判定模式', '', '| 模式 | 次数 | 含义 |', '|---|---|---|']
    for tag, n in fp_pat.most_common():
        out.append('| %s | %d | %s |' % (tag, n, _tag_desc(tag)))
    out += ['', '## 二、TP 高频确认模式', '', '| 模式 | 次数 | 含义 |', '|---|---|---|']
    for tag, n in tp_pat.most_common():
        out.append('| %s | %d | %s |' % (tag, n, _tag_desc(tag)))
    out += ['', '## 三、待讨论的判定口径分歧', '',
            '以下口径在数据中出现过两种立场，建议复盘会上定标准：', '']
    for i, (q, detail) in enumerate(_OPEN_QUESTIONS, 1):
        out.append('%d. **%s**——%s' % (i, q, detail))
    out += ['', '## 四、规则级判定实录（备注最多 TOP5）', '']
    for svid, vs in sorted(by_rule.items(), key=lambda x: -len(x[1]))[:5]:
        out.append('### CVI-%s %s（%d 条备注）' % (svid, rule_name.get(svid, '?'), len(vs)))
        out.append('')
        for v in vs[:3]:
            verdict = 'TP' if v.verification_status.lower() == 'tp' else 'FP'
            out.append('- `%s` %s： %s' % (verdict, (v.vulfile_path or '')[:60], (v.verification_notes or '')[:160]))
        out.append('')
    return '\n'.join(out)


def build_engine(labeled, rule_name):
    engine_mismatch = []
    for v in ScanResultTask.objects.filter(verified_by='ai-adjudication'):
        if _chain_mismatch(v) is True:
            engine_mismatch.append(v)

    out = ['# 引擎缺陷清单', '',
           '> 给引擎侧的改进 backlog。每条都有可复现的证据锚点（vul id + 文件对照）。', '',
           '## 链-sink 错配（最高优先级，实锤 %d 例）' % len(engine_mismatch), '',
           '**现象**：报告的 sink 文件与传播链文件完全不同源——链在中途接到了另一个数据流上。', '',
           '| vul id | 规则 | sink 文件 | 链实际文件 |', '|---|---|---|---|']
    for v in engine_mismatch[:15]:
        chains = TaintChain.objects.filter(vul_result=v.id)
        cfs = '/'.join(sorted(set((c.file_path or '').split('/')[-1] for c in chains))[:2])
        out.append('| #%d | %s | %s | %s |' % (
            v.id, v.cvi_id, (v.vulfile_path or '').split('/')[-1].split(':')[0], cfs))
    if len(engine_mismatch) > 15:
        out.append('| …共 %d 例 | | | |' % len(engine_mismatch))
    out += ['',
            '**建议修复方向**：parameters_back 回溯时校验每步文件与 sink 文件同源（或同函数调用链），'
            '跨文件跳转必须经过明确的 include/require/call 边，否则剪链。', '',
            '## 规则级 FP 率（结论回馈引擎侧参考）', '',
            '| 规则 | 人工 FP 率 | 样本 | 说明 |', '|---|---|---|---|']
    stat = defaultdict(Counter)
    for v in labeled:
        stat[v.cvi_id][v.verification_status.lower()] += 1
    for svid, c in sorted(stat.items(), key=lambda x: -(x[1]['fp'] / max(1, sum(x[1].values())))):
        total = sum(c.values())
        out.append('| CVI-%s %s | %.0f%% | %d | %s |' % (
            svid, rule_name.get(svid, '?'), 100 * c['fp'] / total, total,
            '建议规则级复核/降噪' if c['fp'] and c['fp'] / total >= 0.8 else ''))
    return '\n'.join(out)


def build_log():
    from web.verdict_ledger import ledger_stats, pattern_verdict_mix
    from web.index.models import VerdictEvent
    ai_rej = list(ScanResultTask.objects.filter(verified_by='ai-adjudication'))
    keeps = [v for v in ScanResultTask.objects.filter(is_active=1)
             if (v.ai_reasoning or '').startswith('保留人工判定')]
    adopted_n = ScanResultTask.objects.filter(verified_by='precedent-adoption').count()

    out = ['# 裁决台账', '', '> 本批所有非常规裁决的完整证据链。每条可独立复核。', '']

    st = ledger_stats()
    out += ['## ⓪ 判定账本全景', '',
            '- 事件总数：%d' % st['total_events'],
            '- 来源分布：%s' % st['by_source'],
            '- 经历多轮判定的漏洞：%d 条（每一条都值得复盘：是什么让人改变了判断）' % st['vuls_with_multiple_rounds'],
            '']

    from collections import Counter as _C
    pat_c = _C()
    for e in VerdictEvent.objects.filter(new_status__in=('tp', 'fp')).values('pattern_hash', 'cvi_id', 'new_status'):
        pat_c[(e['cvi_id'], e['pattern_hash'], e['new_status'])] += 1
    contested_list = []
    seen = set()
    for (cvi, pat, _v), _n in pat_c.most_common():
        if (cvi, pat) in seen or not pat:
            continue
        seen.add((cvi, pat))
        mix = pattern_verdict_mix(pat, cvi)
        if mix.get('status') == 'contested':
            contested_list.append((cvi, pat, mix))
    out += ['## ⓪-b 争议模式清单（少数派≥20%，互斥经验共存待裁决）', '']
    if contested_list:
        out += ['| 规则 | 模式 | 多数 | 少数 | 最近反方依据 |', '|---|---|---|---|---|']
        for cvi, pat, mix in contested_list[:10]:
            recent = (mix.get('recent_minor_events') or [{}])[0].get('notes', '')[:60]
            out.append('| CVI-%s | %s… | %s×%d | ×%d | %s |' % (
                cvi, pat[:10], (mix['major'] or '').upper(), mix['major_n'], mix['minor_n'], recent))
    else:
        out.append('- 当前无争议模式')
    out += ['']

    out += ['## A. 采信 AI 的改判（%d 条）' % len(ai_rej), '']
    for v in ai_rej:
        mm = _chain_mismatch(v)
        out.append('- **#%d** CVI-%s `%s`' % (v.id, v.cvi_id, (v.vulfile_path or '')[:70]))
        out.append('  - 判定：人工 tp → **fp**（%s）' % ('链错配实锤' if mm is True else 'AI 推理'))
        out.append('  - AI 理由：%s' % (v.ai_reasoning or '')[:180])
        if mm is True:
            cfs = '/'.join(sorted(set((c.file_path or '').split('/')[-1]
                                      for c in TaintChain.objects.filter(vul_result=v.id)))[:2])
            out.append('  - 独立核实：链文件 %s ≠ sink 文件 %s ✓' % (
                cfs, (v.vulfile_path or '').split('/')[-1].split(':')[0]))
        else:
            out.append('  - 独立核实：未独立核实')
    out += ['', '## B. 保留人工的裁决（%d 条，按原因分组）' % len(keeps), '']
    groups = Counter(((v.ai_reasoning or '').split('(')[1].split(')')[0]
                      if '(' in (v.ai_reasoning or '') else 'other') for v in keeps)
    for reason, n in groups.most_common():
        out.append('- %s 条：%s' % (n, reason))
    out += ['', '## C. 判例批量采纳（%d 条）' % adopted_n, '',
            '- 判例源头：同模式 ≥2 例人工一致判定（exact/module 级覆盖）', '']
    return '\n'.join(out)


def generate_all():
    """生成三类讨论件并写入 DB。返回 [(doc_type, title, doc_id)]。"""
    labeled, with_note, rule_name = _collect()
    baseline = '%d 条人工判定 / %d 条含备注' % (len(labeled), len(with_note))
    now = timezone.now().strftime('%Y-%m-%d %H:%M')
    made = []
    for dtype, title, content in (
        ('lessons', '判定经验教训 %s' % now, build_lessons(labeled, with_note, rule_name)),
        ('engine', '引擎缺陷清单 %s' % now, build_engine(labeled, rule_name)),
        ('log', '裁决台账 %s' % now, build_log()),
    ):
        d = DiscussionDoc.objects.create(doc_type=dtype, title=title,
                                         content_md=content, data_baseline=baseline)
        made.append((dtype, title, d.id))
    return made
