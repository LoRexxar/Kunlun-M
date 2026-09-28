"""复盘讨论包生成器：把审计经验沉淀为人类可多次讨论的显式文档，而非 DB 里的隐式记忆。

产出三类讨论件（全部写入 web/reports/discussions/，git 可追踪、可 diff、可评审）：
1. verdict-lessons-YYYYMMDD.md  — 判定经验教训：本批裁决中的可复用判定规则（人类语言）
2. engine-issues-YYYYMMDD.md   — 引擎缺陷清单：链错配/误报模式，按修复价值排序（给引擎侧 backlog）
3. adjudication-log-YYYYMMDD.md — 裁决台账：每个改判的完整证据链（复核/追责用）
"""
import os, sys, django
from collections import Counter, defaultdict
from datetime import date

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')
django.setup()
from web.index.models import ScanResultTask, TaintChain, Rules
from django.db.models import F

OUT = '/home/ubuntu/.hermes/hermes-agent/Kunlun-M/web/reports/discussions'
os.makedirs(OUT, exist_ok=True)
today = date.today().isoformat()


def chain_mismatch(v):
    r = v.ai_reasoning or ''
    if not ('不匹配' in r or '不符' in r or '未流' in r or '未到达' in r or '脱节' in r):
        return None
    chains = TaintChain.objects.filter(vul_result=v.id)
    if not chains.exists():
        return None
    vf = (v.vulfile_path or '').split(':')[0].split('/')[-1]
    cfs = set((c.file_path or '').split('/')[-1] for c in chains)
    return vf not in cfs


def main():
    # ---------- 数据收集 ----------
    # A. 全部人工判定（含备注 = 经验载体）
    labeled = list(ScanResultTask.objects.filter(is_active=1).exclude(
        verification_status='').exclude(verification_status__in=('TP', 'tp', 'stale')))
    with_note = [v for v in labeled if len((v.verification_notes or '').strip()) > 20]
    by_rule_notes = defaultdict(list)
    for v in with_note:
        by_rule_notes[v.cvi_id].append(v)

    # B. 本批裁决痕迹
    ai_rej = list(ScanResultTask.objects.filter(verified_by='ai-adjudication'))
    keeps = [v for v in ScanResultTask.objects.filter(is_active=1)
             if (v.ai_reasoning or '').startswith('保留人工判定')]
    adopted = list(ScanResultTask.objects.filter(verified_by='precedent-adoption'))

    # C. 引擎错配实锤（独立核实过的）
    engine_mismatch = []
    for v in ai_rej:
        if chain_mismatch(v) is True:
            engine_mismatch.append(v)

    rule_name = {}
    for r in Rules.objects.all().only('svid', 'rule_name'):
        rule_name[r.svid] = r.rule_name

    # ---------- 1. 判定经验教训 ----------
    # 从备注中提炼高频判定模式（FP 理由 / TP 理由的归类）
    fp_patterns = Counter()
    tp_patterns = Counter()
    KW_FP = [('净化函数', 'sanitizer'), ('第二参', 'double-arg-safe'), ('重绑定', 'var-rebind'),
             ('遮蔽', 'var-shadow'), ('不可达', 'unreachable'), ('CLI', 'cli-only'),
             ('parse_str', 'parse_str'), ('urlencode', 'urlencode-safe'), ('intval', 'cast'),
             ('白名单', 'whitelist'), ('print_r', 'print_r-true'), ('常量', 'const-src')]
    KW_TP = [('无过滤', 'no-filter'), ('直接拼接', 'direct-concat'), ('未验证', 'unverified'),
             ('可控', 'controlled'), ('原样', 'passthrough')]
    for v in with_note:
        note = v.verification_notes or ''
        is_fp = v.verification_status.lower() == 'fp'
        for kw, tag in (KW_FP if is_fp else KW_TP):
            if kw in note:
                (fp_patterns if is_fp else tp_patterns)[tag] += 1

    lessons = []
    lessons.append('# 判定经验教训（%s）' % today)
    lessons.append('')
    lessons.append('> 产物性质：本文件由审计数据自动汇总，供团队定期复盘讨论、修订后作为下一阶段的**判定标准**。')
    lessons.append('> 数据基线：%d 条人工判定（其中 %d 条含实质备注）。' % (len(labeled), len(with_note)))
    lessons.append('')
    lessons.append('## 一、FP 高频判定模式（按出现次数排序）')
    lessons.append('')
    lessons.append('| 模式 | 次数 | 含义 |')
    lessons.append('|---|---|---|')
    TAG_DESC = {
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
    }
    for tag, n in fp_patterns.most_common():
        lessons.append('| %s | %d | %s |' % (tag, n, TAG_DESC.get(tag, '')))
    lessons.append('')
    lessons.append('## 二、TP 高频确认模式')
    lessons.append('')
    lessons.append('| 模式 | 次数 | 含义 |')
    lessons.append('|---|---|---|')
    for tag, n in tp_patterns.most_common():
        lessons.append('| %s | %d | %s |' % (tag, n, TAG_DESC.get(tag, '')))
    lessons.append('')
    lessons.append('## 三、待讨论的判定口径分歧')
    lessons.append('')
    lessons.append('以下口径在本批数据中出现过**两种立场**，建议复盘会上定标准：')
    lessons.append('')
    lessons.append('1. **demo/示例代码算不算攻击面**——微信 sample 的 checkSignature 被人工判 FP（签名守卫不可伪造），')
    lessons.append('   AI 判 TP（访问控制非净化）。需要明确：第三方 SDK 的示例路由是否默认排除。')
    lessons.append('2. **老项目批量豁免是否持续有效**——"old CMS no filtering" 类项目级批量 TP 覆盖了引擎的链级判断，')
    lessons.append('   本次 AI 复核发现其中部分链本身错配（见引擎缺陷清单）。项目级豁免应标注有效期/复核轮次。')
    lessons.append('3. **二阶注入（存储型反序列化）算不算该规则的发现**——引擎把 SQL 注入链尾接到 unserialize sink，')
    lessons.append('   人工口径是"二阶需要额外前提，不算本规则的直接发现"。AI 已跟随此口径，建议成文。')
    lessons.append('')

    # 规则级教训：备注最集中的规则，直接摘录代表性备注
    lessons.append('## 四、规则级判定实录（备注最多 TOP5 规则）')
    lessons.append('')
    for svid, vs in sorted(by_rule_notes.items(), key=lambda x: -len(x[1]))[:5]:
        lessons.append('### CVI-%s %s（%d 条备注）' % (svid, rule_name.get(svid, '?'), len(vs)))
        lessons.append('')
        for v in vs[:3]:
            verdict = 'TP' if v.verification_status.lower() == 'tp' else 'FP'
            lessons.append('- `%s` %s： %s' % (verdict, v.vulfile_path[:60], (v.verification_notes or '')[:160]))
        lessons.append('')

    open(os.path.join(OUT, 'verdict-lessons-%s.md' % today), 'w').write('\n'.join(lessons))

    # ---------- 2. 引擎缺陷清单 ----------
    eng = []
    eng.append('# 引擎缺陷清单（%s）' % today)
    eng.append('')
    eng.append('> 产物性质：给引擎侧的改进 backlog。每条都有可复现的证据锚点（vul id + 文件对照）。')
    eng.append('')
    eng.append('## 链-sink 错配（最高优先级，已实锤 %d 例）' % len(engine_mismatch))
    eng.append('')
    eng.append('**现象**：报告的 sink 文件与传播链文件完全不同源——链在中途接到了另一个数据流上。')
    eng.append('典型：Piwigo rule 1015（unserialize），sink 在 `plugins.class.php`/`themes.class.php`，')
    eng.append('但链全部终止于 `picture_modify.php` 的 SQL 拼接（`$_GET[image_id]` → implode → pwg_query）。')
    eng.append('')
    eng.append('| vul id | 规则 | sink 文件 | 链实际文件 |')
    eng.append('|---|---|---|---|')
    for v in engine_mismatch[:15]:
        chains = TaintChain.objects.filter(vul_result=v.id)
        cfs = '/'.join(sorted(set((c.file_path or '').split('/')[-1] for c in chains))[:2])
        eng.append('| #%d | %s | %s | %s |' % (
            v.id, v.cvi_id, (v.vulfile_path or '').split('/')[-1].split(':')[0], cfs))
    if len(engine_mismatch) > 15:
        eng.append('| …共 %d 例 | | | |' % len(engine_mismatch))
    eng.append('')
    eng.append('**建议修复方向**：parameters_back 回溯时校验每步文件与 sink 文件同源（或同函数调用链），')
    eng.append('跨文件跳转必须经过明确的 include/require/call 边，否则剪链。')
    eng.append('')
    # 死代码/不可达类
    eng.append('## 死代码后的不可达报告')
    eng.append('')
    eng.append('helper.php 等公共库中 `die();`/`exit;` 之后的语句仍被报告（已由 21h-2 修复大部分，残留见 stale 列表）。')
    eng.append('')
    eng.append('## 规则级 FP 率（结论回馈引擎侧参考）')
    eng.append('')
    eng.append('| 规则 | 人工 FP 率 | 样本 | 说明 |')
    eng.append('|---|---|---|---|')
    cred_stat = defaultdict(Counter)
    for v in labeled:
        cred_stat[v.cvi_id][v.verification_status.lower()] += 1
    for svid, c in sorted(cred_stat.items(), key=lambda x: -(x[1]['fp'] / max(1, sum(x[1].values())))):
        total = sum(c.values())
        eng.append('| CVI-%s %s | %.0f%% | %d | %s |' % (
            svid, rule_name.get(svid, '?'), 100 * c['fp'] / total, total,
            '建议规则级复核/降噪' if c['fp'] and c['fp'] / total >= 0.8 else ''))
    eng.append('')
    open(os.path.join(OUT, 'engine-issues-%s.md' % today), 'w').write('\n'.join(eng))

    # ---------- 3. 裁决台账 ----------
    log = []
    log.append('# 裁决台账（%s）' % today)
    log.append('')
    log.append('> 产物性质：本批所有非常规裁决的完整证据链。每条可独立复核。')
    log.append('')
    log.append('## A. 采信 AI 的改判（%d 条）' % len(ai_rej))
    log.append('')
    for v in ai_rej:
        mm = chain_mismatch(v)
        log.append('- **#%d** CVI-%s `%s`' % (v.id, v.cvi_id, v.vulfile_path[:70]))
        log.append('  - 判定：人工 tp → **fp**（%s）' % (
            '链错配实锤' if mm is True else 'AI 推理'))
        log.append('  - AI 理由：%s' % (v.ai_reasoning or '')[:180])
        log.append('  - 独立核实：%s' % (
            '链文件 %s ≠ sink 文件 %s ✓' % (
                '/'.join(sorted(set((c.file_path or '').split('/')[-1] for c in TaintChain.objects.filter(vul_result=v.id)))[:2]),
                (v.vulfile_path or '').split('/')[-1].split(':')[0]) if mm is True else '未独立核实'))
    log.append('')
    log.append('## B. 保留人工的裁决（%d 条，按原因分组）' % len(keeps))
    keep_groups = Counter((v.ai_reasoning or '').split('(')[1].split(')')[0] if '(' in (v.ai_reasoning or '') else 'other'
                          for v in keeps)
    for reason, n in keep_groups.most_common():
        log.append('- %s 条：%s' % (n, reason))
    log.append('')
    log.append('## C. 判例批量采纳（%d 条）' % len(adopted))
    log.append('')
    src_counter = Counter()
    for v in adopted:
        for tok in (v.verification_notes or '').split():
            if tok.startswith('exact') or tok.startswith('module'):
                src_counter[tok] += 1
    log.append('- 来源分布：%s' % (dict(src_counter) or 'exact/module 判例覆盖'))
    log.append('- 判例源头：同模式 ≥2 例人工一致判定（49 例 echo 族 FP 为主力判例）')
    log.append('')
    open(os.path.join(OUT, 'adjudication-log-%s.md' % today), 'w').write('\n'.join(log))

    print('discussion pack written to %s' % OUT)
    for f in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, f)
        print('  %-36s %6d bytes' % (f, os.path.getsize(p)))


if __name__ == '__main__':
    main()
