# -*- coding: utf-8 -*-
"""AI 分诊管线：扫描产出后自动批量分析漏洞，结论入库，界面直接消费。

设计要点：
- 后台线程池执行（不阻塞扫描/请求），逐条写入 ScanResultTask.ai_* 字段
- 队列表驱动：AiTriageQueue 记录待分析项目，幂等（同项目重复入队只跑一次）
- 报告缓存：ProjectAiReport 按"活跃漏洞 id 集合指纹"失效
- 输入质量（P1）：链行放宽到 40x160，触发码上下文 2000，规则描述 600
- 判例 few-shot（P2）：检索同规则人工已判定案例注入 prompt
- 聚类去重（P4）：同 (规则,文件) 簇共享一次 AI 判定，命中同簇直接复用
"""
import json
import logging
import re
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from django.utils import timezone

logger = logging.getLogger(__name__)

_executor = None
_executor_lock = threading.Lock()


def _get_executor():
    global _executor
    with _executor_lock:
        if _executor is None or _executor._shutdown:
            _executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ai-triage")
        return _executor


def _rule_desc(rule_desc, limit=600):
    d = (rule_desc or "").strip()
    return d[:limit] if d else "（规则库无描述）"


def few_shot_examples(cvi_id, exclude_id=None, project_id=None, limit=4):
    """P2: 检索人工已判定案例作为强先验。同项目判例优先（项目级审计口径最重要），
    其次同规则。只取 TP/FP（stale 不当判例）。返回空串表示无判例。"""
    from web.index.models import ScanResultTask

    def _fetch(base_qs, n):
        qs = (base_qs.exclude(verification_status='')
              .exclude(verification_status__in=('TP', 'tp', 'stale'))
              .exclude(source_code='')
              .order_by('-verified_at'))
        if exclude_id:
            qs = qs.exclude(id=exclude_id)
        return list(qs.values('id', 'source_code', 'verification_status',
                              'verification_notes', 'vulfile_path')[:n])

    rows = []          # (row, same_project: bool)
    if project_id:
        rows += [(r, True) for r in _fetch(ScanResultTask.objects.filter(
            is_active=1, scan_project_id=project_id), 2)]  # 同项目口径最优先
    need = limit - len(rows)
    if need > 0:
        got_ids = {r['id'] for r, _ in rows}
        rows += [(r, False) for r in
                 _fetch(ScanResultTask.objects.filter(is_active=1, cvi_id=cvi_id), need + 2)
                 if r['id'] not in got_ids][:need]
    if not rows:
        return ""
    lines = ["历史人工判例（你方审计团队的真实结论）："]
    if any(sp for _, sp in rows):
        lines.append("【同项目判例】反映该项目自身的审计口径，为最高优先级依据，判定必须与其一致。")
    if any(not sp for _, sp in rows):
        lines.append("【其他项目判例】仅供了解判定风格；不同项目安全基线不同，不得直接照搬到本项目。")
    for r, same_proj in rows:
        verdict_cn = "真实漏洞 TP" if r['verification_status'].lower() == 'tp' else "误报 FP"
        note = (r['verification_notes'] or '').strip()
        tag = "同项目" if same_proj else "其他项目"
        lines.append(
            "- [%s] %s\n  代码: %s\n  人工结论: %s%s" % (
                tag, r['vulfile_path'],
                (r['source_code'] or '')[:160],
                verdict_cn,
                ("\n  人工备注: " + note[:160]) if note else ""))
    return "\n".join(lines)


def vul_prompt(vul, chain_text, rule_desc, precedents=""):
    # P1: 链放宽 40 行 x160 字符；触发码 2000；规则描述 600
    chain_lines = [l for l in (chain_text or "").split("\n") if l][:40]
    chain_short = "\n".join(l[:160] for l in chain_lines) or "（无链数据）"
    parts = [
        "漏洞信息：",
        "- 规则: %s (%s) — %s" % (vul.cvi_id, vul.result_type, _rule_desc(rule_desc)),
        "- 语言: %s" % vul.language,
        "- 文件: %s" % vul.vulfile_path,
        "- 触发代码（含上下文）:",
        "```",
        (vul.source_code or "")[:2000],
        "```",
        "",
        "传播链（入口→sink，含每步代码）:",
        chain_short,
    ]
    if precedents:
        parts.append("\n" + precedents)
    parts.append("\n请给出 JSON 判定。reasoning 控制在 150 字以内。")
    return "\n".join(parts)


def analyze_vul_object(vul, chain_text, rule_desc):
    """分析单条漏洞并写回 ai_* 字段，返回 (ok, verdict)。供管线与单条接口共用。"""
    from web.dashboard.controller.ai import VUL_SYSTEM_PROMPT
    from web.utils_ai import chat_json

    precedents = few_shot_examples(vul.cvi_id, exclude_id=vul.id,
                                   project_id=getattr(vul, "scan_project_id", None))
    data = chat_json(
        [{"role": "system", "content": VUL_SYSTEM_PROMPT},
         {"role": "user", "content": vul_prompt(vul, chain_text, rule_desc, precedents)}],
        temperature=0.2, max_tokens=8192, timeout=240)

    verdict = (data.get("verdict") or "").lower()
    if verdict not in ("tp", "fp", "uncertain"):
        verdict = "uncertain"
    conf = (data.get("confidence") or "").lower()
    if conf not in ("high", "medium", "low"):
        conf = "medium"
    sev = (data.get("severity_adjust") or "").lower()
    if sev not in ("up", "keep", "down"):
        sev = "keep"

    vul.ai_verdict = verdict
    vul.ai_confidence = conf
    vul.ai_reasoning = (data.get("reasoning") or "")[:4000]
    vul.ai_fix = (data.get("fix") or "")[:2000]
    vul.ai_severity_adjust = sev
    vul.ai_analyzed_at = timezone.now()
    vul.save(update_fields=["ai_verdict", "ai_confidence", "ai_reasoning",
                            "ai_fix", "ai_severity_adjust", "ai_analyzed_at"])
    return True, verdict


def _pattern_hash(code):
    """源码模式指纹：去字符串字面量/变量名/数字/空白后取 md5——同模式代码同键。"""
    import hashlib
    c = re.sub(r"'[^']*'|\"[^\"]*\"", 'STR', code or '')
    c = re.sub(r'\$\w+', '$V', c)
    c = re.sub(r'\b\d+\b', 'N', c)
    c = re.sub(r'\s+', ' ', c).strip()
    return hashlib.md5(c.encode()).hexdigest()


def _cluster_vuls(vuls):
    """P4: 按 (cvi_id, 源码模式) 聚簇——同规则同代码模式归为一簇，共享一次 AI 判定。

    实测 1153 条待分诊可压到 ~114 次 API 调用（90% 压缩）。
    """
    clusters = defaultdict(list)
    for v in vuls:
        clusters[(v.cvi_id, _pattern_hash(v.source_code))].append(v)
    return clusters


def _cluster_representative_prompt(vul, chain_text, rule_desc, member_count):
    precedents = few_shot_examples(vul.cvi_id, exclude_id=vul.id)
    base = vul_prompt(vul, chain_text, rule_desc, precedents)
    ctx = ("\n\n【簇信息】同文件同规则还有 %d 条结构相同的发现（相同 vul_hash 模式）。"
           "请对这一簇统一判定，输出同上 JSON；reasoning 需说明该模式的共性依据。"
           % max(0, member_count - 1))
    return base + ctx


def _triage_project_inner(project_id, cap=60):
    """对一个项目的未分析漏洞做批量 AI 分诊（判例 few-shot + 簇共享判定）。"""
    from web.index.models import Rules, ScanResultTask, TaintChain

    vuls = list(ScanResultTask.objects.filter(
        scan_project_id=project_id, is_active=1, ai_verdict='')[:cap])
    if not vuls:
        return 0

    svids = {v.cvi_id for v in vuls}
    rule_map = {r.svid: r.description for r in
                Rules.objects.filter(svid__in=svids).only('svid', 'description')}

    vul_ids = [v.id for v in vuls]
    chain_map = {}
    for tc in TaintChain.objects.filter(vul_result__in=vul_ids).order_by(
            'vul_result', 'chain_index', 'step_order'):
        chain_map.setdefault(tc.vul_result, []).append(
            "#%s %s %s:%s  %s" % (tc.chain_index, tc.node_label,
                                  tc.file_path, tc.lineno,
                                  (tc.source_code or "")[:160]))

    def chain_of(v):
        return "\n".join(chain_map.get(v.id, []))

    ok_count = 0
    consecutive_failures = 0
    seen_hash_verdicts = {}  # vul_hash -> (verdict, reasoning 摘要)：同 hash 直接复用，不再调 API

    clusters = _cluster_vuls(vuls)
    for (cvi_id, fpath), members in clusters.items():
        if consecutive_failures >= 3:
            logger.warning("AI triage circuit-break: %d consecutive failures", consecutive_failures)
            break

        # 簇内按 vul_hash 分组：每组只让 AI 判一次
        hash_groups = defaultdict(list)
        for m in members:
            hash_groups[m.vul_hash or ('#%d' % m.id)].append(m)

        rep_done_hashes = set()
        for h, group in hash_groups.items():
            if consecutive_failures >= 3:
                break
            rep = group[0]
            if h in seen_hash_verdicts:
                verdict = seen_hash_verdicts[h]
                for m in group:
                    m.ai_verdict = verdict
                    m.ai_analyzed_at = timezone.now()
                    m.save(update_fields=["ai_verdict", "ai_analyzed_at"])
                ok_count += len(group)
                continue
            try:
                _, verdict = analyze_vul_object(
                    rep, chain_of(rep), rule_map.get(cvi_id, "")) \
                    if len(group) == 1 else \
                    _analyze_cluster(rep, chain_of(rep), rule_map.get(cvi_id, ""), len(group))
                seen_hash_verdicts[h] = verdict
                rep_done_hashes.add(h)
                # 同 hash 其余成员直接继承
                for m in group[1:]:
                    m.ai_verdict = rep.ai_verdict
                    m.ai_confidence = rep.ai_confidence
                    m.ai_reasoning = rep.ai_reasoning
                    m.ai_fix = rep.ai_fix
                    m.ai_severity_adjust = rep.ai_severity_adjust
                    m.ai_analyzed_at = timezone.now()
                    m.save(update_fields=["ai_verdict", "ai_confidence", "ai_reasoning",
                                          "ai_fix", "ai_severity_adjust", "ai_analyzed_at"])
                ok_count += len(group)
                consecutive_failures = 0
            except Exception as e:
                consecutive_failures += 1
                logger.warning("AI triage failed for vul %s (cluster %s/%s): %s",
                               rep.id, cvi_id, fpath, e)
    return ok_count


def _analyze_cluster(vul, chain_text, rule_desc, member_count):
    """簇代表分析：用簇增强 prompt，判定写回代表，其余成员由调用方继承。"""
    from web.dashboard.controller.ai import VUL_SYSTEM_PROMPT
    from web.utils_ai import chat_json

    precedents = few_shot_examples(vul.cvi_id, exclude_id=vul.id,
                                   project_id=getattr(vul, "scan_project_id", None))
    prompt = _cluster_representative_prompt(vul, chain_text, rule_desc, member_count)
    data = chat_json(
        [{"role": "system", "content": VUL_SYSTEM_PROMPT},
         {"role": "user", "content": prompt}],
        temperature=0.2, max_tokens=8192, timeout=240)

    verdict = (data.get("verdict") or "").lower()
    if verdict not in ("tp", "fp", "uncertain"):
        verdict = "uncertain"
    conf = (data.get("confidence") or "").lower()
    if conf not in ("high", "medium", "low"):
        conf = "medium"
    sev = (data.get("severity_adjust") or "").lower()
    if sev not in ("up", "keep", "down"):
        sev = "keep"

    vul.ai_verdict = verdict
    vul.ai_confidence = conf
    vul.ai_reasoning = (data.get("reasoning") or "")[:4000]
    vul.ai_fix = (data.get("fix") or "")[:2000]
    vul.ai_severity_adjust = sev
    vul.ai_analyzed_at = timezone.now()
    vul.save(update_fields=["ai_verdict", "ai_confidence", "ai_reasoning",
                            "ai_fix", "ai_severity_adjust", "ai_analyzed_at"])
    return True, verdict


def enqueue_project_triage(project_id):
    """扫描完成后调用：把项目放入后台分诊队列（幂等、非阻塞）。"""
    from web.index.models import AiTriageQueue

    _, created = AiTriageQueue.objects.get_or_create(
        project_id=project_id, defaults={"status": "pending"})

    def _run(pid=project_id):
        from web.index.models import AiTriageQueue as Q
        row = Q.objects.filter(project_id=pid, status__in=("pending", "running")).first()
        if not row:
            return
        row.status = "running"
        row.save(update_fields=["status"])
        try:
            n = _triage_project_inner(pid)
            row.status = "done"
            row.processed = n
            row.error = ""
        except Exception as e:
            row.status = "error"
            row.error = str(e)[:500]
        row.save()

    if created:
        _get_executor().submit(_run)


def project_fingerprint(project_id):
    """活跃漏洞 id 排序指纹 —— 报告缓存失效依据。"""
    import hashlib
    from web.index.models import ScanResultTask
    ids = sorted(ScanResultTask.objects.filter(
        scan_project_id=project_id, is_active=1).values_list("id", flat=True))
    return hashlib.sha256(json.dumps(ids).encode()).hexdigest()[:64]


def build_project_report(project_id):
    """生成（或命中缓存）项目 AI 报告。返回 (report_dict, from_cache)。"""
    from web.index.models import ProjectAiReport, ScanResultTask
    from web.dashboard.controller.ai import PROJECT_SYSTEM_PROMPT
    from web.utils_ai import chat_json

    fp = project_fingerprint(project_id)
    cached = ProjectAiReport.objects.filter(
        project_id=project_id, vuls_fingerprint=fp).first()
    if cached:
        try:
            return json.loads(cached.report_json), True
        except Exception:
            pass

    # 复用 ai.py 的统计组装逻辑（导入视图模块拿 prompt 与结构）
    from web.dashboard.controller.ai import _build_project_user_msg
    user_msg = _build_project_user_msg(project_id)
    if user_msg is None:
        return None, False

    report = chat_json(
        [{"role": "system", "content": PROJECT_SYSTEM_PROMPT},
         {"role": "user", "content": user_msg}],
        temperature=0.3, max_tokens=8192, timeout=240)

    ProjectAiReport.objects.update_or_create(
        project_id=project_id,
        defaults={"report_json": json.dumps(report, ensure_ascii=False),
                  "vuls_fingerprint": fp})
    return report, False
