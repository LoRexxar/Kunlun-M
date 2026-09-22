# -*- coding: utf-8 -*-
"""AI 分诊管线：扫描产出后自动批量分析漏洞，结论入库，界面直接消费。

设计要点：
- 后台线程池执行（不阻塞扫描/请求），逐条写入 ScanResultTask.ai_* 字段
- 队列表驱动：AiTriageQueue 记录待分析项目，幂等（同项目重复入队只跑一次）
- 报告缓存：ProjectAiReport 按"活跃漏洞 id 集合指纹"失效
"""
import json
import logging
import threading
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


def vul_prompt(vul, chain_text, rule_desc):
    # 长链是推理模型截断的主因：收紧输入
    chain_lines = [l for l in (chain_text or "").split("\n") if l][:25]
    chain_short = "\n".join(l[:100] for l in chain_lines) or "（无链数据）"
    return (
        "漏洞信息：\n"
        "- 规则: %s (%s) — %s\n"
        "- 语言: %s\n"
        "- 文件: %s\n"
        "- 触发代码: %s\n\n"
        "传播链（入口→sink）:\n%s\n\n"
        "请给出 JSON 判定。reasoning 控制在 150 字以内。" % (
            vul.cvi_id, vul.result_type, (rule_desc or "")[:150],
            vul.language, vul.vulfile_path,
            (vul.source_code or "")[:200],
            chain_short)
    )


def analyze_vul_object(vul, chain_text, rule_desc):
    """分析单条漏洞并写回 ai_* 字段，返回 (ok, verdict)。供管线与单条接口共用。"""
    from web.dashboard.controller.ai import VUL_SYSTEM_PROMPT
    from web.utils_ai import chat_json

    data = chat_json(
        [{"role": "system", "content": VUL_SYSTEM_PROMPT},
         {"role": "user", "content": vul_prompt(vul, chain_text, rule_desc)}],
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


def _triage_project_inner(project_id, cap=60):
    """对一个项目的未分析漏洞做批量 AI 分诊（带链数据、规则描述）。"""
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
                                  (tc.source_code or "")[:120]))

    ok_count = 0
    consecutive_failures = 0
    for v in vuls:
        if consecutive_failures >= 3:
            logger.warning("AI triage circuit-break: %d consecutive failures", consecutive_failures)
            break
        chain_text = "\n".join(chain_map.get(v.id, []))
        try:
            _, _ = analyze_vul_object(v, chain_text, rule_map.get(v.cvi_id, ""))
            ok_count += 1
            consecutive_failures = 0
        except Exception as e:
            consecutive_failures += 1
            logger.warning("AI triage failed for vul %s: %s", v.id, e)
    return ok_count


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
