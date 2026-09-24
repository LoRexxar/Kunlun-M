# -*- coding: utf-8 -*-
"""AI 能力视图：漏洞分析 / 项目报告 / 规则生成 / AI 设置"""
import json
import os
import re

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from django.views import View
from django.views.decorators.http import require_POST

from web.index.models import (NewEvilFunc, Project, Rules, ScanResultTask,
                              ScanTask, TaintChain, FrameworkTamper)
from web.utils_ai import (AICallFailed, AINotConfigured, ai_configured,
                          chat, chat_json, get_ai_config)


def _ai_or_error(fn):
    """统一包装：返回 (ok, data_or_message)"""
    try:
        return True, fn()
    except AINotConfigured as e:
        return False, str(e)
    except AICallFailed as e:
        return False, str(e)
    except Exception as e:
        return False, "AI 分析异常: %s" % e


def _chain_summary(vul_id):
    """取传播链，格式化为紧凑文本（入口→...→sink）"""
    rows = TaintChain.objects.filter(
        vul_result=vul_id).order_by("chain_index", "step_order")[:40]
    if not rows:
        return ""
    lines = []
    for r in rows:
        lines.append("#%s %s %s:%s  %s" % (
            r.chain_index, r.node_label, r.file_path, r.lineno,
            (r.source_code or "")[:120]))
    return "\n".join(lines)


VUL_SYSTEM_PROMPT = (
    "你是代码审计专家。用户给出一条 SAST 引擎报告的漏洞（含传播链）。\n"
    "请输出严格 JSON：{\n"
    '  "verdict": "tp" | "fp" | "uncertain",   // 真实漏洞倾向 / 误报倾向 / 不确定\n'
    '  "confidence": "high" | "medium" | "low",\n'
    '  "reasoning": "判定理由，3-6 句，中文，解释数据流是否真正可达、有无净化",\n'
    '  "fix": "修复建议，2-4 句，中文，给出具体改法",\n'
    '  "severity_adjust": "up" | "keep" | "down"   // 相对报告等级的建议\n'
    "}"
)
VUL_SYSTEM_PROMPT += "\n只输出该 JSON 对象本身，不要输出任何其他文字或思考过程。"


class AiVulAnalyzeView(View):
    """单漏洞 AI 分析：解释数据流 + 误报判定 + 修复建议"""

    def post(self, request, vul_id):
        vul = ScanResultTask.objects.filter(id=vul_id).first()
        if not vul:
            return JsonResponse({"code": 404, "message": "漏洞不存在"})

        chain = _chain_summary(vul_id)
        rule = Rules.objects.filter(svid=vul.cvi_id).first()
        rule_desc = (rule.description if rule else "") or ""

        user_msg = (
            "漏洞信息：\n"
            "- 规则: %s (%s) — %s\n"
            "- 语言: %s\n"
            "- 文件: %s\n"
            "- 触发代码: %s\n\n"
            "传播链（入口→sink）:\n%s\n\n"
            "请给出 JSON 判定。" % (
                vul.cvi_id, vul.result_type, rule_desc,
                vul.language, vul.vulfile_path,
                (vul.source_code or "")[:300],
                chain[:4000] or "（无链数据）")
        )

        def call():
            from web.ai_pipeline import analyze_vul_object
            from web.index.models import TaintChain
            rows = TaintChain.objects.filter(
                vul_result=vul_id).order_by("chain_index", "step_order")[:40]
            chain_text = "\n".join(
                "#%s %s %s:%s  %s" % (r.chain_index, r.node_label, r.file_path,
                                       r.lineno, (r.source_code or "")[:120])
                for r in rows)
            analyze_vul_object(vul, chain_text, rule_desc)
            return {"verdict": vul.ai_verdict, "confidence": vul.ai_confidence,
                    "reasoning": vul.ai_reasoning, "fix": vul.ai_fix,
                    "severity_adjust": vul.ai_severity_adjust}

        ok, data = _ai_or_error(call)
        if not ok:
            return JsonResponse({"code": 500, "message": data})
        return JsonResponse({"code": 200, "data": data})


def _build_project_user_msg(project_id):
    """组装项目报告的用户消息（统计聚合好再喂 AI）。无活跃漏洞返回 None。"""
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return None
    vuls = list(ScanResultTask.objects.filter(
        scan_project_id=project_id, is_active=1)[:150])
    if not vuls:
        return None

    by_type = {}
    by_file = {}
    for v in vuls:
        by_type[v.result_type] = by_type.get(v.result_type, 0) + 1
        by_file.setdefault(v.vulfile_path, []).append(v.cvi_id)
    top_types = sorted(by_type.items(), key=lambda x: -x[1])[:8]
    top_files = sorted(by_file.items(), key=lambda x: -len(x[1]))[:8]

    rule_levels = dict(Rules.objects.values_list("svid", "level"))
    confirmed_tp = sum(1 for v in vuls if v.verification_status == "tp")
    confirmed_fp = sum(1 for v in vuls if v.verification_status == "fp")
    ai_tp = sum(1 for v in vuls if v.ai_verdict == "tp")
    ai_fp = sum(1 for v in vuls if v.ai_verdict == "fp")

    listing = "\n".join(
        "- %s | %s | %s | AI:%s" % (v.cvi_id, v.result_type, v.vulfile_path,
                                     v.ai_verdict or "n/a")
        for v in vuls[:80])

    return (
        "项目: %s (id=%s)\n语言: PHP\n活跃漏洞: %d 条（人工TP %d / 人工FP %d；AI判TP %d / AI判FP %d）\n\n"
        "漏洞类型分布: %s\n\n热点文件: %s\n\n漏洞清单（前80条）:\n%s\n\n"
        "请输出 JSON 报告。" % (
            project.project_name, project.id, len(vuls),
            confirmed_tp, confirmed_fp, ai_tp, ai_fp,
            ", ".join("%s×%d" % t for t in top_types),
            "; ".join("%s(%d处: %s)" % (f, len(ids), ",".join(ids[:5]))
                      for f, ids in top_files),
            listing))


PROJECT_SYSTEM_PROMPT = (
    "你是应用安全顾问。根据某项目的 SAST 扫描统计与漏洞清单，输出严格 JSON：{\n"
    '  "overview": "项目风险面总体评价，4-6 句中文：主要风险类型、代码质量信号、与同类项目对比",\n'
    '  "top_risks": [ {"title": "风险点简称", "why": "为什么重要, 1-2句", "vul_refs": "相关CVI/文件"} ],  // 3-5 条\n'
    '  "fix_plan": [ {"step": "修复步骤", "detail": "具体做法", "effort": "低|中|高"} ]  // 3-5 步, 按优先级排序\n'
    "}"
)
PROJECT_SYSTEM_PROMPT += "\n只输出该 JSON 对象本身，不要输出任何其他文字或思考过程。"


class AiProjectReportView(View):
    """项目级 AI 报告：风险概览 + Top 风险 + 修复路线"""

    def post(self, request, project_id):
        user_msg = _build_project_user_msg(project_id)
        if user_msg is None:
            project = Project.objects.filter(id=project_id).first()
            if not project:
                return JsonResponse({"code": 404, "message": "项目不存在"})
            return JsonResponse({"code": 400, "message": "项目无活跃漏洞，无需报告"})

        # 报告缓存（指纹相同直接命中）
        from web.ai_pipeline import build_project_report
        report, from_cache = build_project_report(project_id)
        if report is None:
            return JsonResponse({"code": 400, "message": "项目无活跃漏洞，无需报告"})

        def call():
            return report

        ok, data = _ai_or_error(call)
        if not ok:
            return JsonResponse({"code": 500, "message": data})
        data["from_cache"] = from_cache
        return JsonResponse({"code": 200, "data": data})

        user_msg = (
            "项目: %s (id=%s)\n语言: PHP\n活跃漏洞: %d 条（已确认TP %d / FP %d）\n\n"
            "漏洞类型分布: %s\n\n热点文件: %s\n\n漏洞清单（前80条）:\n%s\n\n"
            "请输出 JSON 报告。" % (
                project.project_name, project.id, len(vuls),
                confirmed_tp, confirmed_fp,
                ", ".join("%s×%d" % t for t in top_types),
                "; ".join("%s(%d处: %s)" % (f, len(ids), ",".join(ids[:5]))
                          for f, ids in top_files),
                listing)
        )




RULE_SYSTEM_PROMPT = (
    "你是 Kunlun-M SAST 规则工程师。用户给出目标危险函数（sink）与语言。\n"
    "Kunlun-M 规则 mode 说明: function-param-regex 按函数参数正则匹配。\n"
    "请输出严格 JSON：{\n"
    '  "rule_name": "英文规则名, 大驼峰",\n'
    '  "match_mode": "function-param-regex",\n'
    '  "match": "匹配该 sink 调用的正则（Python re 语法，注意转义）",\n'
    '  "unmatch": "排除误报的正则或 null",\n'
    '  "description": "中文规则说明 1-2 句",\n'
    '  "level": 1,  // 1高危 2中 3低\n'
    '  "reason": "为何这样设计匹配, 2句"\n'
    "}"
)
RULE_SYSTEM_PROMPT += "\n只输出该 JSON 对象本身，不要输出任何其他文字或思考过程。"


class AiRuleGenerateView(View):
    """AI 规则生成：sink 函数名 → 规则 JSON 预览（不直接落库，用户确认后调 generate）"""

    def post(self, request):
        lang = (request.POST.get("language") or "php").strip()
        sink = (request.POST.get("sink") or "").strip()
        extra = (request.POST.get("extra") or "").strip()
        if not sink:
            return JsonResponse({"code": 400, "message": "请填写 sink 函数名"})

        # 已有规则提示避免重复
        exists = list(Rules.objects.filter(
            language=lang, rule_name__icontains=sink.split("(")[0]
        ).values_list("svid", "rule_name")[:5])
        exists_note = ("已存在相似规则: %s" % exists) if exists else "无相似规则"

        def call():
            return chat_json(
                [{"role": "system", "content": RULE_SYSTEM_PROMPT},
                 {"role": "user", "content":
                  "语言: %s\nsink 函数: %s\n补充要求: %s\n%s\n请输出 JSON。" % (
                      lang, sink, extra or "无", exists_note)}],
                temperature=0.2, max_tokens=8192, timeout=240)

        ok, data = _ai_or_error(call)
        if not ok:
            return JsonResponse({"code": 500, "message": data})
        # 附带引擎侧校验：正则可编译
        import re as _re
        try:
            _re.compile(data.get("match") or "")
            data["match_valid"] = True
        except Exception as e:
            data["match_valid"] = False
            data["match_error"] = str(e)
        return JsonResponse({"code": 200, "data": data})

    def put(self, request):
        """一键落库：把预览的规则写入规则文件并同步 DB（等价 CLI generate rule --sync）"""
        import json as _json
        try:
            body = _json.loads(request.body or b"{}")
        except Exception:
            return JsonResponse({"code": 400, "message": "请求体不是合法 JSON"})

        lang = (body.get("language") or "php").strip().lower()
        rule_name = (body.get("rule_name") or "").strip()
        match_mode = (body.get("match_mode") or "function-param-regex").strip()
        match = (body.get("match") or "").strip()
        unmatch = (body.get("unmatch") or "").strip() or None
        description = (body.get("description") or "").strip() or rule_name
        try:
            level = int(body.get("level") or 1)
        except Exception:
            level = 1
        if level not in (1, 2, 3):
            level = 1
        if not rule_name or not match:
            return JsonResponse({"code": 400, "message": "rule_name 与 match 必填"})

        import re as _re
        try:
            _re.compile(match)
        except Exception as e:
            return JsonResponse({"code": 400, "message": "match 正则不可编译: %s" % e})

        from core.scaffold import write_rule_file
        from core.rule import RuleCheck
        try:
            rid, rule_path = write_rule_file(
                language=lang, rule_name=rule_name, author="web-ai",
                description=description, level=level, status=True,
                match_mode=match_mode, match=match, unmatch=unmatch,
                force=False)
        except FileExistsError:
            return JsonResponse({"code": 409, "message": "同名规则文件已存在（CVI 冲突），请修改名称后重试"})
        except Exception as e:
            return JsonResponse({"code": 500, "message": "规则文件生成失败: %s" % e})

        sync_err = ""
        try:
            RuleCheck().load()
        except Exception as e:
            sync_err = str(e)

        return JsonResponse({"code": 200, "data": {
            "svid": rid, "rule_path": rule_path,
            "synced": not sync_err, "sync_error": sync_err}})


class AiSettingsView(View):
    """AI 设置页（查看 + 保存）"""

    def get(self, request):
        cfg = get_ai_config()
        masked = cfg["api_key"][:6] + "..." + cfg["api_key"][-4:] if len(cfg["api_key"]) > 12 else ("已配置" if cfg["api_key"] else "")
        return render(request, "dashboard/ai_settings.html", {
            "cfg": cfg, "masked_key": masked,
            "has_key": bool(cfg["api_key"]),
        })

    def post(self, request):
        from web.index.models import AiConfig
        row = AiConfig.objects.first() or AiConfig(id=1)
        api_key = (request.POST.get("api_key") or "").strip()
        if api_key:
            row.api_key = api_key
        row.base_url = (request.POST.get("base_url") or "").strip()
        row.model = (request.POST.get("model") or "").strip()
        row.save()
        saved_msg = "配置已保存（%s / %s）" % (
            get_ai_config()["base_url"], get_ai_config()["model"])
        # 测试连通性（推理模型 thinking 消耗大，max_tokens 给足）
        try:
            reply = chat([{"role": "user", "content": "回复两个字: OK"}],
                         max_tokens=2048, timeout=90)
            ok = bool(reply)
            msg = saved_msg + "，连通正常"
        except Exception as e:
            # 保存本身成功，连通失败单独说明（不代表配置没存上）
            ok = False
            msg = saved_msg + "；连通测试失败：" + str(e)
        from django.shortcuts import redirect
        from django.contrib import messages
        if ok:
            messages.success(request, msg)
        else:
            messages.error(request, msg)
        return redirect("dashboard:ai_settings")

class AiVulDetailView(View):
    """读取漏洞的已存 AI 分诊结果（不触发新分析）"""

    @staticmethod
    def get(request, vul_id):
        from django.contrib.auth.decorators import login_required
        from web.index.models import ScanResultTask

        srt = ScanResultTask.objects.filter(id=vul_id, is_active=True).only(
            'ai_verdict', 'ai_confidence', 'ai_reasoning', 'ai_fix',
            'ai_severity_adjust', 'ai_analyzed_at', 'verification_status',
        ).first()
        if not srt:
            return JsonResponse({"code": 404, "message": "结果不存在"})

        return JsonResponse({"code": 200, "data": {
            "verdict": srt.ai_verdict,
            "confidence": srt.ai_confidence,
            "reasoning": srt.ai_reasoning or '',
            "fix": srt.ai_fix or '',
            "severity_adjust": srt.ai_severity_adjust or '',
            "analyzed_at": srt.ai_analyzed_at.strftime('%Y-%m-%d %H:%M') if srt.ai_analyzed_at else '',
            "human_status": srt.verification_status or '',
            "disagreed": bool(
                srt.ai_verdict in ('tp', 'fp')
                and srt.verification_status in ('tp', 'fp')
                and srt.ai_verdict != srt.verification_status
            ),
        }})
