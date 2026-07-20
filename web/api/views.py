#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/26 16:38
# @Author  : LoRexxar
# @File    : views.py
# @Contact : lorexxar@gmail.com

import os
import json

from django.shortcuts import HttpResponse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

from web.index.controller import login_or_token_required, api_token_required
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Count
from django.utils import timezone

from web.index.models import ScanTask, VendorVulns, Rules, Project, ProjectVendors, ScanResultTask
from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult
from core.vendors import get_project_vendor_by_name, get_vendor_vul_by_name

from Kunlun_M.settings import LOGS_PATH


def _get_cached_session(scan_id):
    """获取已缓存的 graph session（不会触发加载）。

    Returns (session, error_response) tuple.
    session=None + error_response=JsonResponse 表示 session 未加载或不可用。
    """
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        pass
    from web.api.graph_session_manager import get_session
    session = get_session(scan_id)
    if session is None or not session.is_loaded:
        return None, JsonResponse({"code": 412, "error": "Graph not loaded. Please load graph first via /api/graph/load."})
    return session, None


def index(request):
    return HttpResponse("Nothing here.")


class TaskListApiView(View):
    """展示当前任务列表"""

    @staticmethod
    @api_token_required
    def get(request):

        scantasks = ScanTask.objects.all().order_by('-id')
        scantaskidlist = []

        for scantask in scantasks:
            scantaskdata = {
                "id": scantask.id,
                "taskname": scantask.task_name,
                "is_finished": scantask.is_finished,
            }

            scantaskidlist.append(scantaskdata)

        scantasklist = {"code": 200, "status": True, "message": scantaskidlist}

        return JsonResponse(scantasklist)


class TaskDetailApiView(View):
    """展示当前任务细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(scantask)})


class TaskResultApiView(View):
    """展示当前任务所有结果细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        project_id = get_and_check_scantask_project_id(task_id)
        scantaskresults = list(get_and_check_scanresult(task_id).objects.filter(scan_project_id=project_id, is_active=1).values())

        return JsonResponse(
            {"code": 200, "status": True, "message": scantaskresults})


class TaskResultDetailApiView(View):
    """指定任务结果细节"""

    @staticmethod
    @api_token_required
    def get(request, result_id):
        srt = ScanResultTask.objects.filter(id=result_id, is_active=1).values()

        if not srt:
            return JsonResponse({"code": 403, "status": False, "message": "TaskResult {} not exist.".format(result_id)})

        return JsonResponse({"code": 200, "status": True, "message": list(srt)})


class TaskResultDetailDelApiView(View):
    """删除当前任务结果细节"""

    @staticmethod
    @api_token_required
    def get(request, result_id):
        srt = ScanResultTask.objects.filter(id=result_id).first()

        if not srt or srt.is_active == 0:
            return JsonResponse({"code": 403, "status": False, "message": "TaskResult {} not exist.".format(result_id)})

        srt.is_active = 0
        srt.save()
        return JsonResponse({"code": 200, "status": True, "message": "Delete Success."})


class TaskTaintChainApiView(View):
    """展示指定任务结果流"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        from web.index.models import TaintChain
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask:
            return JsonResponse({"code": 404, "status": False, "message": "Task {} not found.".format(task_id)})

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        # 获取该 task 下所有活跃的 ScanResultTask id
        srt_ids = list(
            get_and_check_scanresult(task_id).objects.filter(
                scan_task_id=task_id, is_active=1
            ).values_list("id", flat=True)
        )

        chains = TaintChain.objects.filter(scan_task=task_id, vul_result__in=srt_ids).order_by("vul_result", "chain_index", "step_order")
        result_list = []
        for tc in chains:
            result_list.append({
                "vul_id": tc.vul_result,
                "chain_index": tc.chain_index,
                "step_order": tc.step_order,
                "node_type": tc.node_label,
                "node_content": tc.node_name,
                "node_path": tc.file_path,
                "node_lineno": tc.lineno,
                "node_source": tc.source_code,
                "node_vid": tc.vid,
            })
        return JsonResponse({"code": 200, "status": True, "message": result_list})


class TaskTaintChainDetailApiView(View):
    """展示指定任务结果流细节"""

    @staticmethod
    @api_token_required
    def get(request, result_id, vul_id):
        from web.index.models import TaintChain
        scantask = ScanResultTask.objects.filter(id=result_id).first()
        task_id = scantask.scan_task_id

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        chains = TaintChain.objects.filter(vul_result=vul_id).order_by("chain_index", "step_order")
        result_list = []
        for tc in chains:
            result_list.append({
                "vul_id": tc.vul_result,
                "chain_index": tc.chain_index,
                "step_order": tc.step_order,
                "node_type": tc.node_label,
                "node_content": tc.node_name,
                "node_path": tc.file_path,
                "node_lineno": tc.lineno,
                "node_source": tc.source_code,
                "node_vid": tc.vid,
            })
        return JsonResponse({"code": 200, "status": True, "message": result_list})


class TaskVendorsApiView(View):
    """展示当前任务组件"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        project_id = get_and_check_scantask_project_id(task_id)
        pvs = list(ProjectVendors.objects.filter(project_id=project_id).values())

        return JsonResponse(
            {"code": 200, "status": True, "message": pvs})


class RuleListApiView(View):
    """展示规则列表"""

    @staticmethod
    @api_token_required
    def get(request):
        rules = Rules.objects.filter().values()

        return JsonResponse(
            {"code": 200, "status": True, "message": list(rules)})


class RuleDetailApiView(View):
    """展示当前规则细节"""

    @staticmethod
    @api_token_required
    def get(request, rule_cviid):

        rules = Rules.objects.filter(svid=rule_cviid).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(rules)})


class VendorVulListApiView(View):
    """展示组件漏洞列表"""

    @staticmethod
    @api_token_required
    def get(request):
        vendorvuls = VendorVulns.objects.filter()[:100].values()

        return JsonResponse(
            {"code": 200, "status": True, "message": list(vendorvuls)})

    @staticmethod
    @api_token_required
    def post(request):
        if 'vendor_name' in request.POST:
            vendor_name = request.POST['vendor_name']
            vs = list(get_project_vendor_by_name(vendor_name))
        else:
            vs = []

        return JsonResponse(
            {"code": 200, "status": True, "message": vs})


class VendorVuLDetailApiView(View):
    """展示当前规则细节"""

    @staticmethod
    @api_token_required
    def get(request, vendor_vul_id):

        vendorvuls = VendorVulns.objects.filter(id=vendor_vul_id).values()

        return JsonResponse({"code": 200, "status": True, "message":  list(vendorvuls)})

    @staticmethod
    @api_token_required
    def post(request):
        if 'vendor_name' in request.POST:
            vendor_name = request.POST['vendor_name']
            vs = list(get_vendor_vul_by_name(vendor_name))
        else:
            vs = []

        return JsonResponse(
            {"code": 200, "status": True, "message": vs})


class VendorStatisticsApiView(View):
    """展示组件统计数据Top100"""

    @staticmethod
    @api_token_required
    def get(request):
        limit = 100
        pvs = ProjectVendors.objects.values('name', 'language').annotate(total=Count('id')).order_by('total')
        pvs = pvs[::-1][:limit]

        pv_list = list(pvs)
        id = 1
        for pv in pv_list:
            pv['id'] = id
            id += 1

        return JsonResponse({"code": 200, "status": True, "message":  pv_list})


class VendorVulStatisticsApiView(View):
    """展示组件漏洞统计数据top100"""

    @staticmethod
    @api_token_required
    def get(request):
        limit = 100
        vns = VendorVulns.objects.values('vendor_name').annotate(total=Count('id')).order_by('total')
        vns = vns[::-1][:limit]
        vn_list = list(vns)

        id = 1
        for vn in vn_list:
            vn['id'] = id
            id += 1

            vendor_name = vn['vendor_name']
            vn['id'] = id
            id += 1

            vs = get_project_vendor_by_name(vendor_name)
            vn['vendor_count'] = vs.count()

            vvs = get_vendor_vul_by_name(vendor_name)
            vn['high'] = 0
            vn['medium'] = 0
            vn['low'] = 0

            for vv in vvs:
                if vv.severity > 6:
                    vn['high'] += 1
                elif vv.severity > 2:
                    vn['medium'] += 1
                else:
                    vn['low'] += 1

        return JsonResponse({"code": 200, "status": True, "message":  vn_list})


class TaskLogTailApiView(View):
    """实时获取扫描日志尾部"""

    @staticmethod
    @login_or_token_required
    def get(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return JsonResponse({"code": 404, "status": False, "message": "Task not found."})

        log_path = os.path.join(LOGS_PATH, "ScanTask_{}.log".format(task_id))
        if not os.path.exists(log_path):
            return JsonResponse({"code": 200, "data": [], "finished": task.is_finished != 2})

        lines = []
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            pass

        return JsonResponse({"code": 200, "data": [l.rstrip() for l in lines[-300:]], "finished": task.is_finished != 2})


class TaskCancelApiView(View):
    """取消运行中的任务"""

    @staticmethod
    @login_or_token_required
    def post(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return JsonResponse({"code": 404, "message": "Task not found."})

        if task.is_finished != 2:
            return JsonResponse({"code": 400, "message": "Task is not running."})

        # 尝试终止进程
        if task.pid:
            try:
                os.kill(task.pid, 9)
            except (OSError, ProcessLookupError):
                pass

        ScanTask.objects.filter(id=task.id).update(
            is_finished=0, finished_at=timezone.now(),
            exit_code=-1, error_message="Cancelled by user.", pid=None
        )
        return JsonResponse({"code": 200, "message": "Task cancelled."})


class TaskRetryApiView(View):
    """重试失败的任务"""

    @staticmethod
    @login_or_token_required
    def post(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return JsonResponse({"code": 404, "message": "Task not found."})

        if task.is_finished not in (0, 1):
            return JsonResponse({"code": 400, "message": "Only failed/success tasks can be retried."})

        ScanTask.objects.filter(id=task.id).update(
            is_finished=3, started_at=None, finished_at=None,
            exit_code=None, error_message=None, pid=None
        )
        return JsonResponse({"code": 200, "message": "Task queued for retry."})


class TaskStatusApiView(View):
    """轻量级任务状态查询 — 仅返回 id/name/status/error 等核心字段。

    GET 参数:
        task_id: 任务 ID
    """

    @staticmethod
    @api_token_required
    def get(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        if not task:
            return JsonResponse({"code": 404, "status": False, "message": "Task not found."})

        status_map = {0: "failed", 1: "success", 2: "running", 3: "pending"}
        return JsonResponse({
            "code": 200, "status": True,
            "message": {
                "id": task.id,
                "task_name": task.task_name,
                "status": status_map.get(task.is_finished, "unknown"),
                "source_type": task.source_type,
                "language": "",
                "error_message": task.error_message or "",
                "created_at": str(task.created_at) if task.created_at else "",
                "started_at": str(task.started_at) if task.started_at else "",
                "finished_at": str(task.finished_at) if task.finished_at else "",
            }
        })


class TaskCreateApiView(View):
    """通过 API 创建扫描任务（仅支持本地路径模式）。

    POST 参数:
        target_path: 扫描目标路径 (必填)
        task_name: 任务名称 (可选，默认取目录名)
        language: 语言 (可选)
        special_rules: 特殊规则 (可选)
        tamper_name: tamper 名称 (可选)
        black_path: 黑名单路径 (可选)
        unconfirm: 是否确认未确认漏洞 0/1 (可选，默认 0)
        unprecom: 是否跳过预编译 0/1 (可选，默认 0)
        without_vendor: 是否跳过组件检测 0/1 (可选，默认 0)
        no_cache: 是否不使用缓存 0/1 (可选，默认 0)
    """

    @staticmethod
    @api_token_required
    def post(request):
        from Kunlun_M import settings

        allowed_paths = getattr(settings, "WEB_SCAN_ALLOWED_PATHS", [])
        if not allowed_paths:
            return JsonResponse({"code": 403, "status": False, "message": "Path scan not enabled. Configure WEB_SCAN_ALLOWED_PATHS in settings."})

        target_path = (request.POST.get("target_path", "") or "").strip()
        if not target_path:
            return JsonResponse({"code": 400, "status": False, "message": "target_path required"})

        target_path = os.path.abspath(os.path.expanduser(target_path))
        if not os.path.isdir(target_path):
            return JsonResponse({"code": 400, "status": False, "message": "Path does not exist or is not a directory: {}".format(target_path)})

        if "*" not in allowed_paths:
            real_path = os.path.realpath(target_path)
            matched = False
            for allowed_dir in allowed_paths:
                real_allowed = os.path.realpath(os.path.abspath(allowed_dir))
                if real_path == real_allowed or real_path.startswith(real_allowed + os.sep):
                    matched = True
                    break
            if not matched:
                return JsonResponse({"code": 403, "status": False, "message": "Path not in allowed scan directories."})

        task_name = (request.POST.get("task_name", "") or "").strip()
        if not task_name:
            task_name = os.path.basename(target_path.rstrip(os.sep)) or "unnamed"

        opts = {
            "language": (request.POST.get("language", "") or "").strip(),
            "special_rules": (request.POST.get("special_rules", "") or "").strip(),
            "tamper_name": (request.POST.get("tamper_name", "") or "").strip(),
            "black_path": (request.POST.get("black_path", "") or "").strip(),
            "unconfirm": request.POST.get("unconfirm", "0"),
            "unprecom": request.POST.get("unprecom", "0"),
            "without_vendor": request.POST.get("without_vendor", "0"),
            "no_cache": request.POST.get("no_cache", "0"),
        }

        task = ScanTask(
            task_name=task_name,
            target_path=target_path,
            parameter_config=repr(["api", "path", target_path]),
            is_finished=3,
            source_type="path",
            options_json=json.dumps(opts, ensure_ascii=False),
            created_at=timezone.now(),
            last_scan_time=timezone.now(),
        )
        task.save()

        return JsonResponse({"code": 200, "status": True, "message": {"task_id": task.id, "task_name": task.task_name}})


class TaskCreateWithConfigApiView(View):
    """通过 API 一步创建、配置并排队扫描任务。

    POST 参数同 TaskCreateApiView + TaskConfigView 合并。
    创建后自动设置 options_json 并置为待执行状态。
    """

    @staticmethod
    @api_token_required
    def post(request):
        from Kunlun_M import settings
        from web.index.scan_dispatcher import try_dispatch

        allowed_paths = getattr(settings, "WEB_SCAN_ALLOWED_PATHS", [])
        if not allowed_paths:
            return JsonResponse({"code": 403, "status": False, "message": "Path scan not enabled."})

        target_path = (request.POST.get("target_path", "") or "").strip()
        if not target_path:
            return JsonResponse({"code": 400, "status": False, "message": "target_path required"})

        target_path = os.path.abspath(os.path.expanduser(target_path))
        if not os.path.isdir(target_path):
            return JsonResponse({"code": 400, "status": False, "message": "Path does not exist: {}".format(target_path)})

        if "*" not in allowed_paths:
            real_path = os.path.realpath(target_path)
            matched = any(
                real_path == os.path.realpath(os.path.abspath(d)) or real_path.startswith(os.path.realpath(os.path.abspath(d)) + os.sep)
                for d in allowed_paths
            )
            if not matched:
                return JsonResponse({"code": 403, "status": False, "message": "Path not in allowed scan directories."})

        task_name = (request.POST.get("task_name", "") or "").strip() or os.path.basename(target_path.rstrip(os.sep)) or "unnamed"

        opts = {
            "language": (request.POST.get("language", "") or "").strip(),
            "special_rules": (request.POST.get("special_rules", "") or "").strip(),
            "tamper_name": (request.POST.get("tamper_name", "") or "").strip(),
            "black_path": (request.POST.get("black_path", "") or "").strip(),
            "unconfirm": request.POST.get("unconfirm", "0"),
            "unprecom": request.POST.get("unprecom", "0"),
            "without_vendor": request.POST.get("without_vendor", "0"),
            "no_cache": request.POST.get("no_cache", "0"),
        }

        task = ScanTask(
            task_name=task_name,
            target_path=target_path,
            parameter_config=repr(["api", "path", target_path]),
            is_finished=3,
            source_type="path",
            options_json=json.dumps(opts, ensure_ascii=False),
            created_at=timezone.now(),
            last_scan_time=timezone.now(),
        )
        task.save()

        # 尝试立即调度
        try_dispatch()

        task.refresh_from_db()
        return JsonResponse({
            "code": 200, "status": True,
            "message": {
                "task_id": task.id,
                "task_name": task.task_name,
                "status": "running" if task.is_finished == 2 else "queued",
            }
        })


class StatsApiView(View):
    """仪表盘统计数据"""

    @staticmethod
    @login_required
    def get(request):
        # 漏洞按语言分布
        lang_dist = list(
            ScanResultTask.objects.filter(is_active=1)
            .values('language').annotate(count=Count('id'))
            .order_by('-count')
        )

        # 漏洞按等级分布 — 通过 join Rules 获取 level
        level_map = {0: '信息', 1: '低危', 2: '低危', 3: '中危', 4: '中危', 5: '高危', 6: '高危', 7: '高危', 8: '高危', 9: '高危', 10: '严重'}
        rules = {str(r.svid): r.level for r in Rules.objects.all()}
        vuls = ScanResultTask.objects.filter(is_active=1).only('cvi_id')
        level_dist = {'高危': 0, '中危': 0, '低危': 0, '信息': 0}
        for v in vuls:
            lv = rules.get(v.cvi_id, 5)
            level_name = level_map.get(lv, '中危')
            level_dist[level_name] = level_dist.get(level_name, 0) + 1

        # 任务状态分布
        tasks = ScanTask.objects.all()
        task_status = {
            'success': tasks.filter(is_finished=1).count(),
            'running': tasks.filter(is_finished=2).count(),
            'failed': tasks.filter(is_finished=0).count(),
            'pending': tasks.filter(is_finished=3).count(),
        }

        # 最近 7 天扫描量
        from django.db.models.functions import TruncDate
        from django.utils import timezone as tz
        seven_days_ago = tz.now() - tz.timedelta(days=7)
        daily_tasks = list(
            tasks.filter(created_at__gte=seven_days_ago)
            .annotate(date=TruncDate('created_at'))
            .values('date').annotate(count=Count('id'))
            .order_by('date')
        )
        # 补齐空白天数
        daily_map = {str(d['date']): d['count'] for d in daily_tasks}
        for i in range(7):
            d = (seven_days_ago + tz.timedelta(days=i)).strftime('%Y-%m-%d')
            if d not in daily_map:
                daily_tasks.append({'date': d, 'count': 0})
        daily_tasks.sort(key=lambda x: str(x['date']))

        return JsonResponse({
            "code": 200,
            "lang_dist": lang_dist,
            "level_dist": level_dist,
            "task_status": task_status,
            "daily_tasks": daily_tasks,
        })


class GraphScansApiView(View):
    """列出 workspace 中有图数据的 scan"""

    @staticmethod
    @login_or_token_required
    def get(request):
        try:
            from core.graph.workspace import get_workspace_db
            import sqlite3

            workspace_db = get_workspace_db()
            conn = sqlite3.connect(workspace_db)
            conn.row_factory = sqlite3.Row
            conn.execute(
                "CREATE TABLE IF NOT EXISTS scans ("
                "id INTEGER PRIMARY KEY, language TEXT, target TEXT, "
                "graph_path TEXT, file_count INTEGER, node_count INTEGER, "
                "edge_count INTEGER, created_at TEXT)"
            )
            cur = conn.execute("SELECT * FROM scans ORDER BY id DESC")
            scans = [dict(row) for row in cur.fetchall()]
            conn.close()

            # 反查 project_id（scan_id 即 ScanTask.id）
            scan_ids = [s["id"] for s in scans if s.get("id")]
            if scan_ids:
                task_map = dict(
                    ScanTask.objects.filter(id__in=scan_ids).values_list("id", "project_id")
                )
                for s in scans:
                    s["project_id"] = task_map.get(s["id"])

            return JsonResponse({"code": 200, "scans": scans})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})


class GraphLoadApiView(View):
    """加载 graph session 到进程缓存。

    POST 参数:
        scan_id: 扫描 ID (必填)

    大型图加载需要数秒到数十秒，客户端应轮询 /api/graph/status 或
    使用返回的 load_time 估算。
    """

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @staticmethod
    @login_or_token_required
    def post(request):
        scan_id = request.POST.get("scan_id") or request.GET.get("scan_id")
        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})
        try:
            scan_id = int(scan_id)
        except ValueError:
            return JsonResponse({"code": 400, "error": "invalid scan_id"})

        from web.api.graph_session_manager import load_session, session_info

        # 如果已经加载，直接返回
        existing = session_info()
        for s in existing.get("loaded", []):
            if s.get("scan_id") == scan_id:
                return JsonResponse({
                    "code": 200,
                    "message": "Already loaded",
                    "scan_id": scan_id,
                    **s,
                })

        session, error = load_session(scan_id)
        if error:
            return JsonResponse({"code": 500, "error": error})

        info = session_info()
        for s in info.get("loaded", []):
            if s.get("scan_id") == scan_id:
                return JsonResponse({"code": 200, **s})

        return JsonResponse({"code": 200, "message": "Loaded"})


class GraphReleaseApiView(View):
    """释放已加载的 graph session，回收内存。"""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    @staticmethod
    @login_or_token_required
    def post(request):
        from web.api.graph_session_manager import release_session
        scan_id = request.POST.get("scan_id") or request.GET.get("scan_id")
        if not scan_id:
            # 释放所有
            from web.api.graph_session_manager import _release_all
            _release_all()
            return JsonResponse({"code": 200, "message": "All sessions released"})
        try:
            scan_id = int(scan_id)
        except ValueError:
            return JsonResponse({"code": 400, "error": "invalid scan_id"})

        released = release_session(scan_id)
        if released:
            return JsonResponse({"code": 200, "message": f"Session {scan_id} released"})
        return JsonResponse({"code": 404, "message": f"No session for scan {scan_id}"})


class GraphStatusApiView(View):
    """查询当前 graph session 缓存状态。"""

    @staticmethod
    @login_or_token_required
    def get(request):
        from web.api.graph_session_manager import session_info
        return JsonResponse({"code": 200, **session_info()})


class GraphQueryApiView(View):
    """AST 图查询 API — 对应 CLI analyze 子命令"""

    @staticmethod
    @login_or_token_required
    def get(request):
        scan_id = request.GET.get("scan_id")
        query_type = request.GET.get("query_type", "overview")
        query_arg = request.GET.get("query_arg", "")

        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})

        session, err = _get_cached_session(scan_id)
        if err:
            return err

        try:
            if query_type == "overview":
                result = session.query.overview()
            elif query_type == "file":
                result = session.query.get_file(query_arg)
            elif query_type == "function":
                result = session.query.get_function(query_arg)
            elif query_type == "trace":
                parts = query_arg.rsplit(":", 1)
                if len(parts) != 2:
                    return JsonResponse({"code": 400, "error": "trace format: file:line"})
                result = session.query.trace(parts[0], int(parts[1]))
            elif query_type == "search":
                label = request.GET.get("label") or (query_arg.split(":", 2)[0] if query_arg else None) or None
                name = request.GET.get("name") or (query_arg.split(":", 2)[1] if query_arg and ":" in query_arg else None) or None
                result = session.query.search(label=label, name=name)
            elif query_type == "call_graph":
                depth = int(request.GET.get("depth", "2"))
                direction = request.GET.get("direction", "both")
                result = session.query.get_call_graph(
                    func_name=query_arg, depth=depth, direction=direction,
                )
            elif query_type == "trace_variable":
                var_file = request.GET.get("file_path", "")
                result = session.query.trace_variable(
                    var_name=query_arg, file_path=var_file or None,
                )
            else:
                return JsonResponse({"code": 400, "error": f"Unknown query type: {query_type}"})

            return JsonResponse({"code": 200, "data": result})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})


class GraphSubgraphApiView(View):
    """AST 子图提取 API — 返回指定节点周围的子图用于可视化。

    GET 参数:
        scan_id: 扫描 ID (必填)
        vid: 中心节点 vid (必填，与 file_path 二选一)
        file_path: 文件路径 (必填，与 vid 二选一，提取整个文件的子图)
        depth: BFS 深度 (默认 2，仅 vid 模式)
        edge_labels: 边类型过滤，逗号分隔 (如 own,cg,dfg)
        max_nodes: 最大节点数 (默认 500)
    """

    @staticmethod
    @login_or_token_required
    def get(request):
        scan_id = request.GET.get("scan_id")
        vid = request.GET.get("vid")
        file_path = request.GET.get("file_path")
        depth = int(request.GET.get("depth", 2))
        edge_labels_str = request.GET.get("edge_labels", "")
        max_nodes = int(request.GET.get("max_nodes", 500))

        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})

        if not vid and not file_path:
            return JsonResponse({"code": 400, "error": "vid or file_path required"})

        session, err = _get_cached_session(scan_id)
        if err:
            return err

        edge_labels = [x.strip() for x in edge_labels_str.split(",") if x.strip()] or None

        try:
            if file_path:
                result = session.query.get_file_subgraph(
                    file_path, include_cross_edges=True, max_nodes=max_nodes
                )
            else:
                result = session.query.get_subgraph(
                    int(vid), depth=depth, edge_labels=edge_labels, max_nodes=max_nodes
                )
            return JsonResponse({"code": 200, "data": result})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})

class GraphChainSubgraphApiView(View):
    """传播链子图 API — 给定一组 vid，返回它们之间的子图用于链路可视化。

    GET 参数:
        scan_id: 扫描 ID (必填)
        vids: 逗号分隔的 vid 列表 (必填)
    """

    @staticmethod
    @login_or_token_required
    def get(request):
        scan_id = request.GET.get("scan_id")
        vids_str = request.GET.get("vids", "")

        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})
        if not vids_str:
            return JsonResponse({"code": 400, "error": "vids required"})

        session, err = _get_cached_session(scan_id)
        if err:
            return err

        vids = []
        for part in vids_str.split(","):
            part = part.strip()
            if part:
                try:
                    vids.append(int(part))
                except ValueError:
                    pass

        if not vids:
            return JsonResponse({"code": 400, "error": "No valid vids"})

        try:
            result = session.query.get_chain_subgraph(vids)
            return JsonResponse({"code": 200, "data": result})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})


# --- 查询节点关联漏洞 ---
class GraphNodeVulnsApiView(View):
    """Return vulnerabilities associated with a specific graph node vid."""

    @staticmethod
    @login_or_token_required
    def get(request):
        scan_id = request.GET.get("scan_id")
        vid = request.GET.get("vid")
        if not scan_id or not vid:
            return JsonResponse({"code": 400, "error": "scan_id and vid required"})

        scan_id = int(scan_id)
        vid = int(vid)

        try:
            from web.index.models import TaintChain
            chains = TaintChain.objects.filter(scan_task=scan_id, vid=vid).values(
                "vul_result", "node_name", "file_path", "lineno", "node_label"
            )[:20]
        except Exception as e:
            return JsonResponse({"code": 404, "error": str(e)})

        vulns = []
        for tc in chains:
            vulns.append({
                "vul_id": tc.get("vul_result", ""),
                "node_content": tc.get("node_name", ""),
                "node_path": tc.get("file_path", ""),
                "node_lineno": tc.get("lineno", ""),
                "node_type": tc.get("node_label", ""),
            })

        return JsonResponse({"code": 200, "data": vulns})


# --- 查询节点源码上下文 ---
class GraphNodeSourceApiView(View):
    """Return source code context for a specific graph node vid.

    GET 参数:
        scan_id: 扫描 ID (必填)
        vid: 节点 VID (必填)
        context_lines: 上下文行数 (默认 5)
    """

    @staticmethod
    @login_or_token_required
    def get(request):
        scan_id = request.GET.get("scan_id")
        vid = request.GET.get("vid")
        context_lines = int(request.GET.get("context_lines", 5))

        if not scan_id or not vid:
            return JsonResponse({"code": 400, "error": "scan_id and vid required"})

        vid = int(vid)
        session, err = _get_cached_session(scan_id)
        if err:
            return err

        try:
            result = session.query.get_node_source_context(vid, context_lines=context_lines)
            return JsonResponse({"code": 200, "data": result})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})
