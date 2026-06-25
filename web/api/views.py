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
from django.db.models import Count
from django.utils import timezone

from web.index.models import ScanTask, VendorVulns, Rules, Project, ProjectVendors, ScanResultTask
from web.index.models import get_and_check_scantask_project_id, get_resultflow_class, get_and_check_scanresult
from core.vendors import get_project_vendor_by_name, get_vendor_vul_by_name

from Kunlun_M.settings import LOGS_PATH


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


class TaskResultFlowApiView(View):
    """展示当前任务结果流细节"""

    @staticmethod
    @api_token_required
    def get(request, task_id):
        scantask = ScanTask.objects.filter(id=task_id).first()

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        ResultFlow = get_resultflow_class(int(task_id))
        rfs = ResultFlow.objects.filter().order_by('vul_id')

        resultflow_list = list(rfs.values())
        return JsonResponse(
            {"code": 200, "status": True, "message": resultflow_list})


class TaskResultFlowDetailApiView(View):
    """展示指定任务结果流细节"""

    @staticmethod
    @api_token_required
    def get(request, result_id, vul_id):
        scantask = ScanResultTask.objects.filter(id=result_id).first()
        task_id = scantask.scan_task_id

        if not scantask.is_finished:
            return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})

        ResultFlow = get_resultflow_class(int(task_id))
        rfs = ResultFlow.objects.filter(vul_id=vul_id)

        resultflow_list = list(rfs.values())
        return JsonResponse(
            {"code": 200, "status": True, "message": resultflow_list})


# class TaskResultFlowDetailDelApiView(View):
#     """删除当前任务结果流细节"""
#
#     @staticmethod
#     @api_token_required
#     def get(request, task_id, vul_id):
#         scantask = ScanTask.objects.filter(id=task_id).first()
#
#         if not scantask.is_finished:
#             return JsonResponse({"code": 403, "status": False, "message": "Task {} not finished.".format(task_id)})
#
#         ResultFlow = get_resultflow_class(int(task_id))
#         rfs = ResultFlow.objects.filter(vul_id=vul_id)
#
#         resultflow_list = list(rfs.values())
#         return JsonResponse(
#             {"code": 200, "status": True, "message": resultflow_list})




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


class StatsApiView(View):
    """仪表盘统计数据"""

    @staticmethod
    @login_required
    def get(request):
        from django.db.models import Count
        from web.index.models import ScanResultTask, Rules, ScanTask

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


class GraphQueryApiView(View):
    """AST 图查询 API — 对应 CLI analyze 子命令"""

    @staticmethod
    @login_or_token_required
    def get(request):
        import os
        from core.graph.session import AstGraphSession
        from core.graph.workspace import get_workspace_db, get_scan_dir

        scan_id = request.GET.get("scan_id")
        query_type = request.GET.get("query_type", "overview")
        query_arg = request.GET.get("query_arg", "")

        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})

        workspace_db = get_workspace_db()
        graph_dir = get_scan_dir(scan_id)

        # Verify graph exists
        graph_path = os.path.join(graph_dir, "graph.graphmlz")
        if not os.path.exists(graph_path):
            return JsonResponse({"code": 404, "error": f"Graph not found for scan {scan_id}"})

        # Get language from scan record
        from core.graph.sqlite_index import ScanRecord
        sr = ScanRecord(workspace_db)
        info = sr.get_by_id(scan_id)
        language = info.get("language", "php") if info else "php"

        try:
            session = AstGraphSession(graph_dir, db_path=workspace_db, language=language)
            session.load()

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
                tokens = query_arg.split(":", 2)
                label = tokens[0] if len(tokens) > 0 else None
                name = tokens[1] if len(tokens) > 1 else None
                result = session.query.search(label=label or None, name=name or None)
            elif query_type == "call_graph":
                depth = int(request.GET.get("depth", "2"))
                direction = request.GET.get("direction", "both")
                result = session.query.get_call_graph(
                    func_name=query_arg,
                    depth=depth,
                    direction=direction,
                )
            elif query_type == "trace_variable":
                var_file = request.GET.get("file_path", "")
                result = session.query.trace_variable(
                    var_name=query_arg,
                    file_path=var_file or None,
                )
            else:
                return JsonResponse({"code": 400, "error": f"Unknown query type: {query_type}"})

            session.close()
            return JsonResponse({"code": 200, "data": result})
        except FileNotFoundError as e:
            return JsonResponse({"code": 404, "error": str(e)})
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
        import os
        from core.graph.session import AstGraphSession
        from core.graph.workspace import get_workspace_db, get_scan_dir

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

        graph_dir = get_scan_dir(scan_id)
        graph_path = os.path.join(graph_dir, "graph.graphmlz")
        if not os.path.exists(graph_path):
            return JsonResponse({"code": 404, "error": f"Graph not found for scan {scan_id}"})

        workspace_db = get_workspace_db()
        from core.graph.sqlite_index import ScanRecord
        sr = ScanRecord(workspace_db)
        info = sr.get_by_id(scan_id)
        language = info.get("language", "php") if info else "php"

        edge_labels = [x.strip() for x in edge_labels_str.split(",") if x.strip()] or None

        try:
            session = AstGraphSession(graph_dir, db_path=workspace_db, language=language)
            session.load()

            if file_path:
                result = session.query.get_file_subgraph(
                    file_path, include_cross_edges=True, max_nodes=max_nodes
                )
            else:
                result = session.query.get_subgraph(
                    int(vid), depth=depth, edge_labels=edge_labels, max_nodes=max_nodes
                )

            session.close()
            return JsonResponse({"code": 200, "data": result})
        except FileNotFoundError as e:
            return JsonResponse({"code": 404, "error": str(e)})
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
        import os
        from core.graph.session import AstGraphSession
        from core.graph.workspace import get_workspace_db, get_scan_dir

        scan_id = request.GET.get("scan_id")
        vids_str = request.GET.get("vids", "")

        if not scan_id:
            return JsonResponse({"code": 400, "error": "scan_id required"})
        if not vids_str:
            return JsonResponse({"code": 400, "error": "vids required"})

        graph_dir = get_scan_dir(scan_id)
        graph_path = os.path.join(graph_dir, "graph.graphmlz")
        if not os.path.exists(graph_path):
            return JsonResponse({"code": 404, "error": f"Graph not found for scan {scan_id}"})

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

        workspace_db = get_workspace_db()
        from core.graph.sqlite_index import ScanRecord
        sr = ScanRecord(workspace_db)
        info = sr.get_by_id(scan_id)
        language = info.get("language", "php") if info else "php"

        try:
            session = AstGraphSession(graph_dir, db_path=workspace_db, language=language)
            session.load()
            result = session.query.get_chain_subgraph(vids)
            session.close()
            return JsonResponse({"code": 200, "data": result})
        except FileNotFoundError as e:
            return JsonResponse({"code": 404, "error": str(e)})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})


# --- 查询节点关联漏洞 ---
class GraphNodeVulnsApiView(View):
    """Return vulnerabilities associated with a specific graph node vid."""

    @staticmethod
    @login_or_token_required
    def get(self, request):
        scan_id = request.GET.get("scan_id")
        vid = request.GET.get("vid")
        if not scan_id or not vid:
            return JsonResponse({"code": 400, "error": "scan_id and vid required"})

        scan_id = int(scan_id)
        vid = int(vid)

        try:
            from web.index.models import get_resultflow_class
            ResultFlow = get_resultflow_class(scan_id)
        except Exception:
            return JsonResponse({"code": 200, "data": []})

        vulns = []
        for rf in ResultFlow.objects.filter(node_vid=vid).values(
            "vul_id", "node_content", "node_path", "node_lineno", "node_type"
        )[:20]:
            vulns.append({
                "vul_id": rf.get("vul_id", ""),
                "node_content": rf.get("node_content", ""),
                "node_path": rf.get("node_path", ""),
                "node_lineno": rf.get("node_lineno", ""),
                "node_type": rf.get("node_type", ""),
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
        import os
        from core.graph.session import AstGraphSession
        from core.graph.workspace import get_workspace_db, get_scan_dir

        scan_id = request.GET.get("scan_id")
        vid = request.GET.get("vid")
        context_lines = int(request.GET.get("context_lines", 5))

        if not scan_id or not vid:
            return JsonResponse({"code": 400, "error": "scan_id and vid required"})

        vid = int(vid)
        graph_dir = get_scan_dir(scan_id)
        graph_path = os.path.join(graph_dir, "graph.graphmlz")
        if not os.path.exists(graph_path):
            return JsonResponse({"code": 404, "error": f"Graph not found for scan {scan_id}"})

        workspace_db = get_workspace_db()
        from core.graph.sqlite_index import ScanRecord
        sr = ScanRecord(workspace_db)
        info = sr.get_by_id(scan_id)
        language = info.get("language", "php") if info else "php"

        try:
            session = AstGraphSession(graph_dir, db_path=workspace_db, language=language)
            session.load()
            result = session.query.get_node_source_context(vid, context_lines=context_lines)
            session.close()
            return JsonResponse({"code": 200, "data": result})
        except FileNotFoundError as e:
            return JsonResponse({"code": 404, "error": str(e)})
        except Exception as e:
            return JsonResponse({"code": 500, "error": str(e)})
