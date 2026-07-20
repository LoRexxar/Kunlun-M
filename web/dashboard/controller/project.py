#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: project.py
@time: 2021/7/20 15:50
@desc:

'''


import re
import ast
from datetime import datetime, timezone as dt_timezone

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect
from django.urls import reverse

from Kunlun_M.settings import SUPER_ADMIN
from Kunlun_M.const import VUL_LEVEL, VENDOR_VUL_LEVEL

from web.index.controller import login_or_token_required
from utils.utils import del_sensitive_for_config

from web.index.models import ScanTask, ScanResultTask, Rules, NewEvilFunc, Project, ProjectVendors, VendorVulns
from web.index.models import search_project_by_name


class ProjectListView(TemplateView):
    """展示当前用户的项目"""
    template_name = "dashboard/projects/projects_list.html"

    def get_context_data(self, **kwargs):
        context = super(ProjectListView, self).get_context_data(**kwargs)

        # 搜索项目
        search_project_name = ""
        if "project_name" in self.request.GET:
            search_project_name = self.request.GET['project_name']

        rows = search_project_by_name(search_project_name)
        project_count = Project.objects.all().count()

        # 分页
        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*50 > project_count:
            page = 1

        context['projects'] = rows[(page-1)*50: page*50]
        context['page'] = page

        for project in context['projects']:

            tasks = ScanTask.objects.filter(project_id=project.id).order_by('-id')
            tasks_count = len(tasks)

            vendors_count = ProjectVendors.objects.filter(project_id=project.id).count()

            results_count = ScanResultTask.objects.filter(scan_project_id=project.id, is_active=1).count()

            last_scan_time = None
            if tasks:
                last_scan_time = tasks.first().last_scan_time

            project.tasks_count = tasks_count
            project.results_count = results_count
            project.last_scan_time = last_scan_time
            project.vendors_count = vendors_count

        min_dt = datetime.min.replace(tzinfo=dt_timezone.utc)
        context['projects'] = sorted(context['projects'], key=lambda x: x.last_scan_time or min_dt, reverse=True)

        # context['projects'] = context['projects'][(page-1)*50: page*50]

        max_page = project_count // 50 if project_count % 50 == 0 else (project_count // 50)+1
        max_page = max_page+1 if max_page == 1 else max_page

        context['max_page'] = max_page
        context['page_range'] = range(int(max_page))[1:]
        context['search_project_name'] = search_project_name

        return context


class ProjectDetailView(View):
    """展示当前项目细节"""

    @staticmethod
    @login_or_token_required
    def get(request, project_id):
        project = Project.objects.filter(id=project_id).first()

        tasks = ScanTask.objects.filter(project_id=project.id).order_by('-id')[:20]
        taskresults = ScanResultTask.objects.filter(scan_project_id=project.id, is_active=1).all()
        newevilfuncs = NewEvilFunc.objects.filter(project_id=project.id).all()
        pvs = ProjectVendors.objects.filter(project_id=project.id)

        for task in tasks:
            task.is_finished = int(task.is_finished)
            task.parameter_config = del_sensitive_for_config(task.parameter_config)

        # 加载漏洞链数据
        chain_map = {}
        source_root = ''
        finished_tasks = [t for t in tasks if int(t.is_finished) == 1]
        task_ids = [t.id for t in finished_tasks]
        if task_ids:
            try:
                from web.index.models import TaintChain
                srt_ids = [tr.id for tr in taskresults]
                for tc in TaintChain.objects.filter(scan_task__in=task_ids, vul_result__in=srt_ids).order_by('vul_result', 'chain_index', 'step_order'):
                    chain_map.setdefault(tc.vul_result, []).append({
                        'type': tc.node_label,
                        'content': tc.node_name or '',
                        'path': tc.file_path or '',
                        'lineno': str(tc.lineno or ''),
                        'source': tc.source_code or '',
                        'vid': tc.vid,
                    })
                source_root = finished_tasks[0].source_dir or finished_tasks[0].target_path or ''
            except Exception as e:
                import logging
                logging.getLogger('django').warning('[chain] load chain data failed: %s', e)

        for taskresult in taskresults:
            taskresult.is_unconfirm = int(taskresult.is_unconfirm)
            taskresult.level = 0
            taskresult.vid = 0
            taskresult.chain_nodes = chain_map.get(taskresult.id, [])
            taskresult.has_chain = len(taskresult.chain_nodes) > 0

            if taskresult.cvi_id == '9999':
                taskresult.rule_name = 'Vendor Vuln'
                vender_vul_id = taskresult.vulfile_path.split(":")[-1]
                if vender_vul_id:
                    vv = VendorVulns.objects.filter(id=vender_vul_id).first()

                    if vv:
                        taskresult.vulfile_path = "[{}]{}".format(vv.vendor_name, vv.title)
                        taskresult.level = VENDOR_VUL_LEVEL[vv.severity]
                        taskresult.vid = vv.id

                    # 处理多个refer的显示问题
                    references = []
                    if re.search(r'"http[^"]+"', taskresult.source_code, re.I):
                        rs = re.findall(r'"http[^"]+"', taskresult.source_code, re.I)
                        for r in rs:
                            references.append(r.strip('"'))
                    else:
                        references = [taskresult.source_code.strip('"')]

                    taskresult.source_code = references

            else:
                r = Rules.objects.filter(svid=taskresult.cvi_id).first()
                taskresult.level = VUL_LEVEL[r.level]
                taskresult.rule_name = r.rule_name if r else taskresult.cvi_id

        if not project:
            return HttpResponseNotFound('Project Not Found.')
        else:
            # 构建 chain JSON 供前端使用
            chain_json_map = {}
            for tr in taskresults:
                if tr.has_chain:
                    chain_json_map[str(tr.id)] = tr.chain_nodes
            import json as _json
            chain_json = _json.dumps(chain_json_map, ensure_ascii=False)

            data = {
                'tasks': tasks,
                'taskresults': taskresults,
                'newevilfuncs': newevilfuncs,
                'project': project,
                'project_vendors': pvs,
                'source_root': source_root,
                'chain_json': chain_json,
            }
            return render(request, 'dashboard/projects/project_detail.html', data)
