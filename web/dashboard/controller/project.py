#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: project.py
@time: 2021/7/20 15:50
@desc:

'''


import ast

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect

from Kunlun_M.settings import SUPER_ADMIN
from web.index.controller import login_or_token_required

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc, Project, ProjectVendors
from web.index.models import get_and_check_scanresult, get_and_check_evil_func


class ProjectListView(TemplateView):
    """展示当前用户的项目"""
    template_name = "dashboard/projects/projects_list.html"

    def get_context_data(self, **kwargs):
        context = super(ProjectListView, self).get_context_data(**kwargs)

        rows = Project.objects.all().order_by('-id')

        context['projects'] = rows

        for project in context['projects']:

            tasks = ScanTask.objects.filter(project_id=project.id).order_by('-id')
            tasks_count = len(tasks)

            pvs = ProjectVendors.objects.filter(project_id=project.id)
            vendors_cout = len(pvs)

            # check all scanresulttask
            for task in tasks:
                get_and_check_scanresult(task.id)
                get_and_check_evil_func(task.id)

            results = ScanResultTask.objects.filter(scan_project_id=project.id, is_active=1)
            results_count = len(results)

            last_scan_time = 0
            if tasks:
                last_scan_time = tasks.first().last_scan_time

            project.tasks_count = tasks_count
            project.results_count = results_count
            project.last_scan_time = last_scan_time
            project.vendors_cout = vendors_cout

        return context


class ProjectDetailView(View):
    """展示当前项目细节"""

    @staticmethod
    @login_or_token_required
    def get(request, project_id):
        project = Project.objects.filter(id=project_id).first()

        tasks = ScanTask.objects.filter(project_id=project.id).order_by('-id')
        taskresults = ScanResultTask.objects.filter(scan_project_id=project.id, is_active=1).all()
        newevilfuncs = NewEvilFunc.objects.filter(project_id=project.id).all()
        pvs = ProjectVendors.objects.filter(project_id=project.id)

        for task in tasks:
            task.is_finished = int(task.is_finished)
            task.parameter_config = " ".join(ast.literal_eval(task.parameter_config)).replace('\\', '/')[100:]

        for taskresult in taskresults:
            taskresult.is_unconfirm = int(taskresult.is_unconfirm)

        if not project:
            return HttpResponseNotFound('Project Not Found.')
        else:
            data = {
                'tasks': tasks,
                'taskresults': taskresults,
                'newevilfuncs': newevilfuncs,
                'project': project,
                'project_vendors': pvs,
            }
            return render(request, 'dashboard/projects/project_detail.html', data)
