#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/3/2 15:15
# @Author  : LoRexxar
# @File    : tasks.py
# @Contact : lorexxar@gmail.com

import ast

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect

from Kunlun_M.settings import SUPER_ADMIN
from web.index.controller import login_or_token_required

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc, Project
from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult, get_and_check_evil_func


class TaskListView(TemplateView):
    """展示当前用户的任务"""
    template_name = "dashboard/tasks/tasks_list.html"

    def get_context_data(self, **kwargs):
        context = super(TaskListView, self).get_context_data(**kwargs)

        rows = ScanTask.objects.all().order_by('-id')

        context['tasks'] = rows

        for task in context['tasks']:
            task.is_finished = int(task.is_finished)
            task.parameter_config = " ".join(ast.literal_eval(task.parameter_config)).replace('\\', '/')

            project_id = get_and_check_scantask_project_id(task.id)
            project = Project.objects.filter(id=project_id).first()

            task.project_name = project.project_name

        return context


class TaskDetailView(View):
    """展示当前任务细节"""

    @staticmethod
    @login_or_token_required
    def get(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        visit_token = ""

        if 'token' in request.GET:
            visit_token = request.GET['token']

        project_id = get_and_check_scantask_project_id(task.id)
        project = Project.objects.filter(id=project_id).first()

        taskresults = get_and_check_scanresult(task.id).objects.filter(scan_project_id=project_id, is_active=1).all()
        newevilfuncs = get_and_check_evil_func(task.id)

        task.is_finished = int(task.is_finished)
        task.parameter_config = " ".join(ast.literal_eval(task.parameter_config)).replace('\\', '/')

        for taskresult in taskresults:
            taskresult.is_unconfirm = int(taskresult.is_unconfirm)

        if not task:
            return HttpResponseNotFound('Task Not Found.')
        else:
            data = {
                'task': task,
                'taskresults': taskresults,
                'newevilfuncs': newevilfuncs,
                'visit_token': visit_token,
                'project': project,
            }
            return render(request, 'dashboard/tasks/task_detail.html', data)
