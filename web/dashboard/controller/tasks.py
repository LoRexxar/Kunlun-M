#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/3/2 15:15
# @Author  : LoRexxar
# @File    : tasks.py
# @Contact : lorexxar@gmail.com

from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect

from Kunlun_M.settings import SUPER_ADMIN

from web.index.models import ScanTask, ScanResultTask, Rules, Tampers, NewEvilFunc


class TaskListView(TemplateView):
    """展示当前用户的任务"""
    template_name = "dashboard/tasks/tasks_list.html/"

    def get_context_data(self, **kwargs):
        context = super(TaskListView, self).get_context_data(**kwargs)

        rows = ScanTask.objects.all().order_by('-id')

        context['tasks'] = rows

        for task in context['tasks']:
            task.is_finished = int(task.is_finished)
            task.parameter_config = " ".join(eval(task.parameter_config)).replace('\\', '/')

        return context


class TaskDetailView(View):
    """展示当前任务细节"""

    @staticmethod
    def get(request, task_id):
        task = ScanTask.objects.filter(id=task_id).first()
        taskresults = ScanResultTask.objects.filter(scan_task_id=task_id).all()
        newevilfuncs = NewEvilFunc.objects.filter(scan_task_id=task_id).all()

        task.is_finished = int(task.is_finished)
        task.parameter_config = " ".join(eval(task.parameter_config)).replace('\\', '/')

        for taskresult in taskresults:
            taskresult.is_unconfirm = int(taskresult.is_unconfirm)

        if not task:
            return HttpResponseNotFound('Task Not Found.')
        else:
            data = {
                'task': task,
                'taskresults': taskresults,
                'newevilfuncs': newevilfuncs,
            }
            return render(request, 'dashboard/tasks/task_detail.html', data)
