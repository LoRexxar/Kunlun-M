#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/9 15:36
# @Author  : LoRexxar
# @File    : tamper.py
# @Contact : lorexxar@gmail.com

from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect
from django.db.models import Q

from web.index.models import Tampers


class TamperListView(TemplateView):
    """展示所有tamper"""
    template_name = "dashboard/tampers/tampers_list.html"

    def get_context_data(self, **kwargs):
        context = super(TamperListView, self).get_context_data(**kwargs)
        tampers_details = {}

        ts = Tampers.objects.all()
        i = 1

        for t in ts:
            if t.tam_name in tampers_details:
                if t.tam_type == 'Filter-Function':
                    tampers_details[t.tam_name]['FilterFunction'][t.tam_key] = t.tam_value
                elif t.tam_type == 'Input-Control':
                    tampers_details[t.tam_name]['InputControl'].append(t.tam_value)

            else:
                tampers_details[t.tam_name] = {
                    'id': i,
                    'FilterFunction': {},
                    'InputControl': []
                }
                i += 1

        context['tampers'] = tampers_details

        return context


class TamperDetailView(View):
    """展示当前任务细节"""

    @staticmethod
    def get(request, task_id):
        tampers = Tampers.objects.all()

        if not tampers:
            return HttpResponseNotFound('Task Not Found.')
        else:
            data = {
                'tampers': tampers
            }
            return render(request, 'dashboard/tasks/task_detail.html', data)
