#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/7/5 10:41
# @Author  : LoRexxar
# @File    : rules.py
# @Contact : lorexxar@gmail.com

from django.http import HttpResponseNotFound
from django.shortcuts import render
from django.views import View
from django.views.generic import TemplateView

from web.index.models import Rules


class RuleListView(TemplateView):
    """展示所有规则"""
    template_name = "dashboard/rules/rules_list.html"

    def get_context_data(self, **kwargs):
        context = super(RuleListView, self).get_context_data(**kwargs)

        rows = Rules.objects.filter()
        context['rules'] = rows

        return context


class RuleDetailView(View):
    """展示规则细节"""

    @staticmethod
    def get(request, rule_id):
        row = Rules.objects.filter(id=rule_id).first()

        # 这里有模板注入，真是个令人悲伤的故事
        if not row:
            return HttpResponseNotFound('Rule Not Found.')
        else:
            data = {
                'rule': row,
            }
            return render(request, 'dashboard/rules/rules_detail.html', data)
