#!/usr/bin/env python
# -*- coding: utf-8 -*-
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required


class GraphAnalysisView(TemplateView):
    """AST 图分析页面"""
    template_name = "dashboard/graph_analysis.html"
