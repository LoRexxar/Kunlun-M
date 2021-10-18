#!/usr/bin/env python
# encoding: utf-8
'''
@author: LoRexxar
@contact: lorexxar@gmail.com
@file: vendor.py
@time: 2021/8/11 17:05
@desc:

'''

import ast

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound
from django.views.generic import TemplateView
from django.views import View
from django.shortcuts import render, redirect
from django.db.models import Count

from Kunlun_M.settings import SUPER_ADMIN
from Kunlun_M.const import VENDOR_VUL_LEVEL, VUL_LEVEL

from web.index.controller import login_or_token_required
from utils.utils import del_sensitive_for_config
from core.vendors import get_vendor_vul_by_name, get_project_vendor_by_name

from web.index.models import ScanTask, VendorVulns, Rules, ProjectVendors, Project
from web.index.models import get_and_check_scantask_project_id, get_and_check_scanresult, get_and_check_evil_func


class VendorListView(TemplateView):
    """展示所有的组件"""
    template_name = "dashboard/vendors/vendors_list.html"

    def get_context_data(self, **kwargs):
        context = super(VendorListView, self).get_context_data(**kwargs)
        vendor_count = ProjectVendors.objects.all().count()

        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*100 > vendor_count:
            page = 1

        rows = ProjectVendors.objects.all()[(page-1)*100: page*100]

        context['vendors'] = rows

        context['page'] = page
        max_page = vendor_count / 100 if vendor_count % 100 == 0 else (vendor_count / 100)+1
        context['max_page'] = int(max_page)
        context['page_range'] = range(int(max_page))[1:]

        for row in context['vendors']:
            project = Project.objects.filter(id=row.project_id).first()

            row.project_name = project.project_name

        return context


class VendorVulnListView(TemplateView):
    """展示所有的组件漏洞"""
    template_name = "dashboard/vendors/vendors_vuln_list.html"

    def get_context_data(self, **kwargs):
        context = super(VendorVulnListView, self).get_context_data(**kwargs)
        vendor_vulns_count = VendorVulns.objects.all().count()

        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*100 > vendor_vulns_count:
            page = 1

        rows = VendorVulns.objects.all()[(page-1)*100: page*100]

        context['vendorvulns'] = rows

        context['page'] = page
        max_page = vendor_vulns_count / 100 if vendor_vulns_count % 100 == 0 else (vendor_vulns_count / 100)+1
        context['max_page'] = int(max_page)
        context['page_range'] = range(int(max_page))[1:]

        for vendorvul in context['vendorvulns']:
            vendorvul.severity = VENDOR_VUL_LEVEL[vendorvul.severity]
            vendorvul.cves = ','.join(ast.literal_eval(vendorvul.cves))

            afversions = str(vendorvul.affected_versions).split(',')
            if len(afversions) > 2:
                display_version = afversions[:2]
                display_version.append('...')
            else:
                display_version = afversions

            vendorvul.affected_versions = ','.join(display_version)

        return context


class VendorDetailView(View):
    """展示当前组件细节"""

    @staticmethod
    @login_or_token_required
    def get(request):

        if "vendorname" in request.GET:
            vendor_name = request.GET['vendorname']
        else:
            redirect('dashboard:vendors_list')
            return

        vs = get_project_vendor_by_name(vendor_name)
        projects = []
        vvulns = []

        for v in vs:
            project_id = v.project_id
            v_name = v.name
            vvs = get_vendor_vul_by_name(v_name.strip())
            p = Project.objects.filter(id=project_id).first()
            p.vendor_name = v_name
            p.version = v.version

            projects.append(p)
            vvulns.extend(list(vvs))
            vvulns = list(set(vvulns))

        if not len(vs):
            return HttpResponseNotFound('Vendor Not Found.')
        else:
            data = {
                'vendor_name': vendor_name,
                'vendors': vs,
                'projects': projects,
                'vvulns': vvulns,
            }
            return render(request, 'dashboard/vendors/vendor_detail.html', data)


class VendorVulnDetailView(View):
    """展示当前组件漏洞细节"""

    @staticmethod
    @login_or_token_required
    def get(request, vendor_vul_id):
        vvuln_references = []
        vvuln = VendorVulns.objects.filter(id=vendor_vul_id).first()

        vvuln.affected_versions = vvuln.affected_versions.replace(",", '\n')
        if vvuln.reference.startswith("["):
            vvuln_references = ast.literal_eval(vvuln.reference)
        else:
            vvuln_references = [vvuln.reference]

        if not vvuln:
            return HttpResponseNotFound('Vendor vuls Not Found.')
        else:
            data = {
                'vvuln': vvuln,
                "vvuln_references": vvuln_references,
            }
            return render(request, 'dashboard/vendors/vendor_vuln_detail.html', data)


class VendorStatisticsView(TemplateView):
    """展示所有的组件"""
    template_name = "dashboard/vendors/vendors_statistics.html"

    def get_context_data(self, **kwargs):
        context = super(VendorStatisticsView, self).get_context_data(**kwargs)
        pvs = ProjectVendors.objects.values('name', 'language').annotate(total=Count('id')).order_by('total')
        vendor_count = pvs.count()

        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*100 > vendor_count:
            page = 1

        rows = pvs[::-1][(page-1)*100: page*100]

        context['vendors'] = rows

        context['page'] = page
        max_page = vendor_count / 100 if vendor_count % 100 == 0 else (vendor_count / 100)+1
        context['max_page'] = int(max_page)
        context['page_range'] = range(int(max_page))[1:]

        id = (page-1)*100+1
        for pv in context['vendors']:
            pv['id'] = id
            id += 1

        return context


class VendorVulnStatisticsView(TemplateView):
    """展示所有的组件"""
    template_name = "dashboard/vendors/vendors_vuln_statistics.html"

    def get_context_data(self, **kwargs):
        context = super(VendorVulnStatisticsView, self).get_context_data(**kwargs)
        vns = VendorVulns.objects.values('vendor_name').annotate(total=Count('id')).order_by('total')
        vendor_vulns_count = vns.count()

        if 'p' in self.request.GET:
            page = int(self.request.GET['p'])
        else:
            page = 1

        # check page
        if page*100 > vendor_vulns_count:
            page = 1

        rows = vns[::-1][(page-1)*100: page*100]

        context['vendorvulns'] = rows

        context['page'] = page
        max_page = vendor_vulns_count / 100 if vendor_vulns_count % 100 == 0 else (vendor_vulns_count / 100) + 1
        context['max_page'] = int(max_page)
        context['page_range'] = range(int(max_page))[1:]

        id = (page - 1) * 100 + 1
        for vendorvul in context['vendorvulns']:
            vendor_name = vendorvul['vendor_name']
            vendorvul['id'] = id
            id += 1

            vs = get_project_vendor_by_name(vendor_name)
            vendorvul['vendor_count'] = vs.count()

            vvs = get_vendor_vul_by_name(vendor_name)
            vendorvul['high'] = 0
            vendorvul['medium'] = 0
            vendorvul['low'] = 0

            for vv in vvs:
                if vv.severity > 6:
                    vendorvul['high'] += 1
                elif vv.severity > 2:
                    vendorvul['medium'] += 1
                else:
                    vendorvul['low'] += 1

        return context
