#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView
from django.db.models import Count, Q

from web.index.models import ScanResultTask, ScanTask, Rules, TaintChain, Project
from web.index.models import get_and_check_scantask_project_id
from Kunlun_M.const import VUL_LEVEL


# 节点 label → 可读角色（链的首尾节点语义推断）
_SOURCE_LABELS = frozenset({'source', 'Source', 'SOURCE', 'NewScan'})
_SINK_LABELS = frozenset({'sink', 'Sink', 'SINK'})
_CALLER_LABELS = frozenset({'Function', 'Call', 'Caller', 'Return', 'Identifier', 'Statement', 'Expression'})


def _chain_role(idx, total, label):
    """推断链节点的角色: source / sink / propagation"""
    if idx == 0:
        return 'source'
    if idx == total - 1:
        return 'sink'
    return 'propagation'


class VulListView(TemplateView):
    """全局漏洞列表 — 跨任务查看所有漏洞"""
    template_name = 'dashboard/vuls/vuls_list.html'
    per_page = 50

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        request = self.request
        params = request.GET

        qs = ScanResultTask.objects.filter(is_active=True).only(
            'id', 'scan_task_id', 'cvi_id', 'language', 'vulfile_path',
            'source_code', 'result_type', 'is_unconfirm',
            'verification_status',
        )

        # 筛选
        lang = params.get('lang', '').strip()
        cvi = params.get('cvi', '').strip()
        level = params.get('level', '').strip()
        confirm = params.get('confirm', '').strip()
        search = params.get('q', '').strip()
        task_id = params.get('task_id', '').strip()

        if lang:
            qs = qs.filter(language=lang)
        if cvi:
            qs = qs.filter(cvi_id=cvi)
        if confirm == 'tp':
            qs = qs.filter(verification_status='tp')
        elif confirm == 'fp':
            qs = qs.filter(verification_status='fp')
        elif confirm == 'unconfirmed':
            qs = qs.filter(Q(verification_status='') | Q(verification_status='pending') | Q(verification_status='unknown'))
        if task_id:
            qs = qs.filter(scan_task_id=int(task_id))
        if search:
            qs = qs.filter(
                Q(vulfile_path__icontains=search)
                | Q(source_code__icontains=search)
                | Q(cvi_id__icontains=search)
            )

        # 等级筛选
        level_rule_ids = []
        if level:
            for r in Rules.objects.all().only('svid', 'level'):
                if r.level < len(VUL_LEVEL) and VUL_LEVEL[r.level].lower() == level.lower():
                    level_rule_ids.append(r.svid)
            if level_rule_ids:
                qs = qs.filter(cvi_id__in=level_rule_ids)
            else:
                qs = qs.none()

        total = qs.count()

        # 分页
        page = int(params.get('p', 1))
        if page < 1:
            page = 1
        max_page = max(1, (total + self.per_page - 1) // self.per_page)
        if page > max_page:
            page = max_page

        rows = qs.order_by('-id')[(page - 1) * self.per_page : page * self.per_page]

        # 批量获取规则信息
        cvi_set = set(r.cvi_id for r in rows if r.cvi_id != '9999')
        rules_map = {}
        for r in Rules.objects.filter(svid__in=cvi_set).only('svid', 'rule_name', 'level'):
            rules_map[r.svid] = r

        # 批量获取传播链（含 source_code 和 vid）
        vul_ids = [r.id for r in rows]
        chain_map = {}
        for tc in TaintChain.objects.filter(vul_result__in=vul_ids).order_by('vul_result', 'chain_index', 'step_order'):
            chain_map.setdefault(tc.vul_result, []).append({
                'type': tc.node_label,
                'content': tc.node_name or '',
                'path': tc.file_path or '',
                'lineno': tc.lineno or 0,
                'vid': tc.vid,
                'source_code': tc.source_code or '',
            })

        # 批量获取项目名
        task_ids = list(set(r.scan_task_id for r in rows))
        task_project_map = {}
        for t in ScanTask.objects.filter(id__in=task_ids).only('id', 'project_id', 'task_name'):
            task_project_map[t.id] = t

        project_cache = {}
        def get_project_name(pid):
            if pid not in project_cache:
                p = Project.objects.filter(id=pid).first()
                project_cache[pid] = p.project_name if p else '-'
            return project_cache[pid]

        # 构建结果列表
        results = []
        for r in rows:
            rule = rules_map.get(r.cvi_id)
            level_str = VUL_LEVEL[rule.level] if rule and rule.level < len(VUL_LEVEL) else ''
            rule_name = rule.rule_name if rule else r.cvi_id

            chains = list(reversed(chain_map.get(r.id, [])))
            n = len(chains)

            # 构建链摘要: [Sink] name → ... → [Source] name
            chain_summary = ''
            if chains:
                parts = []
                for i, c in enumerate(chains[:8]):
                    role = _chain_role(i, n, c['type'])
                    name = c['content'] or c['type']
                    fname = (c['path'] or '').split('/')[-1]
                    if fname:
                        parts.append(f'{fname}:{c["lineno"]} {name}')
                    else:
                        parts.append(name)
                if n > 8:
                    parts.append('...')
                chain_summary = ' → '.join(parts)

            task_info = task_project_map.get(r.scan_task_id)
            project_name = get_project_name(task_info.project_id) if task_info else '-'
            task_name = task_info.task_name if task_info else '-'

            results.append({
                'id': r.id,
                'scan_task_id': r.scan_task_id,
                'task_name': task_name,
                'project_name': project_name,
                'cvi_id': r.cvi_id,
                'language': r.language,
                'vulfile_path': r.vulfile_path,
                'source_code': r.source_code,
                'result_type': r.result_type,
                'rule_name': rule_name,
                'level': level_str,
                'level_lower': level_str.lower(),
                'is_unconfirm': r.is_unconfirm,
                'verification_status': r.verification_status,
                'chain_summary': chain_summary,
                'chain_nodes_json': json.dumps(chains, ensure_ascii=False),
                'has_chain': len(chains) > 0,
            })

        ctx['results'] = results
        ctx['total'] = total
        ctx['page'] = page
        ctx['max_page'] = max_page
        ctx['page_range'] = range(1, max_page + 1)

        # 获取语言/CVI 选项
        ctx['languages'] = sorted(
            ScanResultTask.objects.filter(is_active=True)
            .values_list('language', flat=True).distinct()
        )
        ctx['cvi_ids'] = sorted(
            ScanResultTask.objects.filter(is_active=True)
            .values_list('cvi_id', flat=True).distinct()
        )

        # 保留筛选参数
        ctx['f_lang'] = lang
        ctx['f_cvi'] = cvi
        ctx['f_level'] = level
        ctx['f_confirm'] = confirm
        ctx['f_q'] = search
        ctx['f_task_id'] = task_id

        return ctx
