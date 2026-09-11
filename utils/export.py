# -*- coding: utf-8 -*-

"""
    export
    ~~~~~~

    Export scan result to files or console

    :author:    40huo <git@40huo.cn>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import csv
import json
import os
import re
from collections import Counter
from codecs import open
from datetime import datetime

from prettytable import PrettyTable

from Kunlun_M.settings import RUNNING_PATH, EXPORT_PATH, DEFAULT_RESULT_PATH, HTML_TEMPLATE_PATH
from utils.log import logger

import html

try:
    import jinja2
except ImportError:
    jinja2 = None

try:
    # Python 2
    _unicode = unicode
except NameError:
    # Python 3
    _unicode = str


def dict_to_xml(dict_obj, line_padding=''):
    """
    Convert scan result to XML string.
    :param dict_obj:a dict object
    :param line_padding:
    :return: XML String
    """
    result_list = []

    if isinstance(dict_obj, list):
        for list_id, sub_elem in enumerate(dict_obj):
            result_list.append(' ' * 4 + '<vul>')
            result_list.append(dict_to_xml(sub_elem, line_padding))
            result_list.append(' ' * 4 + '</vul>')

        return '\n'.join(result_list)

    if isinstance(dict_obj, dict):
        for tag_name in dict_obj:
            sub_obj = dict_obj[tag_name]
            if isinstance(sub_obj, _unicode):
                sub_obj = html.escape(sub_obj)
            result_list.append('%s<%s>' % (line_padding, tag_name))
            result_list.append(dict_to_xml(sub_obj, ' ' * 4 + line_padding))
            result_list.append('%s</%s>' % (line_padding, tag_name))

        return '\n'.join(result_list)

    return '%s%s' % (line_padding, dict_obj)


def dict_to_json(dict_obj):
    """
    Convert scan result to JSON string.
    :param dict_obj: a dict object
    :return: JSON String
    """
    return json.dumps(dict_obj, ensure_ascii=False, indent=2)


def _iso_utc_now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _safe_str(v):
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return repr(v)


def _guess_severity(analysis):
    t = _safe_str(analysis).lower()
    for name in ["critical", "high", "medium", "low"]:
        if name in t:
            return name
    return "unknown"


def _rel_path(p, base_dir):
    if not p:
        return ""
    try:
        if base_dir:
            bp = os.path.normpath(base_dir)
            pp = os.path.normpath(p)
            if pp.startswith(bp):
                return pp[len(bp):].lstrip("\\/") or os.path.basename(pp)
    except Exception:
        pass
    return p


def _normalize_vulnerabilities(vul_list, target_directory):
    normalized = []
    for v in vul_list or []:
        if not isinstance(v, dict):
            try:
                v = v.__dict__
            except Exception:
                v = {"value": v}

        file_path = v.get("file_path") or v.get("file") or ""
        line_number = v.get("line_number")
        try:
            line_number = int(line_number) if line_number is not None else None
        except Exception:
            line_number = None

        analysis = v.get("analysis") or ""
        sev = v.get("severity") or _guess_severity(analysis)
        relative_file = _rel_path(file_path, target_directory)
        location = "{}{}".format(relative_file, "" if line_number is None else ":" + str(line_number))

        is_unconfirm = v.get("is_unconfirm")
        if is_unconfirm is None:
            is_unconfirm = "unconfirmed" in _safe_str(analysis).lower()

        nv = dict(v)
        nv["severity"] = sev
        nv["relative_file"] = relative_file
        nv["location"] = location
        nv["is_unconfirm"] = bool(is_unconfirm)
        normalized.append(nv)

    def _sev_rank(name):
        order = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return order.get(_safe_str(name).lower().strip(), 0)

    normalized.sort(key=lambda x: (-_sev_rank(x.get("severity")), _safe_str(x.get("rule_name")), _safe_str(x.get("relative_file")), x.get("line_number") or 0))
    return normalized


def _build_summary(vul_list):
    total = len(vul_list)
    by_sev = Counter(_safe_str(v.get("severity")) or "unknown" for v in vul_list)
    by_lang = Counter(_safe_str(v.get("language")) or "unknown" for v in vul_list)
    by_rule = Counter(_safe_str(v.get("rule_name")) or "unknown" for v in vul_list)
    files = set((_safe_str(v.get("relative_file")) or _safe_str(v.get("file_path")) or _safe_str(v.get("file"))).strip() for v in vul_list)
    files.discard("")
    unconfirm_total = sum(1 for v in vul_list if v.get("is_unconfirm"))
    return {
        "total_vulns": total,
        "files_affected": len(files),
        "unconfirmed_total": unconfirm_total,
        "by_severity": dict(by_sev),
        "by_language": dict(by_lang),
        "by_rule": dict(by_rule),
    }


def _md_escape(s):
    t = _safe_str(s)
    return t.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "")


def _md_code_escape(s):
    t = _safe_str(s)
    return t.replace("```", "``\\`")


def _render_markdown(report):
    meta = report.get("meta") or {}
    summary = report.get("summary") or {}
    vulns = list(report.get("vulnerabilities") or [])

    lines = []
    lines.append("# Kunlun-M 扫描结果报告")
    lines.append("")
    lines.append("## 元信息")
    lines.append("")
    lines.append("| 字段 | 值 |")
    lines.append("| --- | --- |")
    for k in ["target", "sid", "exported_at", "generator", "schema_version", "target_directory", "language", "framework", "file", "extension", "push_rules", "trigger_rules"]:
        if k in meta:
            lines.append("| {} | {} |".format(_md_escape(k), _md_escape(meta.get(k))))
    lines.append("")
    lines.append("## 汇总")
    lines.append("")
    lines.append("| 指标 | 值 |")
    lines.append("| --- | --- |")
    for k in ["total_vulns", "files_affected", "unconfirmed_total"]:
        if k in summary:
            lines.append("| {} | {} |".format(_md_escape(k), _md_escape(summary.get(k))))
    for k in ["by_severity", "by_language"]:
        if k in summary:
            lines.append("| {} | {} |".format(_md_escape(k), _md_escape(json.dumps(summary.get(k), ensure_ascii=False))))
    lines.append("")
    lines.append("## 概览")
    lines.append("")
    lines.append("| # | severity | cvi_id | rule_name | language | location | unconfirm |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for idx, v in enumerate(vulns, 1):
        lines.append("| [{}](#vuln-{}) | {} | {} | {} | {} | {} | {} |".format(
            idx,
            idx,
            _md_escape(v.get("severity")),
            _md_escape(v.get("id")),
            _md_escape(v.get("rule_name")),
            _md_escape(v.get("language")),
            _md_escape(v.get("location")),
            _md_escape(v.get("is_unconfirm")),
        ))
    lines.append("")
    lines.append("## 详情")
    lines.append("")
    for idx, v in enumerate(vulns, 1):
        title = "{}. {} ({})".format(idx, _safe_str(v.get("rule_name") or "Unknown"), _safe_str(v.get("severity") or "unknown").upper())
        lines.append('<a name="vuln-{}"></a>'.format(idx))
        lines.append("### {}".format(_md_escape(title)))
        lines.append("")
        lines.append("- cvi_id: {}".format(_md_escape(v.get("id"))))
        lines.append("- language: {}".format(_md_escape(v.get("language"))))
        lines.append("- file_path: {}".format(_md_escape(v.get("file_path"))))
        lines.append("- line_number: {}".format(_md_escape(v.get("line_number"))))
        lines.append("- commit_author: {}".format(_md_escape(v.get("commit_author"))))
        lines.append("- is_unconfirm: {}".format(_md_escape(v.get("is_unconfirm"))))
        lines.append("")
        if v.get("analysis"):
            lines.append("**analysis**")
            lines.append("")
            lines.append("```text")
            lines.append(_md_code_escape(v.get("analysis")))
            lines.append("```")
            lines.append("")
        if v.get("code_content"):
            lines.append("**code_content**")
            lines.append("")
            lines.append("```")
            lines.append(_md_code_escape(v.get("code_content")))
            lines.append("```")
            lines.append("")
        if v.get("chain"):
            lines.append("**chain**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(v.get("chain"), ensure_ascii=False, indent=2))
            lines.append("```")
            lines.append("")
        lines.append("**raw**")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(v, ensure_ascii=False, indent=2))
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def _html_escape(s):
    return html.escape(_safe_str(s), quote=True)


_BUILTIN_CSS = """
    :root{--bg:#f4f6fb;--panel:#ffffff;--panel2:#f7f9ff;--text:#0f172a;--muted:#64748b;--border:rgba(15,23,42,.12);--shadow:0 18px 55px rgba(2,6,23,.08);--shadow2:0 10px 28px rgba(2,6,23,.06);--radius:16px;--accent:#2563eb;--good:#10b981;--warn:#f59e0b;--bad:#ef4444;--crit:#7c3aed}
    *{box-sizing:border-box}
    body{margin:0;background:radial-gradient(1100px 760px at 14% 10%,rgba(37,99,235,.14),transparent 62%),radial-gradient(900px 620px at 86% 14%,rgba(124,58,237,.10),transparent 58%),linear-gradient(180deg,#ffffff,var(--bg));color:var(--text);font:14px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,"PingFang SC","Microsoft YaHei",sans-serif}
    .wrap{max-width:1200px;margin:0 auto;padding:28px 18px 48px}
    .hero{background:linear-gradient(135deg,rgba(37,99,235,.10),rgba(124,58,237,.06));border:1px solid var(--border);box-shadow:var(--shadow2);border-radius:22px;padding:22px 22px 18px}
    .hero-top{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:14px;align-items:start}
    .title{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
    h1{margin:0;font-size:26px;letter-spacing:.2px}
    .subtitle{color:var(--muted)}
    .meta{margin-top:14px}
    .sidebar{display:flex;flex-direction:column;gap:10px}
    .sidebox{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:12px 12px;box-shadow:0 10px 24px rgba(2,6,23,.04)}
    .sidebox .t{font-size:12px;color:var(--muted);letter-spacing:.3px;text-transform:uppercase}
    .sidebox .v{margin-top:8px;font-weight:800;font-size:18px;letter-spacing:.2px}
    .sidebox .sub{margin-top:4px;color:var(--muted);font-size:12px}
    .kvs{margin-top:10px;display:flex;flex-direction:column;gap:8px}
    .kvrow{display:flex;gap:10px;justify-content:space-between;align-items:baseline}
    .kvrow .k{color:var(--muted);font-size:12px}
    .kvrow .v{color:rgba(15,23,42,.86);font-size:12px;max-width:210px;word-break:break-all;text-align:right}
    .kv{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:10px 12px;box-shadow:0 10px 25px rgba(2,6,23,.04)}
    .kv .k{color:var(--muted);font-size:12px}
    .kv .v{margin-top:3px;word-break:break-all}
    .cards{margin-top:18px;display:flex;gap:10px;flex-wrap:nowrap;overflow:auto;padding-bottom:2px}
    .card{position:relative;flex:0 0 220px;background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:12px 12px 11px;box-shadow:0 10px 24px rgba(2,6,23,.04);overflow:hidden}
    .card:before{content:"";position:absolute;left:0;top:0;right:0;height:3px;background:linear-gradient(90deg,rgba(37,99,235,.65),rgba(124,58,237,.55))}
    .card:after{content:"";position:absolute;right:-38px;top:-38px;width:96px;height:96px;border-radius:999px;background:radial-gradient(circle at 30% 30%,rgba(37,99,235,.18),rgba(124,58,237,.10),transparent 62%)}
    .card .n{font-size:28px;font-weight:900;letter-spacing:.2px;font-variant-numeric:tabular-nums}
    .card .d{color:rgba(15,23,42,.68);font-size:12px;margin-top:0}
    .card.total:before{background:linear-gradient(90deg,#2563eb,#7c3aed)}
    .card.files:before{background:linear-gradient(90deg,#06b6d4,#10b981)}
    .card.unconfirmed:before{background:linear-gradient(90deg,#f59e0b,#ef4444)}
    .card.files:after{background:radial-gradient(circle at 30% 30%,rgba(6,182,212,.18),rgba(16,185,129,.10),transparent 62%)}
    .card.unconfirmed:after{background:radial-gradient(circle at 30% 30%,rgba(245,158,11,.18),rgba(239,68,68,.10),transparent 62%)}
    .card .cap{display:flex;gap:8px;align-items:center;justify-content:space-between}
    .card .cap .label{color:rgba(15,23,42,.62);font-size:12px;letter-spacing:.2px}
    .card .cap .hint{color:rgba(15,23,42,.42);font-size:12px}
    .toolbar{margin-top:18px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    .search{flex:1;min-width:260px}
    input[type="search"]{width:100%;padding:12px 12px;border-radius:14px;border:1px solid var(--border);background:var(--panel);color:var(--text);outline:none;box-shadow:0 8px 18px rgba(2,6,23,.03)}
    input[type="search"]::placeholder{color:rgba(100,116,139,.75)}
    .btn{padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:var(--panel);color:var(--text);cursor:pointer;user-select:none;box-shadow:0 8px 18px rgba(2,6,23,.03)}
    .btn:hover{border-color:rgba(37,99,235,.35)}
    .btn.active{border-color:rgba(37,99,235,.55);box-shadow:0 0 0 3px rgba(37,99,235,.14) inset,0 8px 18px rgba(2,6,23,.03)}
    .table{margin-top:14px;background:var(--panel);border:1px solid var(--border);border-radius:18px;overflow:hidden;box-shadow:var(--shadow2)}
    table{width:100%;border-collapse:separate;border-spacing:0 10px}
    thead th{padding:12px 12px}
    tbody td{padding:0 12px;border-bottom:none}
    th{font-size:12px;letter-spacing:.3px;text-transform:uppercase;color:var(--muted);background:var(--panel2);text-align:left}
    .tag{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(15,23,42,.10);background:rgba(248,250,252,.9);padding:3px 8px;border-radius:999px;font-size:12px;color:rgba(15,23,42,.82)}
    .dot{width:8px;height:8px;border-radius:50%}
    .sev-critical .dot{background:var(--crit)}
    .sev-high .dot{background:var(--bad)}
    .sev-medium .dot{background:var(--warn)}
    .sev-low .dot{background:var(--good)}
    .sev-unknown .dot{background:#94a3b8}
    .rowcard{display:grid;grid-template-columns:44px 120px 1fr;gap:12px;align-items:center;padding:12px 12px;background:var(--panel);border:1px solid var(--border);border-radius:16px;box-shadow:0 10px 24px rgba(2,6,23,.04)}
    .rowcard:hover{border-color:rgba(37,99,235,.24);box-shadow:0 18px 42px rgba(2,6,23,.08)}
    .rc-idx{display:flex;align-items:center;justify-content:center;height:32px;border-radius:12px;background:var(--panel2);border:1px solid rgba(15,23,42,.08);color:var(--muted);font-weight:700;font-variant-numeric:tabular-nums}
    .rc-sev{display:flex;align-items:center}
    .rc-main{min-width:0}
    .finding-top{display:flex;gap:8px 10px;align-items:baseline;flex-wrap:wrap}
    .finding-rule{font-weight:800;font-size:14px;letter-spacing:.1px}
    .finding-code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,Monaco,monospace;font-size:12px;color:rgba(15,23,42,.62)}
    .finding-sub{margin-top:4px;color:var(--muted);display:flex;gap:10px;flex-wrap:wrap}
    .finding-loc{font-size:12px}
    .chip{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(15,23,42,.10);background:rgba(37,99,235,.06);padding:2px 8px;border-radius:999px;font-size:12px;color:rgba(15,23,42,.78)}
    .chip-warn{background:rgba(245,158,11,.10)}
    details{margin-top:10px;border:1px solid var(--border);border-radius:18px;background:var(--panel);overflow:hidden;box-shadow:var(--shadow2)}
    summary{list-style:none;cursor:pointer;padding:14px 14px;display:flex;gap:10px;align-items:center}
    summary::-webkit-details-marker{display:none}
    details[open] summary{background:rgba(37,99,235,.04)}
    .sumline{display:flex;gap:10px;align-items:center;flex-wrap:wrap;width:100%}
    .sumline .main{font-weight:700}
    .sumline .muted{color:var(--muted)}
    .body{padding:0 14px 14px}
    .grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:10px}
    .panel{background:var(--panel2);border:1px solid rgba(15,23,42,.08);border-radius:14px;padding:10px 12px}
    pre{margin:0;white-space:pre-wrap;word-break:break-word;background:#f7f9fd;border:1px solid rgba(15,23,42,.10);border-radius:14px;padding:12px 12px;overflow:auto}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,Monaco,monospace;font-size:12px;color:rgba(15,23,42,.92)}
    .footer{margin-top:22px;color:var(--muted);font-size:12px}
    @media (max-width:980px){.hero-top{grid-template-columns:1fr}.cards{grid-template-columns:1fr}.grid{grid-template-columns:1fr}}
    @media print{body{background:#fff}.hero,.table,details,.card,.kv{box-shadow:none} .btn,.toolbar{display:none}}
    """


def _render_html(report, template_path=None):
    """渲染 HTML 报告，支持自定义 Jinja2 模板。"""
    meta = report.get("meta") or {}
    summary = report.get("summary") or {}
    vulnerabilities = list(report.get("vulnerabilities") or [])

    # 确定模板路径：优先使用参数，其次使用全局配置
    tpl = template_path
    if (not tpl or not os.path.isfile(tpl)):
        tpl = HTML_TEMPLATE_PATH if HTML_TEMPLATE_PATH and os.path.isfile(HTML_TEMPLATE_PATH) else None

    if tpl and jinja2 is not None:
        try:
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(os.path.dirname(os.path.abspath(tpl))),
                autoescape=True,
            )
            tpl_obj = env.get_template(os.path.basename(tpl))
            project_name = os.path.basename(os.path.normpath(_safe_str(meta.get("target")))) or _safe_str(meta.get("target"))

            js = """
    (function(){
      var q = document.getElementById('q');
      var sevBtns = Array.prototype.slice.call(document.querySelectorAll('[data-filter-sev]'));
      var rows = Array.prototype.slice.call(document.querySelectorAll('tr.row'));
      var items = Array.prototype.slice.call(document.querySelectorAll('details.item'));
      var activeSev = 'all';
      function apply(){
        var text = (q.value || '').toLowerCase().trim();
        function ok(el){
          var sev = el.getAttribute('data-sev') || 'unknown';
          var hay = el.getAttribute('data-text') || '';
          if(activeSev !== 'all' && sev !== activeSev) return false;
          if(text && hay.indexOf(text) === -1) return false;
          return true;
        }
        rows.forEach(function(r){ r.style.display = ok(r) ? '' : 'none'; });
        items.forEach(function(d){ d.style.display = ok(d) ? '' : 'none'; });
      }
      sevBtns.forEach(function(b){
        b.addEventListener('click', function(){
          sevBtns.forEach(function(x){ x.classList.remove('active'); });
          b.classList.add('active');
          activeSev = b.getAttribute('data-filter-sev') || 'all';
          apply();
        });
      });
      q.addEventListener('input', apply);
      document.getElementById('expand').addEventListener('click', function(){ items.forEach(function(d){ d.open = true; }); });
      document.getElementById('collapse').addEventListener('click', function(){ items.forEach(function(d){ d.open = false; }); });
      apply();
    })();
    """

            return tpl_obj.render(
                report=report,
                meta=meta,
                summary=summary,
                vulnerabilities=vulnerabilities,
                project_name=project_name,
                css=_BUILTIN_CSS,
                js=js,
            )
        except Exception as e:
            logger.warning("[EXPORT] Jinja2 template rendering failed ({}), falling back to builtin.".format(e))

    # fallback: 内置字符串拼接逻辑
    def _tag(sev):
        s = _safe_str(sev).lower() or "unknown"
        s = s if s in ["critical", "high", "medium", "low", "unknown"] else "unknown"
        return '<span class="tag sev-{}"><span class="dot"></span>{}</span>'.format(s, _html_escape(s.upper()))

    def _card(n, d, cls, hint):
        return '<div class="card {cls}"><div class="cap"><div class="label">{d}</div><div class="hint">{hint}</div></div><div class="n">{n}</div></div>'.format(
            cls=_html_escape(cls),
            d=_html_escape(d),
            hint=_html_escape(hint),
            n=_html_escape(n),
        )

    kv_pairs = []
    for k in ["sid", "exported_at", "schema_version", "generator", "target_directory", "language", "framework"]:
        if k in meta and meta.get(k) is not None and _safe_str(meta.get(k)).strip() != "":
            kv_pairs.append('<div class="kvrow"><div class="k">{}</div><div class="v">{}</div></div>'.format(_html_escape(k), _html_escape(meta.get(k))))

    cards = []
    cards.append(_card(summary.get("total_vulns", 0), "Total Findings", "total", "All"))
    cards.append(_card(summary.get("files_affected", 0), "Files Affected", "files", "Unique"))
    cards.append(_card(summary.get("unconfirmed_total", 0), "Unconfirmed", "unconfirmed", "Needs Review"))

    rows = []
    for idx, v in enumerate(vulnerabilities, 1):
        lang = _safe_str(v.get("language")).strip()
        cvi = _safe_str(v.get("id")).strip()
        loc = _safe_str(v.get("location")).strip()
        rule_name = _safe_str(v.get("rule_name")).strip()
        is_unconfirm = bool(v.get("is_unconfirm"))
        chips = []
        if lang:
            chips.append('<span class="chip">{}</span>'.format(_html_escape(lang)))
        if is_unconfirm:
            chips.append('<span class="chip chip-warn">UNCONFIRMED</span>')

        rows.append(
            '<tr class="row" data-sev="{sev}" data-text="{txt}">'
            '<td colspan="3">'
            '<div class="rowcard">'
            '<div class="rc-idx">{idx}</div>'
            '<div class="rc-sev">{sevtag}</div>'
            '<div class="rc-main">'
            '<div class="finding-top">'
            '<span class="finding-rule">{rule}</span>'
            '<span class="finding-code">CVI-{cvi}</span>'
            '{chips}'
            '</div>'
            '<div class="finding-sub">'
            '<span class="finding-loc">{loc}</span>'
            '</div>'
            '</div>'
            '</div>'
            '</td>'
            "</tr>".format(
                idx=idx,
                sev=_html_escape(v.get("severity")),
                sevtag=_tag(v.get("severity")),
                cvi=_html_escape(cvi),
                rule=_html_escape(rule_name),
                loc=_html_escape(loc),
                chips=" ".join(chips),
                txt=_html_escape(" ".join([rule_name, lang, loc, _safe_str(v.get("analysis")), _safe_str(v.get("code_content"))]).lower()),
            )
        )

    details_blocks = []
    for idx, v in enumerate(vulnerabilities, 1):
        sev = _safe_str(v.get("severity")).lower() or "unknown"
        sev = sev if sev in ["critical", "high", "medium", "low", "unknown"] else "unknown"
        title = "{}. {} ({})".format(idx, _safe_str(v.get("rule_name") or "Unknown"), sev.upper())
        analysis = v.get("analysis") or ""
        code_content = v.get("code_content") or ""
        chain = v.get("chain")
        details_blocks.append(
            '<details class="item" data-sev="{sev}" data-text="{txt}">'
            "<summary>"
            '<div class="sumline">{sevtag}<span class="main">{title}</span><span class="muted">{loc}</span>{un}</div>'
            "</summary>"
            '<div class="body">'
            '<div class="grid">'
            '<div class="panel"><div class="k">cvi_id</div><div class="v">{cvi}</div></div>'
            '<div class="panel"><div class="k">language</div><div class="v">{lang}</div></div>'
            '<div class="panel"><div class="k">commit_author</div><div class="v">{author}</div></div>'
            "</div>"
            '{analysis_block}{code_block}{chain_block}'
            '<div class="panel" style="margin-top:10px"><div class="k">raw</div><pre><code>{raw}</code></pre></div>'
            "</div>"
            "</details>".format(
                sev=_html_escape(sev),
                txt=_html_escape(" ".join([_safe_str(title), _safe_str(v.get("location")), _safe_str(analysis), _safe_str(code_content)]).lower()),
                sevtag=_tag(sev),
                title=_html_escape(title),
                loc=_html_escape(v.get("location")),
                un='' if not v.get("is_unconfirm") else '<span class="tag"><span class="dot" style="background:var(--warn)"></span>UNCONFIRMED</span>',
                cvi=_html_escape(v.get("id")),
                lang=_html_escape(v.get("language")),
                author=_html_escape(v.get("commit_author")),
                analysis_block="" if not analysis else '<div class="panel" style="margin-top:10px"><div class="k">analysis</div><pre><code>{}</code></pre></div>'.format(_html_escape(analysis)),
                code_block="" if not code_content else '<div class="panel" style="margin-top:10px"><div class="k">code_content</div><pre><code>{}</code></pre></div>'.format(_html_escape(code_content)),
                chain_block="" if not chain else '<div class="panel" style="margin-top:10px"><div class="k">chain</div><pre><code>{}</code></pre></div>'.format(_html_escape(json.dumps(chain, ensure_ascii=False, indent=2))),
                raw=_html_escape(json.dumps(v, ensure_ascii=False, indent=2)),
            )
        )

    js = """
    (function(){
      var q = document.getElementById('q');
      var sevBtns = Array.prototype.slice.call(document.querySelectorAll('[data-filter-sev]'));
      var rows = Array.prototype.slice.call(document.querySelectorAll('tr.row'));
      var items = Array.prototype.slice.call(document.querySelectorAll('details.item'));
      var activeSev = 'all';
      function apply(){
        var text = (q.value || '').toLowerCase().trim();
        function ok(el){
          var sev = el.getAttribute('data-sev') || 'unknown';
          var hay = el.getAttribute('data-text') || '';
          if(activeSev !== 'all' && sev !== activeSev) return false;
          if(text && hay.indexOf(text) === -1) return false;
          return true;
        }
        rows.forEach(function(r){ r.style.display = ok(r) ? '' : 'none'; });
        items.forEach(function(d){ d.style.display = ok(d) ? '' : 'none'; });
      }
      sevBtns.forEach(function(b){
        b.addEventListener('click', function(){
          sevBtns.forEach(function(x){ x.classList.remove('active'); });
          b.classList.add('active');
          activeSev = b.getAttribute('data-filter-sev') || 'all';
          apply();
        });
      });
      q.addEventListener('input', apply);
      document.getElementById('expand').addEventListener('click', function(){ items.forEach(function(d){ d.open = true; }); });
      document.getElementById('collapse').addEventListener('click', function(){ items.forEach(function(d){ d.open = false; }); });
      apply();
    })();
    """

    return """<!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="utf-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1"/>
      <title>Kunlun-M 扫描结果报告</title>
      <style>{css}</style>
    </head>
    <body>
      <div class="wrap">
        <div class="hero">
          <div class="hero-top">
            <div>
              <div class="title">
                <h1>Kunlun-M 扫描结果报告</h1>
                <div class="subtitle">{target}</div>
              </div>
              <div class="cards">{cards}</div>
            </div>
            <div class="sidebar">
              <div class="sidebox">
                <div class="t">Project</div>
                <div class="v">{project}</div>
                <div class="sub">Target</div>
              </div>
              <div class="sidebox">
                <div class="t">Details</div>
                <div class="kvs">{kv_pairs}</div>
              </div>
            </div>
          </div>
          <div class="toolbar">
            <div class="search"><input id="q" type="search" placeholder="搜索：规则名 / 文件 / 代码 / 分析…"/></div>
            <button class="btn active" data-filter-sev="all">ALL</button>
            <button class="btn" data-filter-sev="critical">CRITICAL</button>
            <button class="btn" data-filter-sev="high">HIGH</button>
            <button class="btn" data-filter-sev="medium">MEDIUM</button>
            <button class="btn" data-filter-sev="low">LOW</button>
            <button class="btn" data-filter-sev="unknown">UNKNOWN</button>
            <button class="btn" id="expand">展开全部</button>
            <button class="btn" id="collapse">收起全部</button>
          </div>
        </div>

        <div class="table">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Severity</th>
                <th>Finding</th>
              </tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>

        <div style="margin-top:14px">
          {details}
        </div>

        <div class="footer">Generated at {exported_at}</div>
      </div>
      <script>{js}</script>
    </body>
    </html>""".format(
        css=_BUILTIN_CSS,
        target=_html_escape(meta.get("target")),
        project=_html_escape(os.path.basename(os.path.normpath(_safe_str(meta.get("target")))) or _safe_str(meta.get("target"))),
        kv_pairs="".join(kv_pairs),
        cards="".join(cards),
        rows="".join(rows),
        details="".join(details_blocks),
        exported_at=_html_escape(meta.get("exported_at")),
        js=js,
    )


def dict_to_csv(vul_list, filename):
    """
    Write scan result to file.
    :param vul_list:a list which contains dicts
    :param filename:
    :return:
    """
    # 排序并将 target 调整到第一列
    header = sorted(vul_list[0].keys())
    header.remove('target')
    header.insert(0, 'target')

    # 去除列表中的换行符

    with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
        csv_writer = csv.DictWriter(f, header)
        csv_writer.writeheader()
        csv_writer.writerows(vul_list)


def dict_to_pretty_table(vul_list):
    """
    Pretty print vul_list in console.
    :param vul_list:
    :return: Pretty Table Format String
    """
    row_list = PrettyTable()
    row_list.field_names = ['#', 'CVI', 'Vulnerability', 'File', 'Commit', 'Code Content']
    row_list.align = 'l'
    for _id, vul in enumerate(vul_list):
        row_list.add_row(
            [_id+1, vul.get('id'), vul.get('rule_name'), vul.get('file_path') + ':' + str(vul.get('line_number')),
             '@' + vul.get('commit_author')+','+vul.get('commit_time'), vul.get('code_content').strip()]
        )
    return row_list


def write_to_file(target, sid, output_format='', filename=None, template_path=None):
    """
    Export scan result to file.
    :param target: scan target
    :param sid: scan sid
    :param output_format: output format
    :param filename: filename to save
    :return:
    """
    _base_cwd = os.getcwd()
    if not filename:
        logger.info('[EXPORT] No filename given, save into default path(result/).')

        targetlist = re.split(r"[\\/]", target)
        if target.endswith("/") or target.endswith("\\"):
            filename = targetlist[-2]
        else:
            filename = targetlist[-1]
        filename = os.path.join(DEFAULT_RESULT_PATH, filename + "." + output_format)
    #     return False
    if not os.path.isabs(filename):
        filename = os.path.abspath(os.path.join(EXPORT_PATH, filename))
    if template_path and (not os.path.isabs(template_path)):
        template_path = os.path.abspath(os.path.join(_base_cwd, template_path))
    _parent = os.path.dirname(filename)
    if _parent:
        os.makedirs(_parent, exist_ok=True)

    scan_data_file = os.path.join(RUNNING_PATH, '{sid}_data'.format(sid=sid))

    if not os.path.exists(scan_data_file):
        logger.warn("[EXPORT] {} not found".format(scan_data_file))
        return False

    with open(scan_data_file, 'r') as f:
        scan_data = json.load(f).get('result')

    os.chdir(EXPORT_PATH)
    scan_data['target'] = target

    target_directory = scan_data.get("target_directory") or ""
    normalized_vulns = _normalize_vulnerabilities(scan_data.get("vulnerabilities") or [], target_directory)
    meta = {
        "target": target,
        "sid": sid,
        "exported_at": _iso_utc_now(),
        "schema_version": "1.0",
        "generator": "Kunlun-M CLI Exporter",
        "target_directory": target_directory,
        "language": scan_data.get("language"),
        "framework": scan_data.get("framework"),
        "extension": scan_data.get("extension"),
        "file": scan_data.get("file"),
        "push_rules": scan_data.get("push_rules"),
        "trigger_rules": scan_data.get("trigger_rules"),
    }
    rich_scan_data = dict(scan_data)
    rich_scan_data["meta"] = meta
    rich_scan_data["summary"] = _build_summary(normalized_vulns)
    rich_scan_data["vulnerabilities"] = normalized_vulns

    if output_format == '' or output_format == 'stream':
        if len(rich_scan_data.get("vulnerabilities") or []) == 0:
            logger.info("[EXPORT] Not found vulnerability.")
            return False
        logger.info('Vulnerabilities\n' + str(dict_to_pretty_table(rich_scan_data.get('vulnerabilities'))))

    elif output_format == 'json' or output_format == 'JSON':
        if not os.path.exists(filename):
            with open(filename, 'w+', encoding='utf-8', errors='ignore') as f:
                json_data = {
                    sid: rich_scan_data,
                }
                f.write(dict_to_json(json_data))
        else:
            with open(filename, 'r+', encoding='utf-8', errors='ignore') as f:
                json_data = json.load(f)
                json_data.update({sid: rich_scan_data})
                # 使用 r+ 模式不会覆盖，调整文件指针到开头
                f.seek(0)
                f.truncate()
                f.write(dict_to_json(json_data))

    elif output_format == 'xml' or output_format == 'XML':
        xml_data = {
            sid: rich_scan_data,
        }
        if not os.path.exists(filename):
            with open(filename, 'w+', encoding='utf-8', errors='ignore') as f:
                f.write("""<?xml version="1.0" encoding="UTF-8"?>\n""")
                f.write("""<results>\n""")
                f.write(dict_to_xml(xml_data))
                f.write("""\n</results>\n""")
        else:
            # 在倒数第二行插入
            with open(filename, 'r+', encoding='utf-8', errors='ignore') as f:
                results = f.readlines()
                results.insert(len(results) - 1, '\n' + dict_to_xml(xml_data) + '\n')
                f.seek(0)
                f.truncate()
                f.writelines(results)

    elif output_format == 'csv' or output_format == 'CSV':
        if len(rich_scan_data.get("vulnerabilities") or []) == 0:
            logger.info("[EXPORT] Not found vulnerability, break export...")
            return False
        for vul in rich_scan_data.get('vulnerabilities'):
            vul['target'] = rich_scan_data.get('target')
        dict_to_csv(rich_scan_data.get('vulnerabilities'), filename)

    elif output_format in ['md', 'markdown', 'MD', 'MARKDOWN']:
        with open(filename, 'w+', encoding='utf-8', errors='ignore') as f:
            f.write(_render_markdown(rich_scan_data))

    elif output_format in ['html', 'htm', 'HTML', 'HTM']:
        with open(filename, 'w+', encoding='utf-8', errors='ignore') as f:
            f.write(_render_html(rich_scan_data, template_path=template_path))

    else:
        logger.warning('[EXPORT] Unknown output format.')
        return False

    logger.info('[EXPORT] Scan result exported successfully: {fn}'.format(fn=filename))
    return True
