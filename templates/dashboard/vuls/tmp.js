 

function kmToast(msg, type) {
  var colors = {error: '#dc2626', success: '#16a34a', info: '#2563eb'};
  var t = document.createElement('div');
  t.style.cssText = 'position:fixed;top:18px;right:18px;z-index:2000;padding:10px 16px;border-radius:8px;color:#fff;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,0.18);background:' + (colors[type] || colors.info) + ';';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(function() { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(function(){ t.remove(); }, 320); }, 3500);
}

  

var chainDataMap = {};
{% for r in results %}
  {% if r.has_chain %}
    chainDataMap["{{ r.id }}"] = {{ r.chain_nodes_json|safe }};
  {% endif %}
{% endfor %}

var activeVulRow = null;

function toggleVulDetail(row) {
  var detailRow = row.nextElementSibling;
  if (!detailRow || !detailRow.classList.contains('km-vul-detail-row')) return;
  if (activeVulRow && activeVulRow !== row) {
    var prev = activeVulRow.nextElementSibling;
    if (prev && prev.classList.contains('km-vul-detail-row')) {
      prev.style.display = 'none';
      activeVulRow.classList.remove('km-vul-row-active');
    }
  }
  if (detailRow.style.display === 'none') {
    detailRow.style.display = 'table-row';
    row.classList.add('km-vul-row-active');
    activeVulRow = row;
    var vulId = row.getAttribute('data-vul-id');
    renderChainPanel(vulId);
  } else {
    detailRow.style.display = 'none';
    row.classList.remove('km-vul-row-active');
    activeVulRow = null;
  }
}

function getChainRole(idx, total) {
  if (idx === 0) return 'source';
  if (idx === total - 1) return 'sink';
  return 'propagation';
}

function getRoleLabel(role) {
  if (role === 'source') return 'SOURCE';
  if (role === 'sink') return 'SINK';
  return '传播';
}

function getRoleClass(role) {
  if (role === 'source') return 'role-source';
  if (role === 'sink') return 'role-sink';
  return 'role-propagation';
}



function renderChainPanel(vulId) {
  var nodes = chainDataMap[vulId];
  if (!nodes || nodes.length === 0) return;
  var total = nodes.length;

  // Build sidebar
  var sidebar = document.getElementById('chainSidebar_' + vulId);
  var html = '';
  for (var i = 0; i < total; i++) {
    var n = nodes[i];
    var role = getChainRole(i, total);
    var fname = (n.path || '').split('/').pop();
    var name = n.content || n.type;
    html += '<div class="km-vul-chain-sidebar-row' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '" onclick="selectChainNode(' + vulId + ',' + i + ')">';
    html += '<span class="role-badge ' + getRoleClass(role) + '">' + getRoleLabel(role) + '</span> ';
    html += '<span class="node-name">' + escapeHtml(name) + '</span>';
    html += '<div class="node-loc">' + escapeHtml(n.type);
    if (fname && n.lineno) html += ' · ' + escapeHtml(fname) + ':' + n.lineno;
    html += '</div></div>';

  }
  sidebar.innerHTML = html;

  // Select last node (source) by default
  selectChainNode(vulId, 0);
}

function selectChainNode(vulId, idx) {
  var nodes = chainDataMap[vulId];
  if (!nodes || !nodes[idx]) return;
  var n = nodes[idx];
  var role = getChainRole(idx, nodes.length);

  var sidebar = document.getElementById('chainSidebar_' + vulId);
  sidebar.querySelectorAll('.km-vul-chain-sidebar-row').forEach(function(el) { el.classList.remove('active'); });
  var activeRow = sidebar.querySelector('[data-idx="' + idx + '"]');
  if (activeRow) activeRow.classList.add('active');

  var codeArea = document.getElementById('chainCode_' + vulId);
  if (!codeArea) return;
  var targetLineno = n.lineno || 0;

  var panel = document.getElementById('chainPanel_' + vulId);
  var pid = panel ? panel.getAttribute('data-project-id') : null;

  var headerHtml = '<div class="code-header">';
  headerHtml += '<span class="role-badge ' + getRoleClass(role) + '">' + getRoleLabel(role) + '</span> ';
  headerHtml += '<strong>' + escapeHtml(n.type) + '</strong> &mdash; ' + escapeHtml(n.content || '');
  if (n.path) headerHtml += ' <span class="vp-ml12 vp-muted">' + escapeHtml(n.path.split('/').pop()) + ':' + n.lineno + '</span>';
  if (n.vid !== null && n.vid !== undefined) headerHtml += ' <span class="vp-ml8 vp-muted">vid=' + n.vid + '</span>';
  if (pid && n.path && targetLineno > 0) {
    headerHtml += ' <button class="btn btn-default btn-sm vp-ml-auto-chip" '
      + 'onclick="openChainBrowser(\'' + vulId + '\',' + idx + ')" title="在源码浏览器中打开全文"><i class="fa fa-external-link"></i> 源码浏览器</button>';
  }
  headerHtml += '</div>';

  // 整文件对照模式：项目内 + 有行号 → 拉全文滚动到目标行
  if (pid && n.path && targetLineno > 0) {
    loadFullFileVul(vulId, n, codeArea, headerHtml, targetLineno);
    return;
  }

  var sourceLines = n.source_code || '';
  var codeLines = [];
  var lineNums = [];
  if (sourceLines) {
    var rawLines = sourceLines.split('\n');
    for (var i = 0; i < rawLines.length; i++) {
      var m = rawLines[i].match(/^(\s*)(\d+):\s?(.*)/);
      if (m) {
        lineNums.push(parseInt(m[2]));
        codeLines.push(m[3]);
      }
    }
  }

  if (codeLines.length === 0) {
    codeArea.innerHTML = headerHtml + '<div class="code-body vp-empty">' + escapeHtml(n.content || '(无代码上下文)') + '</div>';
    return;
  }

  var bodyHtml = '<div class="code-body"><table class="code-table">';
  for (var j = 0; j < codeLines.length; j++) {
    var isTarget = (lineNums[j] === targetLineno);
    bodyHtml += '<tr' + (isTarget ? ' class="hl-line"' : '') + '>';
    bodyHtml += '<td class="td-line">' + (lineNums[j] || '') + '</td>';
    bodyHtml += '<td class="td-code">' + escapeHtml(codeLines[j]) + '</td>';
    bodyHtml += '</tr>';
  }
  bodyHtml += '</table></div>';
  codeArea.innerHTML = headerHtml + bodyHtml;
}

var vulFullFileCache = {};
function openChainBrowser(vulId, idx) {
  var nodes = chainDataMap[vulId];
  if (!nodes || !nodes[idx]) return;
  var panel = document.getElementById('chainPanel_' + vulId);
  var pid = panel ? panel.getAttribute('data-project-id') : null;
  if (!pid) { alert('未找到项目 ID'); return; }
  var n = nodes[idx];
  window.open('/dashboard/projects/' + pid + '/files?file=' + encodeURIComponent(n.path || '')
    + '&lineno=' + (n.lineno || 0), '_blank');
}
function loadFullFileVul(vulId, n, codeArea, headerHtml, targetLineno) {
  var key = (n.path || '');
  var cached = vulFullFileCache[key];
  var apply = function(lines) {
    if (!lines) { // 回退片段模式
      renderSnippetVul(vulId, n, codeArea, headerHtml, targetLineno);
      return;
    }
    var html = headerHtml + '<div class="code-body vp-scroll420"><table class="code-table">';
    for (var i = 0; i < lines.length; i++) {
      var lineno = i + 1;
      var isTarget = (lineno === targetLineno);
      var near = Math.abs(lineno - targetLineno) <= 5;
      html += '<tr' + (isTarget ? ' class="hl-line"' : (near ? ' class="near-line"' : '')) + ' id="kmVL' + vulId + '_' + lineno + '">';
      html += '<td class="td-line">' + lineno + '</td>';
      html += '<td class="td-code">' + escapeHtml(lines[i]) + '</td>';
      html += '</tr>';
    }
    html += '</table></div>';
    codeArea.innerHTML = html;
    var el = document.getElementById('kmVL' + vulId + '_' + targetLineno);
    if (el) el.scrollIntoView({block: 'center'});
  };
  if (cached) { apply(cached); return; }
  codeArea.innerHTML = headerHtml + '<div class="code-body vp-empty"><i class="fa fa-spinner fa-spin"></i> 加载整文件源码...</div>';
  var pid = (document.getElementById('chainPanel_' + vulId) || {}).getAttribute && document.getElementById('chainPanel_' + vulId).getAttribute('data-project-id');
  var url = '/dashboard/projects/' + pid + '/files/content?file=' + encodeURIComponent(n.path) + '&lineno=' + targetLineno;
  fetch(url, {credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(d){
    var lines = d && d.lines;
    if (lines && lines.length && typeof lines[0] === 'object') lines = lines.map(function(l){ return l.code; });
    if (!lines || !lines.length) { apply(null); return; }
    vulFullFileCache[key] = lines;
    apply(lines);
  }).catch(function(){ apply(null); });
}
function renderSnippetVul(vulId, n, codeArea, headerHtml, targetLineno) {
  var sourceLines = n.source_code || '';
  var codeLines = [];
  var lineNums = [];
  if (sourceLines) {
    var rawLines = sourceLines.split('\n');
    for (var i = 0; i < rawLines.length; i++) {
      var m = rawLines[i].match(/^(\s*)(\d+):\s?(.*)/);
      if (m) { lineNums.push(parseInt(m[2])); codeLines.push(m[3]); }
    }
  }
  if (codeLines.length === 0) {
    codeArea.innerHTML = headerHtml + '<div class="code-body vp-empty">' + escapeHtml(n.content || '(无代码上下文)') + '</div>';
    return;
  }
  var bodyHtml = '<div class="code-body"><table class="code-table">';
  for (var j = 0; j < codeLines.length; j++) {
    var isTarget = (lineNums[j] === targetLineno);
    bodyHtml += '<tr' + (isTarget ? ' class="hl-line"' : '') + '>';
    bodyHtml += '<td class="td-line">' + (lineNums[j] || '') + '</td>';
    bodyHtml += '<td class="td-code">' + escapeHtml(codeLines[j]) + '</td>';
    bodyHtml += '</tr>';
  }
  bodyHtml += '</table></div>';
  codeArea.innerHTML = headerHtml + bodyHtml;
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ===== 批量审计 + 键盘导航 ===== */
function getSelIds() {
  return [...document.querySelectorAll('.vul-sel:checked')].map(cb => parseInt(cb.value));
}
function refreshBulkBar() {
  var n = getSelIds().length;
  var bar = document.getElementById('bulkBar');
  bar.style.display = 'flex';
  document.getElementById('bulkCount').textContent = n;
}
function bulkVerify(action) {
  var ids = getSelIds();
  if (ids.length === 0) { alert('请先勾选漏洞行'); return; }
  var labels = {tp: '确认 TP', fp: '标记 FP', stale: '标记过期', unconfirm: '撤销标记'};
  if (!confirm('对 ' + ids.length + ' 条漏洞执行「' + (labels[action] || action) + '」？')) return;
  fetch('{% url "dashboard:vul_verify_bulk" %}', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
    },
    body: JSON.stringify({ids: ids, action: action})
  }).then(r => r.json()).then(function(d) {
    if (d.code === 200) { location.reload(); }
    else { alert('批量操作失败: ' + (d.message || d.error || '')); }
  }).catch(e => alert('请求失败: ' + e));
}
document.addEventListener('change', function(e) {
  if (e.target.id === 'vulSelAll') {
    document.querySelectorAll('.vul-sel').forEach(cb => cb.checked = e.target.checked);
  }
  if (e.target.classList && e.target.classList.contains('vul-sel')) refreshBulkBar();
});

/* AI 分诊详情对照弹窗 */
function showHistory(vulId) {
  var modal = document.getElementById('aiDetailModal');
  var body = document.getElementById('aiDetailBody');
  modal.style.display = 'flex';
  body.innerHTML = '<div class="vp-empty-lg"><i class="fa fa-spinner fa-spin"></i> 加载判定史...</div>';
  fetch('/dashboard/vuls/' + vulId + '/history', {credentials:'same-origin'})
    .then(r => r.json())
    .then(function(res) {
      if (res.code !== 200) { body.innerHTML = '<div class="vp-empty-err">加载失败</div>'; return; }
      var evs = res.events || [];
      if (!evs.length) { body.innerHTML = '<div class="vp-empty-lg">该漏洞暂无判定事件（未人工复核过）</div>'; return; }
      var h = '<div style="padding:14px 18px;max-height:70vh;overflow:auto;">' +
        '<div style="font-weight:700;margin-bottom:8px;">判定史 · 漏洞 #' + vulId + '（' + evs.length + ' 条事件，账本不可篡改）</div>';
      evs.forEach(function(e, i) {
        var color = e.new === 'tp' ? '#16a34a' : e.new === 'fp' ? '#dc2626' : '#6b7280';
        h += '<div style="border-left:3px solid ' + color + ';padding:4px 10px;margin:6px 0;">' +
          '<div style="font-size:13px;"><b>' + (i+1) + '. ' + e.old + ' → ' + e.new + '</b>' +
          ' <span style="color:#888;font-size:11px;">' + e.source_cn + ' · ' + e.actor + ' · ' + e.at + '</span></div>' +
          (e.notes ? '<div style="font-size:12px;color:#555;margin-top:2px;">依据: ' + e.notes.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</div>' : '') +
          '</div>';
      });
      h += '</div>';
      body.innerHTML = h;
    })
    .catch(function(){ body.innerHTML = '<div class="vp-empty-err">网络错误</div>'; });
}
function openDiscussions() {
  var modal = document.getElementById('aiDetailModal');
  var body = document.getElementById('aiDetailBody');
  modal.style.display = 'flex';
  body.innerHTML = '<div class="vp-empty-lg"><i class="fa fa-spinner fa-spin"></i> 加载讨论件...</div>';
  fetch('/dashboard/ai/discussions', {credentials:'same-origin'})
    .then(r => r.json())
    .then(function(res) {
      if (res.code !== 200) { body.innerHTML = '<div class="vp-empty-err">加载失败</div>'; return; }
      var docs = res.docs || [];
      var byType = {};
      docs.forEach(function(d){ (byType[d.doc_type] = byType[d.doc_type] || []).push(d); });
      var labels = {lessons:'判定经验教训', engine:'引擎缺陷清单', log:'裁决台账'};
      var h = '<div style="padding:14px 18px;">';
      h += '<div style="margin-bottom:10px;"><button class="btn btn-sm btn-primary" onclick="genDiscussions(this)">生成新版本</button>';
      h += '<span style="font-size:12px;color:#888;margin-left:8px;">经验沉淀为可讨论文档 · 全量存 DB</span></div>';
      ['lessons','engine','log'].forEach(function(tp){
        h += '<div style="margin:10px 0 4px;font-weight:600;">' + labels[tp] + '</div>';
        var list = byType[tp] || [];
        if (!list.length) { h += '<div style="font-size:12px;color:#aaa;">暂无版本，点上方生成</div>'; return; }
        list.slice(0,5).forEach(function(d){
          h += '<div style="display:flex;align-items:center;gap:8px;padding:3px 0;">' +
               '<a href="javascript:;" onclick="showDiscussion(' + d.id + ')" style="color:#0366d6;">' + d.title + '</a>' +
               '<span style="font-size:11px;color:#999;">' + (d.baseline||'') + '</span></div>';
        });
      });
      h += '</div>';
      body.innerHTML = h;
    })
    .catch(function(){ body.innerHTML = '<div class="vp-empty-err">网络错误</div>'; });
}
function genDiscussions(btn) {
  btn.disabled = true; btn.innerText = '生成中...';
  var m = document.cookie.match(/csrftoken=([^;]+)/);
  var token = m ? decodeURIComponent(m[1]) : '';
  fetch('/dashboard/ai/discussions', {method:'POST', credentials:'same-origin',
    headers:{'X-CSRFToken': token, 'Content-Type':'application/json'}})
    .then(r => r.json())
    .then(function(res){ if (res.code === 200) openDiscussions(); else { alert(res.message || '生成失败'); btn.disabled = false; btn.innerText = '生成新版本'; } })
    .catch(function(){ alert('网络错误'); btn.disabled = false; btn.innerText = '生成新版本'; });
}
function showDiscussion(id) {
  var body = document.getElementById('aiDetailBody');
  body.innerHTML = '<div class="vp-empty-lg"><i class="fa fa-spinner fa-spin"></i> 加载文档...</div>';
  fetch('/dashboard/ai/discussions/' + id, {credentials:'same-origin'})
    .then(r => r.json())
    .then(function(res){
      if (res.code !== 200) { body.innerHTML = '<div class="vp-empty-err">加载失败</div>'; return; }
      var d = res.doc;
      var html = '<div style="padding:14px 18px;max-height:70vh;overflow:auto;">' +
        '<div style="font-weight:700;font-size:15px;margin-bottom:4px;">' + d.title + '</div>' +
        '<div style="font-size:11px;color:#999;margin-bottom:10px;">' + d.type_label + ' · ' + d.baseline + '</div>' +
        '<pre style="white-space:pre-wrap;font-family:inherit;font-size:13px;line-height:1.6;">' +
        d.content_md.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre></div>';
      body.innerHTML = html;
    });
}
function showAiDetail(vulId) {
  var modal = document.getElementById('aiDetailModal');
  var body = document.getElementById('aiDetailBody');
  modal.style.display = 'flex';
  body.innerHTML = '<div class="vp-empty-lg"><i class="fa fa-spinner fa-spin"></i> 加载 AI 分析...</div>';
  var m = document.cookie.match(/csrftoken=([^;]+)/);
  var token = m ? decodeURIComponent(m[1]) : '';
  fetch('/dashboard/ai/vul/' + vulId + '/detail', {credentials:'same-origin'})
    .then(r => r.json())
    .then(function(res) {
      if (res.code !== 200) { body.innerHTML = '<div class="vp-empty-err">' + (res.message || '加载失败') + '</div>'; return; }
      var d = res.data;
      if (!d.verdict) { body.innerHTML = '<div class="vp-empty-lg">该漏洞尚未 AI 分析。可在"操作"菜单点"AI 分析"。</div>'; return; }
      var vLabel = d.verdict === 'tp' ? ['真实漏洞 (TP)', '#16a34a'] : d.verdict === 'fp' ? ['误报 (FP)', '#dc2626'] : ['不确定', '#d97706'];
      var hLabel = d.human_status === 'tp' ? ['人工已确认 TP', '#16a34a'] : d.human_status === 'fp' ? ['人工已判 FP', '#dc2626'] : d.human_status === 'stale' ? ['人工标记过期', '#adb5bd'] : ['未人工复核', '#6b7280'];
      var html = '<div class="vp-compare">';
      html += '<div class="vp-stat-card"><div class="vp-sub">AI 判定</div><strong style="color:' + vLabel[1] + ';font-size:15px;">' + vLabel[0] + '</strong><div class="vp-cmp-sub">置信度 ' + (d.confidence || '-') + (d.severity_adjust ? ' · 建议' + (d.severity_adjust === 'up' ? '升级' : d.severity_adjust === 'down' ? '降级' : '维持') : '') + '</div></div>';
      html += '<div class="vp-stat-card"><div class="vp-sub">人工判定</div><strong style="color:' + hLabel[1] + ';font-size:15px;">' + hLabel[0] + '</strong>' + (d.disagreed ? '<div class="vp-cmp-sub-warn"><i class="fa fa-exclamation-triangle"></i> 与 AI 分歧</div>' : '') + '</div>';
      html += '</div>';
      if (d.reasoning) html += '<div class="vp-mb12"><div class="vp-field-label"><i class="fa fa-brain"></i> AI 判定理由</div><div class="vp-note-ai-2">' + escapeHtml(d.reasoning) + '</div></div>';
      if (d.fix) html += '<div class="vp-mb12"><div class="vp-field-label"><i class="fa fa-wrench"></i> 修复建议</div><div class="vp-note-fix-2">' + escapeHtml(d.fix) + '</div></div>';
      html += '<div class="vp-mt14">';
      html += '<div class="vp-field-label"><i class="fa fa-comment-dots"></i> 复核备注' + (d.disagreed ? ' <span class="vp-warn-tag">（与 AI 分歧，建议写明原因）</span>' : '') + '</div>';
      html += '<textarea id="aiDetailNotes" rows="2" placeholder="可留空。例：链路实际可达，AI 漏算了 X 来源 / 确认 AI 判断，sink 参数固定" class="vp-notes-input"></textarea>';
      html += '<div class="vp-gap10mt">';
      html += '<button class="btn btn-sm btn-success" onclick="aiDetailMark(' + vulId + ',\"tp\")"><i class="fa fa-check"></i> 确认 TP</button>';
      html += '<button class="btn btn-sm btn-danger" onclick="aiDetailMark(' + vulId + ',\"fp\")"><i class="fa fa-times"></i> 标记 FP</button>';
      html += '<span class="vp-mini-hint">分析时间: ' + (d.analyzed_at || '-') + '</span>';
      html += '</div></div>';
      body.innerHTML = html;
    })
    .catch(e => { body.innerHTML = '<div class="vp-empty-err">请求失败: ' + e + '</div>'; });
}
function aiDetailMark(vulId, action) {
  var m = document.cookie.match(/csrftoken=([^;]+)/);
  var token = m ? decodeURIComponent(m[1]) : '';
  var notesEl = document.getElementById('aiDetailNotes');
  var notes = notesEl ? notesEl.value.trim() : '';
  if (action && notes === '' && !confirm('未填备注，直接标记？')) return;
  fetch('/dashboard/vuls/verify/bulk', {method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': token},
    body: JSON.stringify({ids: [vulId], action: action, notes: notes})})
    .then(r => r.json())
    .then(function(d) {
      if (d.code === 200) { document.getElementById('aiDetailModal').style.display = 'none'; location.reload(); }
      else alert('操作失败: ' + (d.message || ''));
    });
}
document.addEventListener('click', function(e) {
  var modal = document.getElementById('aiDetailModal');
  if (modal && modal.style.display === 'flex' && e.target === modal) modal.style.display = 'none';
});

/* 键盘导航 */
(function() {
  var cur = -1;
  var markHistory = [];   // [{id, action, prevTdHtml}]
  function rows() { return [...document.querySelectorAll('tr.km-vul-row')]; }
  function focusRow(idx) {
    var rs = rows();
    if (idx < 0 || idx >= rs.length) return;
    rs.forEach(r => r.classList.remove('km-kb-focus'));
    cur = idx;
    rs[cur].classList.add('km-kb-focus');
    rs[cur].scrollIntoView({block: 'nearest'});
  }
  function markCur(action) {
    if (cur < 0) return;
    var row = rows()[cur];
    var id = row.getAttribute('data-vul-id');
    var prevTdHtml = row.children[9].innerHTML;
    markHistory.push({id: parseInt(id), action: action, prevTdHtml: prevTdHtml});
    if (markHistory.length > 50) markHistory.shift();
    fetch('{% url "dashboard:vul_verify_bulk" %}', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value},
      body: JSON.stringify({ids: [parseInt(id)], action: action})
    }).then(r => r.json()).then(function(d) {
      if (d.code !== 200) { if (typeof kmToast === 'function') kmToast('标记失败: ' + (d.message || d.error || '未知错误'), 'error'); return; }
      var td = row.children[9];
      var labels = {tp: ['TP', '#16a34a'], fp: ['FP', '#dc2626'], stale: ['过期', '#adb5bd']};
      if (action === 'unconfirm') { td.innerHTML = '<span class="vp-mid">-</span>'; return; }
      var m = labels[action];
      if (m) td.innerHTML = '<span class="vp-kb-mark" style="color:' + m[1] + ';">' + m[0] + '</span>';
    }).catch(function(err) {
      if (typeof kmToast === 'function') kmToast('网络错误，标记未保存', 'error');
    });
  }
  document.addEventListener('keydown', function(e) {
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
    var k = e.key.toLowerCase();
    if (k === 'j') { focusRow(cur < 0 ? 0 : Math.min(cur + 1, rows().length - 1)); e.preventDefault(); }
    else if (k === 'k') { focusRow(cur < 0 ? 0 : Math.max(cur - 1, 0)); e.preventDefault(); }
    else if (k === 't' && cur >= 0) markCur('tp');
    else if (k === 'f' && cur >= 0) markCur('fp');
    else if (k === 'x' && cur >= 0) markCur('stale');
    else if (k === 'u' && cur >= 0) markCur('unconfirm');
    else if (k === 'z' && markHistory.length > 0) {
      var last = markHistory.pop();
      var rowEl = document.querySelector('tr.km-vul-row[data-vul-id="' + last.id + '"]');
      if (rowEl) rowEl.children[9].innerHTML = last.prevTdHtml;
      fetch('{% url "dashboard:vul_verify_bulk" %}', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json',
                  'X-CSRFToken': (typeof kmCsrf === 'function' ? kmCsrf() : document.querySelector('[name=csrfmiddlewaretoken]').value)},
        body: JSON.stringify({ids: [last.id], action: 'unconfirm'})
      }).then(r => r.json()).then(function(d) {
        if (d.code !== 200 && typeof kmToast === 'function') kmToast('撤销失败: ' + (d.message || d.error || '未知错误'), 'error');
      }).catch(function() {
        if (typeof kmToast === 'function') kmToast('网络错误，撤销未保存', 'error');
      });
    }
    else if (k === '1' && cur >= 0) { var cb = rows()[cur].querySelector('.vul-sel'); cb.checked = !cb.checked; refreshBulkBar(); }
    else if (e.key === 'Enter' && cur >= 0) { rows()[cur].click(); }
  });
})();


function kmCsrf(){
  var el = document.querySelector('[name=csrfmiddlewaretoken]');
  if (el && el.value) return el.value;
  var m = document.cookie.match(/(?:^|; )csrftoken=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : '';
}
function verifyVul(vulid, action) {
  var tok = kmCsrf();
  if (!tok){ alert('页面缺少 CSRF 令牌，请刷新页面后重试'); return; }
  $.post('/dashboard/vuls/' + vulid + '/verify',
    {action: action, csrfmiddlewaretoken: tok},
    function(data) { if(data.code == 200) location.reload(); else alert(data.message || '操作失败'); }
  ).fail(function(xhr){
    alert('标记失败 (HTTP ' + xhr.status + ')，请刷新页面重试');
  });
}
function applySuggest(vulid, verdict, n, el) {
  var tok = kmCsrf();
  if (!tok){ alert('页面缺少 CSRF 令牌，请刷新页面后重试'); return; }
  if (!el.dataset.confirmed) {
    el.dataset.confirmed = '1';
    el.innerText = '确认' + (verdict === 'fp' ? 'FP' : 'TP') + '?';
    return;
  }
  $.post('/dashboard/vuls/' + vulid + '/verify',
    {action: verdict, notes: '判例批量采纳: 同模式 ' + n + ' 例人工判定', csrfmiddlewaretoken: tok},
    function(data) {
      if (data.code == 200) {
        el.innerText = '已采纳';
        setTimeout(function(){ location.reload(); }, 400);
      } else { alert(data.message || '操作失败'); el.dataset.confirmed = ''; el.innerText = '判例:' + verdict.toUpperCase() + '×' + n; }
    }
  ).fail(function(xhr){
    alert('采纳失败 (HTTP ' + xhr.status + ')，请刷新页面重试');
    el.dataset.confirmed = '';
  });
}
function applySuggestSkip(vulid, el) {
  var tok = kmCsrf();
  if (!tok){ alert('页面缺少 CSRF 令牌，请刷新页面后重试'); return; }
  if (!el.dataset.confirmed) {
    el.dataset.confirmed = '1';
    el.innerText = '确认按判例标FP?';
    return;
  }
  $.post('/dashboard/vuls/' + vulid + '/verify',
    {action: 'fp', notes: '判例队列采纳: 同模式人工判例一致判 FP', csrfmiddlewaretoken: tok},
    function(data) {
      if (data.code == 200) {
        el.innerText = '已采纳';
        setTimeout(function(){ location.reload(); }, 400);
      } else { alert(data.message || '操作失败'); el.dataset.confirmed = ''; el.innerText = '采纳判例'; }
    }
  ).fail(function(xhr){
    alert('采纳失败 (HTTP ' + xhr.status + ')，请刷新页面重试');
    el.dataset.confirmed = '';
  });
}
function delVul(vulid) {
  $.get('/dashboard/vuls/' + vulid + '/del', function(data) { if(data.code == 200) location.reload(); else alert(data.message); });
}

$('#btnSearch').click(function() {
  var q = $('#searchBox').val();
  var url = '?q=' + encodeURIComponent(q);
  var lang = $('select[name=lang]').val();
  if (lang) url += '&lang=' + lang;
  var cvi = $('select[name=cvi]').val();
  if (cvi) url += '&cvi=' + cvi;
  var level = $('select[name=level]').val();
  if (level) url += '&level=' + level;
  var confirm = $('select[name=confirm]').val();
  if (confirm) url += '&confirm=' + confirm;
  window.location.href = url;
});
$('#searchBox').keydown(function(e) { if (e.keyCode === 13) { e.preventDefault(); $('#btnSearch').click(); } });

$(document).ready(function() {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#vuls").addClass("active");
});

  

function aiAnalyzeVul(vulId, el){
  var d = document.getElementById('aiDrawer');
  var body = document.getElementById('aiDrawerBody');
  document.getElementById('aiDrawerTitle').innerHTML = '<i class="fa fa-magic"></i> AI 分析 · 漏洞 #' + vulId;
  body.innerHTML = '<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> AI 正在分析传播链与上下文...</div>';
  d.style.display = 'block';
  fetch('/dashboard/ai/vul/' + vulId + '/analyze', {
    method: 'POST',
    headers: {'X-CSRFToken': $('[name=csrfmiddlewaretoken]').val() || document.cookie.match(/csrftoken=([^;]+)/)?.[1] || ''},
    credentials: 'same-origin'
  }).then(r => r.json()).then(function(res){
    if(res.not_configured){ body.innerHTML = '<div class="alert alert-warning"><i class="fa fa-magic"></i> AI 功能未配置。扫描与人工审计不受影响；<a href="/dashboard/ai/settings">去配置 AI</a> 后可使用自动分诊与判定建议。</div>'; return; }
    if(res.code !== 200){ body.innerHTML = '<div class="alert alert-danger">' + (res.message||'分析失败') + '</div>'; return; }
    var d2 = res.data;
    var badge = d2.verdict === 'tp' ? '<span class="vp-ta-ok-b">真实漏洞倾向 (TP)</span>'
              : d2.verdict === 'fp' ? '<span class="vp-ta-no-b">误报倾向 (FP)</span>'
              : '<span class="vp-ta-old-b">不确定</span>';
    var sev = d2.severity_adjust === 'up' ? '建议升级等级' : d2.severity_adjust === 'down' ? '建议降级' : '维持等级';
    body.innerHTML =
      '<div class="vp-mb12">' + badge + ' · 置信度 ' + (d2.confidence||'-') + ' · ' + sev + '</div>' +
      '<div class="vp-lbl-b">判定理由</div><div class="vp-sec-title">' + (d2.reasoning||'') + '</div>' +
      '<div class="vp-lbl-b">修复建议</div><div class="vp-txt">' + (d2.fix||'') + '</div>' +
      '<div class="vp-foot-hint">AI 判定仅供参考，最终以人工审计为准。</div>';
  }).catch(function(e){
    body.innerHTML = '<div class="alert alert-danger">请求失败: ' + e + '</div>';
  });
}

/* CVE 关联标记 (Fix: cve-tagging) */
function markCve(vulId) {
  var cur = (document.getElementById('cveBadge_' + vulId) || {}).textContent || '';
  if (cur === '未关联') cur = '';
  var cve = prompt('输入要关联的 CVE 编号（留空=取消关联）：\n格式 CVE-YYYY-NNNN，如 CVE-2026-110185', cur.trim());
  if (cve === null) return;
  postCveMark(vulId, cve.trim());
}
function unmarkCve(vulId) { postCveMark(vulId, ''); }
function postCveMark(vulId, cve) {
  var fd = new FormData();
  fd.append('vul_id', vulId);
  fd.append('cve', cve);
  var m = document.cookie.match(/csrftoken=([^;]+)/);
  var headers = m ? {'X-CSRFToken': m[1]} : {};
  fetch("{% url 'dashboard:vul_cve_mark' %}", {method: 'POST', body: fd, credentials: 'same-origin', headers: headers})
    .then(function(r){ return r.json(); })
    .then(function(d){
      if (!d.ok) { alert(d.msg || '标记失败'); return; }
      var badge = document.getElementById('cveBadge_' + vulId);
      if (badge) {
        badge.textContent = d.cve || '未关联';
        badge.className = d.cve ? 'km-cve-badge-inline' : 'vp-muted';
      }
      // 列表行内徽标: 无刷新就地补一个/删掉
      var row = document.querySelector('tr.km-vul-row[data-vul-id="' + vulId + '"] td:nth-child(3)');
      if (row) {
        var old = row.querySelector('.km-cve-badge');
        if (d.cve && !old) {
          var a = document.createElement('a');
          a.href = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + d.cve;
          a.target = '_blank'; a.rel = 'noopener'; a.className = 'km-cve-badge';
          a.onclick = function(e){ e.stopPropagation(); };
          a.textContent = d.cve;
          row.appendChild(document.createTextNode(' '));
          row.appendChild(a);
        } else if (!d.cve && old) { old.remove(); }
        else if (d.cve && old) { old.textContent = d.cve; old.href = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + d.cve; }
      }
    })
    .catch(function(e){ alert('请求失败: ' + e); });
}

 