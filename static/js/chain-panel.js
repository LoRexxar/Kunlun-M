/*
 * 漏洞链面板组件（横向链 + 深色代码区）
 * 依赖: jQuery, Prism.js
 */
var chainPanelVisible = false;
var chainPanelVulId = null;

var NODE_STYLES = {
    'source':      { icon: 'fa-crosshairs',  color: '#ef4444', label: '数据入口' },
    'sink':        { icon: 'fa-bomb',        color: '#f97316', label: '危险函数' },
    'NewScan':     { icon: 'fa-search',      color: '#3b82f6', label: '匹配代码' },
    'identifier':  { icon: 'fa-tag',         color: '#6366f1', label: '变量' },
    'operator':    { icon: 'fa-cog',         color: '#f97316', label: '操作符' },
    'function':    { icon: 'fa-code',        color: '#22c55e', label: '函数' },
    'parameter':   { icon: 'fa-sliders-h',   color: '#14b8a6', label: '参数' },
    'branch':      { icon: 'fa-code-branch', color: '#ef4444', label: '分支' },
    'return':      { icon: 'fa-reply',       color: '#3b82f6', label: '返回值' },
    'file':        { icon: 'fa-file-code',   color: '#3b82f6', label: '文件' },
    'class':       { icon: 'fa-cube',        color: '#8b5cf6', label: '类' },
    'import':      { icon: 'fa-download',    color: '#eab308', label: '引入' },
    'expression':  { icon: 'fa-minus',       color: '#0ea5e9', label: '表达式' },
    'statement':   { icon: 'fa-align-left',  color: '#0ea5e9', label: '语句' },
    'string_literal':  { icon: 'fa-font',       color: '#eab308', label: '字符串' },
    'numeric_literal':  { icon: 'fa-hashtag',    color: '#f87171', label: '数值' },
};
var DEFAULT_NODE_STYLE = { icon: 'fa-circle', color: '#6366f1', label: '传播节点' };

function getNodeStyle(type) {
    return NODE_STYLES[type] || DEFAULT_NODE_STYLE;
}

function inferLang(path) {
    if (!path) return 'php';
    var ext = path.split('.').pop().toLowerCase();
    var map = {
        'php': 'php', 'php4': 'php', 'php5': 'php', 'php7': 'php',
        'py': 'python', 'py3': 'python',
        'java': 'java',
        'js': 'javascript', 'jsx': 'javascript', 'ts': 'typescript',
        'go': 'go',
        'c': 'c', 'h': 'c',
        'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp',
        'rb': 'ruby',
        'sol': 'solidity',
    };
    return map[ext] || 'php';
}

function toggleChainPanel(btnOrId) {
    var vulId, row;

    if (typeof btnOrId === 'string' || typeof btnOrId === 'number') {
        vulId = String(btnOrId);
        row = document.querySelector('tr[data-vul-id="' + vulId + '"]');
    } else {
        vulId = btnOrId.getAttribute('data-vul-id');
        row = btnOrId.closest('tr');
    }

    var panel = document.getElementById('chainPanel');
    if (!panel) return;
    if (!row) return;

    // 点击同一个 → 关闭
    if (chainPanelVisible && chainPanelVulId == vulId) {
        panel.style.display = 'none';
        chainPanelVisible = false;
        chainPanelVulId = null;
        document.querySelectorAll('.km-chain-row-active').forEach(function(el) {
            el.classList.remove('km-chain-row-active');
        });
        return;
    }

    document.querySelectorAll('.km-chain-row-active').forEach(function(el) {
        el.classList.remove('km-chain-row-active');
    });

    row.after(panel);
    chainPanelVulId = vulId;
    chainPanelVisible = true;
    panel.style.display = 'table-row';
    row.classList.add('km-chain-row-active');

    renderChain(vulId);
}

/* ── 横向传播链渲染 ── */
function renderChain(vulId) {
    var nodes = chainDataMap[vulId];
    var flowContainer = document.getElementById('chainSidebar');
    var codeArea = document.getElementById('chainCode');
    if (!flowContainer || !codeArea) return;

    if (!nodes || nodes.length === 0) {
        flowContainer.innerHTML = '<div class="km-chain-empty">暂无链数据</div>';
        codeArea.innerHTML = '<div class="km-chain-code-placeholder">暂无传播链数据</div>';
        return;
    }

    // 渲染横向节点
    var html = '';
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var style = getNodeStyle(node.type);
        var isLast = (i === nodes.length - 1);
        var shortName = node.content || node.type;
        if (shortName.length > 16) shortName = shortName.substring(0, 15) + '…';
        var filename = node.path ? node.path.split('/').pop() : '';

        html += '<div class="km-flow-node' + (isLast ? ' km-flow-node-active' : '') + '" data-idx="' + i + '" onclick="selectChainNode(' + i + ')" title="' + escapeHtml(node.content || '') + (node.path ? '\n' + filename + ':' + node.lineno : '') + '">';
        html += '  <div class="km-flow-node-dot" style="background:' + style.color + '; border-color:' + style.color + '">';
        html += '    <i class="fa ' + style.icon + '"></i>';
        html += '  </div>';
        html += '  <div class="km-flow-node-text" style="color:' + style.color + '">' + escapeHtml(shortName) + '</div>';
        html += '  <div class="km-flow-node-meta">' + escapeHtml(style.label) + (filename ? ' · ' + filename + ':' + node.lineno : '') + '</div>';
        html += '</div>';

        if (i < nodes.length - 1) {
            html += '<div class="km-flow-arrow"><i class="fa fa-chevron-right"></i></div>';
        }
    }
    flowContainer.innerHTML = html;

    // 默认选中最后一个节点 (sink)
    selectChainNode(nodes.length - 1);
}

/* ── 整文件源码缓存（链-码对照模式） ── */
var chainFileCache = {};   // path -> {pid, lines}
function chainProjectId() {
    // 从 URL 推断项目 id：/dashboard/projects/<id>
    var m = location.pathname.match(/\/dashboard\/projects\/(\d+)/);
    return m ? m[1] : (window.chainProjectIdOverride || null);
}
function loadFullFile(node, codeArea, cb) {
    var pid = chainProjectId();
    if (!pid || !node.path) { cb(null); return; }
    var cached = chainFileCache[node.path];
    if (cached) { cb(cached.lines); return; }
    codeArea.innerHTML = '<div class="km-code-header"><i class="fa fa-spinner fa-spin"></i> 加载整文件源码...</div>';
    var url = '/dashboard/projects/' + pid + '/files/content?file=' + encodeURIComponent(node.path)
        + '&lineno=' + (node.lineno || 0);
    fetch(url, {credentials:'same-origin'}).then(function(r){ return r.json(); }).then(function(d){
        var lines = d && d.lines;
        if (lines && lines.length && typeof lines[0] === 'object') {
            lines = lines.map(function(l){ return l.code; });
        }
        if (!lines || !lines.length) { cb(null); return; }
        chainFileCache[node.path] = { lines: lines };
        cb(lines);
    }).catch(function(){ cb(null); });
}

/* ── 节点选中 → 下方代码区（深色主题） ── */
function selectChainNode(idx) {
    var nodes = chainDataMap[chainPanelVulId];
    if (!nodes || !nodes[idx]) return;

    var node = nodes[idx];

    // 更新节点高亮
    document.querySelectorAll('.km-flow-node').forEach(function(el) {
        el.classList.remove('km-flow-node-active');
    });
    var activeNode = document.querySelector('.km-flow-node[data-idx="' + idx + '"]');
    if (activeNode) activeNode.classList.add('km-flow-node-active');
    // 同步滚动节点进视野
    if (activeNode && activeNode.scrollIntoView) activeNode.scrollIntoView({block:'nearest', inline:'nearest'});

    var codeArea = document.getElementById('chainCode');
    if (!codeArea) return;

    var style = getNodeStyle(node.type);
    var targetLineno = parseInt(node.lineno) || 0;

    // 优先整文件模式（链-码对照：能看到漏洞位置在文件中的空间关系）
    if (node.path && targetLineno > 0) {
        var header = '<div class="km-code-header">'
            + '<span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span>'
            + '<span class="km-code-path">' + escapeHtml(node.path) + ':' + node.lineno + '</span>'
            + '<button class="btn btn-default btn-sm" style="margin-left:auto;padding:2px 8px;font-size:11px;" '
            + 'onclick="openChainFileBrowser(' + idx + ')" title="在源码浏览器中打开（可搜索/滚动全文）"><i class="fa fa-external-link"></i> 源码浏览器</button>'
            + '</div>';
        loadFullFile(node, codeArea, function(lines){
            if (lines) {
                renderFullFile(codeArea, node, style, lines, targetLineno, header);
            } else {
                renderSnippetFallback(node, style);
            }
        });
        return;
    }
    renderSnippetFallback(node, style);
}

function openChainFileBrowser(idx) {
    var nodes = chainDataMap[chainPanelVulId];
    if (!nodes || !nodes[idx]) return;
    var node = nodes[idx];
    var pid = chainProjectId();
    if (!pid) { alert('未找到项目 ID'); return; }
    window.open('/dashboard/projects/' + pid + '/files?file=' + encodeURIComponent(node.path)
        + '&lineno=' + (node.lineno || 0), '_blank');
}

function renderFullFile(codeArea, node, style, lines, targetLineno, header) {
    var lang = inferLang(node.path);
    var fullText = lines.join('\n');
    var highlightedText = fullText;
    try {
        if (window.Prism && Prism.languages[lang]) {
            highlightedText = Prism.highlight(fullText, Prism.languages[lang], lang);
            highlightedText = sanitizeHighlightedCode(highlightedText);
        }
    } catch (e) {}
    var hl = highlightedText.split('\n');
    var html = header;
    html += '<div class="km-code-body" id="kmFullFileBody"><table class="km-code-table"><tbody>';
    for (var i = 0; i < hl.length; i++) {
        var lineno = i + 1;
        var isTarget = (lineno === targetLineno);
        var near = Math.abs(lineno - targetLineno) <= 5;
        html += '<tr class="' + (isTarget ? 'km-code-line-highlight' : (near ? 'km-code-line-near' : '')) + '" id="kmFileLine' + lineno + '">';
        html += '<td class="km-code-lineno">' + lineno + '</td>';
        html += '<td class="km-code-line">' + (hl[i] || ' ') + '</td>';
        html += '</tr>';
    }
    html += '</tbody></table></div>';
    codeArea.innerHTML = html;
    // 滚动到目标行
    var el = document.getElementById('kmFileLine' + targetLineno);
    if (el) el.scrollIntoView({block:'center'});
}

function renderSnippetFallback(node, style) {
    var codeArea = document.getElementById('chainCode');
    if (!codeArea) return;
    if (node.source) {
        var sourceLines = node.source.split('\n');
        var targetLineno = parseInt(node.lineno) || 0;

        var rawLines = [];
        var lineNums = [];
        for (var i = 0; i < sourceLines.length; i++) {
            var m = sourceLines[i].match(/^(\s*)(\d+):\s?(.*)/);
            if (m) {
                lineNums.push(parseInt(m[2]));
                rawLines.push(m[3]);
            }
            // 跳过空行，避免渲染多余的空行
        }
        // 去掉末尾空行
        while (rawLines.length > 0 && rawLines[rawLines.length - 1].trim() === '' && lineNums[lineNums.length - 1] === 0) {
            rawLines.pop();
            lineNums.pop();
        }

        var fullText = rawLines.join('\n');
        var lang = inferLang(node.path);
        var highlightedText = fullText;
        try {
            if (window.Prism && Prism.languages[lang]) {
                highlightedText = Prism.highlight(fullText, Prism.languages[lang], lang);
                highlightedText = sanitizeHighlightedCode(highlightedText);
            }
        } catch (e) {}

        var highlightedLines = highlightedText.split('\n');

        var html = '<div class="km-code-header">';
        html += '<span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span>';
        if (node.path) {
            html += '<span class="km-code-path">' + escapeHtml(node.path) + ':' + node.lineno + '</span>';
        }
        html += '</div>';
        html += '<div class="km-code-body"><table class="km-code-table"><tbody>';
        for (var i = 0; i < highlightedLines.length; i++) {
            var isTarget = (lineNums[i] === targetLineno);
            html += '<tr class="' + (isTarget ? 'km-code-line-highlight' : '') + '">';
            html += '<td class="km-code-lineno">' + (lineNums[i] || '') + '</td>';
            html += '<td class="km-code-line">' + highlightedLines[i] + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        codeArea.innerHTML = html;
    } else {
        codeArea.innerHTML = '<div class="km-code-header"><span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span></div>'
            + '<div class="km-code-body"><pre style="margin:0;padding:16px;font-size:13px;font-family:\'Fira Code\',Consolas,monospace;color:#c9d1d9;background:#0d1117;">' + escapeHtml(node.content || '(无代码)') + '</pre></div>';
    }
}
