/*
 * 漏洞链面板组件（inline row 版本）
 * 依赖: jQuery, Prism.js
 *
 * chain panel 以 <tr id="chainPanel"> 形式存在于表格 tbody 中，
 * toggleChainPanel() 会将其 DOM 移动到对应漏洞行之后。
 *
 * Data passed via Django template rendering into chainDataMap.
 */
var chainPanelVisible = false;
var chainPanelVulId = null;

// 节点类型图标和颜色
var NODE_STYLES = {
    'source':      { icon: 'fa-crosshairs',  color: '#e74c3c', label: '数据入口' },
    'sink':        { icon: 'fa-bomb',        color: '#e67e22', label: '危险函数' },
    'NewScan':     { icon: 'fa-search',      color: '#3498db', label: '匹配代码' },
    'identifier':  { icon: 'fa-tag',         color: '#95a5a6', label: '变量' },
    'operator':    { icon: 'fa-cog',         color: '#e67e22', label: '操作符' },
    'function':    { icon: 'fa-code',        color: '#2ecc71', label: '函数' },
    'parameter':   { icon: 'fa-sliders-h',   color: '#1abc9c', label: '参数' },
    'branch':      { icon: 'fa-code-branch', color: '#e74c3c', label: '分支' },
    'return':      { icon: 'fa-reply',       color: '#3498db', label: '返回值' },
    'file':        { icon: 'fa-file-code',   color: '#3498db', label: '文件' },
    'class':       { icon: 'fa-cube',        color: '#9b59b6', label: '类' },
    'import':      { icon: 'fa-download',    color: '#f1c40f', label: '引入' },
    'expression':  { icon: 'fa-minus',       color: '#74b9ff', label: '表达式' },
    'statement':   { icon: 'fa-align-left',  color: '#74b9ff', label: '语句' },
    'string_literal':  { icon: 'fa-font',       color: '#ffeaa7', label: '字符串' },
    'numeric_literal':  { icon: 'fa-hashtag',    color: '#fab1a0', label: '数值' },
};
var DEFAULT_NODE_STYLE = { icon: 'fa-circle', color: '#95a5a6', label: '传播节点' };

function getNodeStyle(type) {
    return NODE_STYLES[type] || DEFAULT_NODE_STYLE;
}

// 从文件路径推断语言
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

function toggleChainPanel(btn) {
    var vulId = btn.getAttribute('data-vul-id');
    var panel = document.getElementById('chainPanel');
    if (!panel) return;

    var row = btn.closest('tr');
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

    // 清除之前高亮
    document.querySelectorAll('.km-chain-row-active').forEach(function(el) {
        el.classList.remove('km-chain-row-active');
    });

    // 移动面板到对应行之后
    row.after(panel);

    chainPanelVulId = vulId;
    chainPanelVisible = true;
    panel.style.display = 'table-row';
    row.classList.add('km-chain-row-active');

    renderChain(vulId);
}

function renderChain(vulId) {
    var nodes = chainDataMap[vulId];
    var sidebar = document.getElementById('chainSidebar');
    var codeArea = document.getElementById('chainCode');
    if (!sidebar || !codeArea) return;

    if (!nodes || nodes.length === 0) {
        sidebar.innerHTML = '<div class="km-chain-empty">暂无链数据</div>';
        codeArea.innerHTML = '<div class="km-chain-empty">选择左侧节点查看代码</div>';
        return;
    }

    // 渲染左侧节点链
    var html = '<div class="km-chain-title">漏洞传播链</div>';
    html += '<div class="km-chain-nodes">';
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var style = getNodeStyle(node.type);
        var relPath = node.path || '';
        var isActive = (i === nodes.length - 1);

        html += '<div class="km-chain-node' + (isActive ? ' km-chain-node-active' : '') + '" data-idx="' + i + '" onclick="selectChainNode(' + i + ')">';
        html += '  <div class="km-chain-node-icon" style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i></div>';
        html += '  <div class="km-chain-node-info">';
        html += '    <div class="km-chain-node-type" style="color:' + style.color + '">' + (style.label || node.type) + '</div>';
        html += '    <div class="km-chain-node-content" title="' + escapeHtml(node.content) + '">' + escapeHtml(node.content) + '</div>';
        if (relPath && node.lineno) {
            html += '    <div class="km-chain-node-loc">' + escapeHtml(relPath.split('/').pop()) + ':' + node.lineno + '</div>';
        }
        html += '  </div>';
        html += '</div>';

        if (i < nodes.length - 1) {
            html += '<div class="km-chain-connector"><div class="km-chain-connector-line"></div></div>';
        }
    }
    html += '</div>';
    sidebar.innerHTML = html;

    // 默认选中最后一个节点 (sink)
    selectChainNode(nodes.length - 1);
}

function selectChainNode(idx) {
    var nodes = chainDataMap[chainPanelVulId];
    if (!nodes || !nodes[idx]) return;

    var node = nodes[idx];

    // 更新左侧高亮
    document.querySelectorAll('.km-chain-node').forEach(function(el) {
        el.classList.remove('km-chain-node-active');
    });
    var activeNode = document.querySelector('.km-chain-node[data-idx="' + idx + '"]');
    if (activeNode) activeNode.classList.add('km-chain-node-active');

    // 右侧显示代码
    var codeArea = document.getElementById('chainCode');
    if (!codeArea) return;

    var style = getNodeStyle(node.type);

    if (node.source) {
        var sourceLines = node.source.split('\n');
        var targetLineno = parseInt(node.lineno) || 0;

        // 解析 source 格式 "  12: code_content"，提取行号和代码
        var rawLines = [];
        var lineNums = [];
        for (var i = 0; i < sourceLines.length; i++) {
            var m = sourceLines[i].match(/^(\s*)(\d+):\s?(.*)/);
            if (m) {
                lineNums.push(parseInt(m[2]));
                rawLines.push(m[3]);
            } else {
                rawLines.push(sourceLines[i]);
                lineNums.push(0);
            }
        }

        // 整段 Prism 高亮（保留多行注释/字符串完整性）
        var fullText = rawLines.join('\n');
        var lang = inferLang(node.path);
        var highlightedText = fullText;
        try {
            if (window.Prism && Prism.languages[lang]) {
                highlightedText = Prism.highlight(fullText, Prism.languages[lang], lang);
            }
        } catch (e) {}

        var highlightedLines = highlightedText.split('\n');

        // 渲染
        var html = '<div class="km-chain-code-header">';
        html += '<span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span>';
        if (node.path) {
            html += ' <span class="km-chain-code-path">' + escapeHtml(node.path.split('/').pop()) + ':' + node.lineno + '</span>';
        }
        html += '</div>';
        html += '<div class="km-chain-code-body">';
        html += '<table class="km-chain-code-table"><tbody>';
        for (var i = 0; i < highlightedLines.length; i++) {
            var isTarget = (lineNums[i] === targetLineno);
            html += '<tr class="' + (isTarget ? 'km-chain-line-highlight' : '') + '">';
            html += '<td class="km-chain-lineno">' + (lineNums[i] || '') + '</td>';
            html += '<td class="km-chain-code-line">' + highlightedLines[i] + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        codeArea.innerHTML = html;
    } else {
        codeArea.innerHTML = '<div class="km-chain-code-header"><span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span></div>'
            + '<div class="km-chain-code-body"><pre style="margin:0; padding:12px; font-size:14px; font-family:\'Fira Code\',Consolas,monospace; background:#eaedf1; color:#24292e;">' + escapeHtml(node.content || '(无代码)') + '</pre></div>';
    }
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
