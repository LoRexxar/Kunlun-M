 

// 快速跳转
$(function(){
  $('#quickSearch').on('keydown', function(e){
    if(e.key === 'Enter'){
      var val = $(this).val().trim();
      if(!val) return;
      // 纯数字 → 项目详情
      if(/^\d+$/.test(val)){
        window.location.href = '{% url "dashboard:project_detail" 0 %}'.replace('/0', '/' + val);
        return;
      }
      // 其他 → 项目列表搜索
      window.location.href = '{% url "dashboard:projects_list" %}?project_name=' + encodeURIComponent('*' + val + '*');
    }
  });
});

  

  $(document).ready(function () {
    $("#dashboard").removeClass("active menu-open");
    $("#dashboard").find("ul li").removeClass("active");
    $("#docs").addClass("active");

    var apiListUrl = "{% url 'dashboard:docs_api_list' %}";
    var apiFileUrl = "{% url 'dashboard:docs_api_file' %}";
    var defaultPath = "{{ default_doc_path|escapejs }}";

    var $list = $("#docsList");
    var $filter = $("#docsFilterInput");
    var $title = $("#docsTitle");
    var $rendered = $("#docsRendered");
    var $sourcePre = $("#docsSourcePre");
    var sourceCodeEl = document.getElementById("docsSourceCode");
    var renderedEl = document.getElementById("docsRendered");

    var state = {
      files: [],
      mode: "render",
      currentPath: null,
      currentMd: ""
    };

    function setMode(mode) {
      state.mode = mode;
      $("#docsModeRender").toggleClass("is-active", mode === "render");
      $("#docsModeSource").toggleClass("is-active", mode === "source");
      $rendered.toggle(mode === "render");
      $sourcePre.toggle(mode === "source");
    }

    function setActive(path) {
      $list.find(".km-docs-item").removeClass("is-active");
      $list.find('.km-docs-item[data-path="' + path.replace(/"/g, '\\"') + '"]').addClass("is-active");
    }

    function urlWithPath(base, path) {
      return base + (base.indexOf("?") === -1 ? "?" : "&") + "path=" + encodeURIComponent(path);
    }

    function pickFromQueryOrDefault(files) {
      var u = new URL(window.location.href);
      var p = (u.searchParams.get("path") || "").trim();
      if (p) return p;
      if (defaultPath) return defaultPath;
      return (files[0] && files[0].path) || null;
    }

    function updateQuery(path) {
      var u = new URL(window.location.href);
      u.searchParams.set("path", path);
      history.replaceState(null, "", u.toString());
    }

    function renderList(files) {
      var q = ($filter.val() || "").toLowerCase().trim();
      var html = files
        .filter(function (f) {
          if (!q) return true;
          return (f.path || "").toLowerCase().indexOf(q) > -1 || (f.name || "").toLowerCase().indexOf(q) > -1;
        })
        .map(function (f) {
          return '<button type="button" class="km-docs-item" data-path="' + f.path + '"><span class="km-docs-item-name">' + f.path + '</span></button>';
        })
        .join("");
      $list.html(html || '<div class="km-docs-empty">没有匹配的文档</div>');
    }

    function setContent(path, md) {
      state.currentPath = path;
      state.currentMd = md || "";
      $title.text(path);
      sourceCodeEl.textContent = state.currentMd;
      if (window.Prism) {
        Prism.highlightElement(sourceCodeEl);
      }
      var html = window.kmMarkdownLite ? window.kmMarkdownLite.render(state.currentMd) : "";
      renderedEl.innerHTML = html;
      if (window.Prism && window.Prism.highlightAllUnder) {
        Prism.highlightAllUnder(renderedEl);
      }
      setActive(path);
      updateQuery(path);
    }

    function loadDoc(path) {
      if (!path) return;
      $.getJSON(urlWithPath(apiFileUrl, path))
        .done(function (res) {
          if (!res || res.status !== "ok") {
            setContent(path, "加载失败");
            return;
          }
          setContent(res.path || path, res.content || "");
        })
        .fail(function () {
          setContent(path, "加载失败");
        });
    }

    $list.on("click", ".km-docs-item", function () {
      var path = $(this).attr("data-path");
      loadDoc(path);
    });

    $rendered.on("click", "a.km-md-link", function (e) {
      var href = $(this).attr("href") || "";
      if (!href) return;
      if (href.indexOf("#") === 0) return;
      if (/\.md($|[?#])/i.test(href) && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(href)) {
        e.preventDefault();
        loadDoc(href.replace(/^\//, ""));
      }
    });

    $filter.on("input", function () {
      renderList(state.files);
    });

    $("#docsModeRender").on("click", function () {
      setMode("render");
    });
    $("#docsModeSource").on("click", function () {
      setMode("source");
    });

    setMode("render");
    $.getJSON(apiListUrl).done(function (res) {
      state.files = (res && res.files) || [];
      renderList(state.files);
      var p = pickFromQueryOrDefault(state.files);
      if (p) loadDoc(p);
      else {
        $title.text("docs/ 目录下没有可用的 .md");
        setMode("render");
      }
    });
  });

  

$(document).ready(function () {
    // 侧边栏高亮
    $("#dashboard").removeClass("active menu-open");
    $("#dashboard").find("ul li").removeClass("active");
    $("#graph_analysis").addClass("active");

    var currentScanId = null;
    var selectedFilePath = null;
    var scanProjectMap = {};  // scan_id → project_id 缓存
    var graphLoaded = false;  // 当前 scan 的图是否已加载到后端
    var graphIdleTimer = null;  // 定时轮询后端 idle 状态
    var graphIdleMaxSec = 30 * 60;  // 默认 30 分钟

    // ===== 加载 scan 列表 =====
    function loadScans() {
        $.ajax({
            url: '/api/graph/scans',
            type: 'GET',
            dataType: 'json',
            success: function (resp) {
                if (resp.code === 200 && resp.scans && resp.scans.length > 0) {
                    var $sel = $('#scanSelect');
                    $sel.empty().append('<option value="">-- 选择 Scan --</option>');
                    var lostCount = 0;
                    $.each(resp.scans, function (i, s) {
                        if (s.project_id) { scanProjectMap[s.id] = s.project_id; }
                        var missing = (s.graph_exists === false);
                        if (missing) lostCount++;
                        var opt = '<option value="' + s.id + '"'
                            + (missing ? ' disabled class="gp-color-muted" ' : '') + '>'
                            + 'ID:' + s.id + ' | ' + (s.language || '?') + ' | '
                            + (s.target || '-') + ' (节点:' + (s.node_count || 0) + ' 边:' + (s.edge_count || 0) + ')'
                            + (missing ? ' [图已清理]' : '')
                            + '</option>';
                        $sel.append(opt);
                    });
                    if (lostCount > 0) {
                        $sel.after('<div class="alert alert-warning gp-note-sm"><i class="fa fa-info-circle"></i> 有 ' + lostCount + ' 条历史扫描的图数据已被清理（重扫时 workspace 被重置）。当前扫描的图会持续保留。</div>');
                    }
                    // 自动选择最新的（第一个）
                    $sel.val(resp.scans[0].id);
                    selectScan(resp.scans[0].id);

                    // URL 参数自动填充（从 task_detail 跳转过来时）
                    var urlParams = new URLSearchParams(window.location.search);
                    var preScanId = urlParams.get('scan_id');
                    var preFilePath = urlParams.get('file_path');
                    var preVid = urlParams.get('vid');
                    var preTab = urlParams.get('tab');
                    if (preScanId) {
                        // 尝试选择指定的 scan_id
                        var found = resp.scans.find(function(s) { return String(s.id) === String(preScanId); });
                        if (found) {
                            $sel.val(found.id);
                            selectScan(found.id);
                        }
                    }
                    // 延迟加载子图（等待 scan_id 设置好）
                    if (preVid !== null && preVid !== '') {
                        setTimeout(function() {
                            loadSubgraph(currentScanId, parseInt(preVid));
                        }, 300);
                    } else if (preFilePath) {
                        setTimeout(function() {
                            loadFileGraph(currentScanId, preFilePath);
                        }, 300);
                    }
                    if (preTab === 'graph') {
                        // 直接切换到图可视化 tab
                        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
                        $('.tab-btn[data-tab="tab-graph"]').removeClass('btn-default').addClass('btn-primary');
                        $('.tab-pane').hide();
                        $('#tab-graph').show();
                        ensureCytoscape();
                    }
                } else {
                    $('#scanSelect').empty().append('<option value="">暂无扫描记录</option>');
                }
            },
            error: function () {
                $('#scanSelect').empty().append('<option value="">加载失败</option>');
            }
        });
    }
    loadScans();

    // ===== Graph 加载 / 释放 / 状态轮询 =====
    function loadGraph(scanId, callback) {
        if (!scanId) return;
        var $btn = $('#btnLoadGraph');
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> 加载中（大图可能需要 10-30 秒）...');

        $.ajax({
            url: '/api/graph/load',
            type: 'POST',
            data: { scan_id: scanId },
            dataType: 'json',
            timeout: 120000,
            success: function (resp) {
                if (resp.code === 200) {
                    graphLoaded = true;
                    _showSessionPanel(resp);
                    $btn.hide();
                    $('#btnReleaseGraph').show();
                    $('#graphLoadStatus').html('');
                    // 自动加载概览
                    _doLoadOverview(scanId);
                    if (callback) callback();
                } else {
                    $('#graphLoadStatus').html('<span class="text-danger"><i class="fa fa-times-circle"></i> ' + (resp.error || '加载失败') + '</span>');
                    $btn.prop('disabled', false).html('<i class="fa fa-download"></i> 加载图数据');
                }
            },
            error: function (xhr) {
                var msg = '网络错误';
                try { var d = JSON.parse(xhr.responseText); msg = d.error || msg; } catch(e) {}
                $('#graphLoadStatus').html('<span class="text-danger"><i class="fa fa-times-circle"></i> ' + msg + '</span>');
                $btn.prop('disabled', false).html('<i class="fa fa-download"></i> 加载图数据');
            }
        });
    }

    function releaseGraph(scanId) {
        _stopIdlePoll();
        $.ajax({
            url: '/api/graph/release',
            type: 'POST',
            data: { scan_id: scanId || '' },
            dataType: 'json',
            success: function (resp) {
                graphLoaded = false;
                $('#btnReleaseGraph').hide();
                $('#btnLoadGraph').show().prop('disabled', false).html('<i class="fa fa-download"></i> 加载图数据');
                $('#graphSessionPanel').hide();
                $('#graphLoadStatus').html('<span class="text-muted"><i class="fa fa-check"></i> 已释放</span>');
            }
        });
    }

    function _showSessionPanel(data) {
        var $panel = $('#graphSessionPanel').show();
        $('#gsNodes').text(data.node_count || '-');
        $('#gsEdges').text(data.edge_count || '-');
        if (data.idle_timeout_minutes) {
            graphIdleMaxSec = data.idle_timeout_minutes * 60;
            $('#gsIdleMax').text(data.idle_timeout_minutes);
        }
        $('#gsIdleSec').text(0);
        $('#gsIdleBar').css('width', '0%').css('background', '#2ecc71');
        _startIdlePoll();
    }

    function _startIdlePoll() {
        _stopIdlePoll();
        graphIdleTimer = setInterval(function () {
            if (!graphLoaded) { _stopIdlePoll(); return; }
            $.ajax({
                url: '/api/graph/status',
                type: 'GET',
                dataType: 'json',
                success: function (resp) {
                    if (resp.code !== 200 || !resp.loaded || resp.loaded.length === 0) {
                        // 后端已自动释放
                        graphLoaded = false;
                        _stopIdlePoll();
                        $('#graphSessionPanel').hide();
                        $('#btnReleaseGraph').hide();
                        $('#btnLoadGraph').show().prop('disabled', false).html('<i class="fa fa-download"></i> 加载图数据');
                        $('#graphLoadStatus').html('<span class="text-warning"><i class="fa fa-clock-o"></i> 图数据已因空闲超时自动释放</span>');
                        return;
                    }
                    var s = resp.loaded[0];
                    var idle = s.idle_seconds || 0;
                    var maxSec = (s.idle_timeout_minutes || 30) * 60;
                    var pct = Math.min(100, (idle / maxSec) * 100);
                    $('#gsIdleSec').text(idle);
                    $('#gsIdleBar').css('width', pct + '%');
                    // 颜色变化：绿 → 黄 → 红
                    if (pct < 60) { $('#gsIdleBar').css('background', '#2ecc71'); }
                    else if (pct < 85) { $('#gsIdleBar').css('background', '#f39c12'); }
                    else { $('#gsIdleBar').css('background', '#e74c3c'); }
                }
            });
        }, 5000);  // 每 5 秒轮询一次
    }

    function _stopIdlePoll() {
        if (graphIdleTimer) { clearInterval(graphIdleTimer); graphIdleTimer = null; }
    }

    function requireGraph(callback) {
        if (graphLoaded) { callback(); return; }
        $('#graphLoadStatus').html('<span class="text-warning"><i class="fa fa-exclamation-triangle"></i> 请先加载图数据</span>');
        alert('请先点击"加载图数据"按钮加载 AST 图。\n\n大图加载可能需要 10-30 秒，加载完成后可进行所有查询操作。');
    }

    $('#btnLoadGraph').on('click', function () {
        loadGraph(currentScanId);
    });

    $('#btnReleaseGraph, #btnReleaseGraph2').on('click', function () {
        if (confirm('确定释放当前图数据？\n\n释放后所有未保存的查询结果将丢失，后续查询需要重新加载。')) {
            releaseGraph(currentScanId);
        }
    });

    // 检查后端已有 session（页面刷新时复用缓存）
    function checkGraphStatus() {
        $.ajax({
            url: '/api/graph/status',
            type: 'GET',
            dataType: 'json',
            success: function (resp) {
                if (resp.code === 200 && resp.loaded && resp.loaded.length > 0) {
                    var s = resp.loaded[0];
                    if (String(s.scan_id) === String(currentScanId)) {
                        graphLoaded = true;
                        $('#btnLoadGraph').hide();
                        $('#btnReleaseGraph').show();
                        $('#graphLoadStatus').html('');
                        _showSessionPanel(s);
                    } else {
                        // 后端有其他 scan 的 session，释放它
                        releaseGraph(s.scan_id);
                    }
                }
            }
        });
    }

    // ===== 选择 scan =====
    function selectScan(scanId) {
        currentScanId = scanId;
        var $sel = $('#scanSelect');
        var opt = $sel.find('option:selected');
        if (scanId && opt.val()) {
            $('#scanInfoBox').show();
            $('#scanInfoId').text(scanId);
            // 从列表文本中解析基本信息
            var text = opt.text();
            var langMatch = text.match(/\| (\w+) \|/);
            var nodeMatch = text.match(/节点:(\d+)/);
            var edgeMatch = text.match(/边:(\d+)/);
            var targetMatch = text.match(/ \| (.+?) \(节点/);
            $('#scanInfoLang').text(langMatch ? langMatch[1] : '-');
            $('#scanInfoNodes').text(nodeMatch ? nodeMatch[1] : '-');
            $('#scanInfoEdges').text(edgeMatch ? edgeMatch[1] : '-');
            $('#scanInfoTarget').text(targetMatch ? targetMatch[1] : '-');
            // 切换 scan 时重置加载状态，检查后端缓存
            graphLoaded = false;
            $('#btnLoadGraph').show().prop('disabled', false).html('<i class="fa fa-download"></i> 加载图数据');
            $('#btnReleaseGraph').hide();
            $('#graphLoadStatus').html('');
            checkGraphStatus();
        } else {
            $('#scanInfoBox').hide();
        }
    }

    $('#btnSelectScan').on('click', function () {
        var scanId = $('#scanSelect').val();
        selectScan(scanId ? parseInt(scanId) : null);
    });

    $('#scanSelect').on('change', function () {
        var scanId = $(this).val();
        selectScan(scanId ? parseInt(scanId) : null);
    });

    // ===== Tab 切换 =====
    $('.tab-btn').on('click', function () {
        var tabId = $(this).data('tab');
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $(this).removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#' + tabId).show();
        // Cytoscape needs to be initialized AFTER the container is visible and reflowed
        if (tabId === 'tab-graph') {
            ensureCytoscape();
        }
    });

    // ===== Tab 1: 概览 =====
    $('#btnLoadOverview').on('click', function () {
        loadOverview(currentScanId);
    });

    function loadOverview(scanId) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        requireGraph(function() {
            _doLoadOverview(scanId);
        });
    }
    function _doLoadOverview(scanId) {
        var $btn = $('#btnLoadOverview');
        $btn.prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> 加载中...');
        // 显示 loading 占位
        var loadingHtml = '<tr><td colspan="3" class="text-center gp-pad10"><i class="fa fa-spinner fa-spin text-primary"></i> 正在加载...</td></tr>';
        $('#labelSummaryBody').html(loadingHtml);
        $('#fileListBody').html('<tr><td colspan="4" class="text-center gp-pad10"><i class="fa fa-spinner fa-spin text-primary"></i> 正在加载...</td></tr>');
        $('#edgeTypeBody').html('<tr><td colspan="4" class="text-center gp-pad10"><i class="fa fa-spinner fa-spin text-primary"></i> 正在加载...</td></tr>');

        $.ajax({
            url: '/api/graph/query',
            type: 'GET',
            data: { scan_id: scanId, query_type: 'overview' },
            dataType: 'json',
            success: function (resp) {
                $btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> 加载概览');
                if (resp.code !== 200 || !resp.data) {
                    $('#labelSummaryBody').html('<tr><td colspan="2" class="text-center text-danger">加载失败</td></tr>');
                    return;
                }
                var d = resp.data;

                // 统计卡片
                $('#overviewCards').show();
                $('#statNodeCount').text(d.node_count || 0);
                $('#statEdgeCount').text(d.edge_count || 0);
                $('#statFuncCount').text(d.function_count || 0);
                $('#statSinkCount').text(d.sink_count || 0);

                // Label Summary + 条形图
                var $lb = $('#labelSummaryBody').empty();
                var $chart = $('#labelChart');
                if (d.label_summary) {
                    // 计算最大值
                    var maxCount = 0;
                    $.each(d.label_summary, function (label, count) { if (count > maxCount) maxCount = count; });

                    // 渲染水平条形图
                    var labelColors = {
                        'file': '#3498db', 'class': '#9b59b6', 'function': '#2ecc71',
                        'operator': '#e67e22', 'parameter': '#1abc9c', 'identifier': '#95a5a6',
                        'branch': '#e74c3c', 'import': '#f1c40f', 'return': '#3498db',
                        'statement': '#74b9ff', 'expression': '#a29bfe',
                        'string_literal': '#ffeaa7', 'numeric_literal': '#fab1a0', 'comment': '#636e72',
                        'dependency': '#ff9800', 'annotation': '#e91e63'
                    };
                    var chartHtml = '<div class="gp-legend-bar">';
                    $.each(d.label_summary, function (label, count) {
                        var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
                        var color = labelColors[label] || '#999';
                        chartHtml += '<div class="gp-bar-fill" style="width:' + pct + '%;background:' + color + ';" title="' + escHtml(label) + ': ' + count + '"></div>';
                    });
                    chartHtml += '</div>';
                    $chart.html(chartHtml);

                    // 表格行增加比例条
                    $.each(d.label_summary, function (label, count) {
                        var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
                        var color = labelColors[label] || '#999';
                        $lb.append('<tr><td><span class="gp-legend-dot" style="background:' + color + ';"></span><code>' + escHtml(label) + '</code></td><td class="gp-ta-r">' + count + '</td><td><div class="gp-bar-track"><div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:2px;"></div></div></td></tr>');
                    });
                } else {
                    $chart.html('');
                    $lb.append('<tr><td colspan="3" class="text-center km-muted">无数据</td></tr>');
                }

                // 文件列表
                var $fl = $('#fileListBody').empty();
                if (d.files && d.files.length > 0) {
                    // 大列表优化：缓存全量，首屏只渲染 80 行，靠过滤框增量显示
                    window._overviewFiles = d.files;
                    renderFileList($fl, d.files, 80);
                    var $hint = $('#fileListHint');
                    if ($hint.length === 0) {
                        $('#fileListBody').closest('table').before(
                            '<div class="input-group input-group-sm gp-mb6">' +
                            '<input id="fileListFilter" class="form-control form-control-sm" placeholder="过滤文件名... (共 ' + d.files.length + ' 个文件)">' +
                            '</div><div id="fileListHint" class="km-muted gp-kb-sub">显示前 80 / ' + d.files.length + ' 个</div>');
                        $('#fileListFilter').on('input', function () {
                            var kw = $(this).val().toLowerCase();
                            var flt = (window._overviewFiles || []).filter(function (f) {
                                return (f.path || f.name || '').toLowerCase().indexOf(kw) >= 0;
                            });
                            renderFileList($('#fileListBody'), flt, 200);
                            $('#fileListHint').text('匹配 ' + flt.length + ' 个（最多显示 200）');
                        });
                    } else {
                        $('#fileListHint').text('显示前 80 / ' + d.files.length + ' 个');
                    }
                } else {
                    $fl.append('<tr><td colspan="3" class="text-center km-muted">无数据</td></tr>');
                }

                // 边类型分布
                var $et = $('#edgeTypeBody').empty();
                var $etChart = $('#edgeTypeChart');
                var edgeTypeNames = {
                    'own': '所属关系', 'cg': '调用图', 'dfg': '数据流', 'use': '使用',
                    'frg': '文件引用', 'control': '控制流', 'unknown': '未知'
                };
                var edgeTypeColors = {
                    'own': '#3498db', 'cg': '#e67e22', 'dfg': '#e74c3c', 'use': '#2ecc71',
                    'frg': '#9b59b6', 'control': '#f39c12', 'unknown': '#95a5a6'
                };
                if (d.edge_type_summary) {
                    var maxEdge = 0;
                    $.each(d.edge_type_summary, function(t, c) { if (c > maxEdge) maxEdge = c; });
                    var etChartHtml = '<div class="gp-legend-bar">';
                    $.each(d.edge_type_summary, function(t, c) {
                        var pct = maxEdge > 0 ? (c / maxEdge * 100) : 0;
                        etChartHtml += '<div style="width:' + pct + '%;background:' + (edgeTypeColors[t] || '#999') + ';" title="' + escHtml(t) + ': ' + c + '"></div>';
                    });
                    etChartHtml += '</div>';
                    $etChart.html(etChartHtml);

                    $.each(d.edge_type_summary, function(t, c) {
                        var pct = maxEdge > 0 ? (c / maxEdge * 100) : 0;
                        var color = edgeTypeColors[t] || '#999';
                        $et.append('<tr><td><span class="gp-legend-dot" style="background:' + color + ';"></span><code>' + escHtml(t) + '</code></td><td class="gp-ta-r">' + c + '</td><td class="km-muted">' + escHtml(edgeTypeNames[t] || t) + '</td><td><div class="gp-bar-track"><div style="height:100%;width:' + pct + '%;background:' + color + ';border-radius:2px;"></div></div></td></tr>');
                    });
                } else {
                    $etChart.html('');
                    $et.append('<tr><td colspan="4" class="text-center km-muted">无数据</td></tr>');
                }
            },
            error: function () {
                $btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> 加载概览');
                $('#labelSummaryBody').html('<tr><td colspan="2" class="text-center text-danger">请求失败</td></tr>');
            }
        });
    }

    // 文件列表中的链接点击 -> 跳到文件查询 Tab

    function renderFileList($fl, files, cap) {
        $fl.empty();
        if (!files || files.length === 0) {
            $fl.append('<tr><td colspan="4" class="text-center km-muted">无匹配</td></tr>');
            return;
        }
        var rows = [];
        var n = Math.min(files.length, cap || 80);
        for (var i = 0; i < n; i++) {
            var f = files[i];
            var fp = f.path || f.name || '';
            rows.push('<tr><td><a href="#" class="file-link" data-path="' + escHtml(fp) + '">' + escHtml(fp || '-') + '</a></td>'
                + '<td>' + escHtml(f.language || '-') + '</td>'
                + '<td class="gp-ta-r">' + (f.node_count || 0) + '</td>'
                + '<td class="gp-cell-w70r"><button type="button" class="btn btn-default btn-sm file-graph-btn" data-path="' + escHtml(fp) + '" title="在图可视化中打开该文件的子图"><i class="fa fa-project-diagram"></i> 图</button></td></tr>');
        }
        $fl.append(rows.join(''));
    }

    $(document).on('click', '.file-graph-btn', function (e) {
        e.preventDefault();
        var path = $(this).data('path');
        selectedFilePath = path;
        // 切到图可视化 tab 并直接加载该文件子图
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $('.tab-btn[data-tab="tab-graph"]').removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#tab-graph').show();
        loadFileGraph(currentScanId, path);
    });

    $(document).on('click', '.file-link', function (e) {
        e.preventDefault();
        var path = $(this).data('path');
        $('#fileQueryInput').val(path);
        selectedFilePath = path;
        // 切换到文件 Tab
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $('.tab-btn[data-tab="tab-file"]').removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#tab-file').show();
        queryFile(currentScanId, path);
    });

    // ===== Tab 2: 文件查询 =====
    $('#btnQueryFile').on('click', function () {
        var filePath = $('#fileQueryInput').val().trim();
        if (!filePath) { alert('请输入文件路径'); return; }
        queryFile(currentScanId, filePath);
    });

    $('#fileQueryInput').on('keypress', function (e) {
        if (e.which === 13) { $('#btnQueryFile').click(); }
    });

    function queryFile(scanId, filePath) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        requireGraph(function() { _doQueryFile(scanId, filePath); });
    }
    function _doQueryFile(scanId, filePath) {
        $('#fileResultArea').hide();
        $('#fileErrorArea').hide();

        $.ajax({
            url: '/api/graph/query',
            type: 'GET',
            data: { scan_id: scanId, query_type: 'file', query_arg: filePath },
            dataType: 'json',
            success: function (resp) {
                if (resp.code !== 200 || !resp.data) {
                    $('#fileErrorArea').show();
                    $('#fileErrorMsg').text(resp.msg || '查询失败，无返回数据');
                    return;
                }
                var d = resp.data;
                $('#fileResultArea').show();

                // Classes
                if (d.classes && d.classes.length > 0) {
                    $('#fileClassesBox').show();
                    var $tb = $('#fileClassesBody').empty();
                    $.each(d.classes, function (i, c) {
                        var vid = c.vid || c.id;
                        var viewBtn = vid != null ? ' <button type="button" class="btn btn-default btn-sm btn-view-graph" data-vid="' + vid + '" title="在图可视化中查看"><i class="fa fa-project-diagram"></i></button>' : '';
                        $tb.append('<tr><td>' + escHtml(c.name || c) + viewBtn + '</td><td>' + (c.lineno || '-') + '</td></tr>');
                    });
                } else { $('#fileClassesBox').hide(); }

                // Functions
                if (d.functions && d.functions.length > 0) {
                    $('#fileFunctionsBox').show();
                    var $tb = $('#fileFunctionsBody').empty();
                    $.each(d.functions, function (i, f) {
                        var vid = f.vid || f.id;
                        var viewBtn = vid != null ? ' <button type="button" class="btn btn-default btn-sm btn-view-graph" data-vid="' + vid + '" title="在图可视化中查看"><i class="fa fa-project-diagram"></i></button>' : '';
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(f.name || f) + '">' + escHtml(f.name || f) + '</a>' + viewBtn + '</td><td>' + (f.lineno || '-') + '</td></tr>');
                    });
                } else { $('#fileFunctionsBox').hide(); }

                // Imports
                if (d.imports && d.imports.length > 0) {
                    $('#fileImportsBox').show();
                    var $tb = $('#fileImportsBody').empty();
                    $.each(d.imports, function (i, imp) {
                        $tb.append('<tr><td>' + escHtml(typeof imp === 'string' ? imp : (imp.name || imp.module || JSON.stringify(imp))) + '</td><td>' + (imp.lineno || '-') + '</td></tr>');
                    });
                } else { $('#fileImportsBox').hide(); }

                // Operators
                if (d.operators && d.operators.length > 0) {
                    $('#fileOperatorsBox').show();
                    $('#fileBranchCount').text(d.branch_count || '-');
                    var $tb = $('#fileOperatorsBody').empty();
                    $.each(d.operators, function (i, op) {
                        $tb.append('<tr><td>' + escHtml(typeof op === 'string' ? op : (op.name || op.type || JSON.stringify(op))) + '</td><td>' + (op.lineno || '-') + '</td></tr>');
                    });
                } else { $('#fileOperatorsBox').hide(); }
            },
            error: function (xhr) {
                $('#fileErrorArea').show();
                $('#fileErrorMsg').text('请求失败: ' + (xhr.statusText || '网络错误'));
            }
        });
    }

    // 函数列表中的链接点击 -> 跳到函数查询 Tab
    $(document).on('click', '.func-link', function (e) {
        e.preventDefault();
        var name = $(this).data('name');
        $('#funcQueryInput').val(name);
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $('.tab-btn[data-tab="tab-function"]').removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#tab-function').show();
        queryFunction(currentScanId, name);
    });

    // "查看子图" 按钮 -> 跳到图可视化 Tab 并加载
    $(document).on('click', '.btn-view-graph', function () {
        var vid = $(this).data('vid');
        if (vid == null) return;
        $('#graphVidInput').val(vid);
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $('.tab-btn[data-tab="tab-graph"]').removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#tab-graph').show();
        // 触发子图加载
        $('#btnLoadSubgraph').click();
    });

    // ===== Tab 3: 函数查询 =====
    $('#btnQueryFunc').on('click', function () {
        var funcName = $('#funcQueryInput').val().trim();
        if (!funcName) { alert('请输入函数名称'); return; }
        queryFunction(currentScanId, funcName);
    });

    $('#funcQueryInput').on('keypress', function (e) {
        if (e.which === 13) { $('#btnQueryFunc').click(); }
    });

    function queryFunction(scanId, funcName) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        requireGraph(function() { _doQueryFunction(scanId, funcName); });
    }
    function _doQueryFunction(scanId, funcName) {
        $('#funcResultArea').hide();
        $('#funcErrorArea').hide();

        $.ajax({
            url: '/api/graph/query',
            type: 'GET',
            data: { scan_id: scanId, query_type: 'function', query_arg: funcName },
            dataType: 'json',
            success: function (resp) {
                if (resp.code !== 200 || !resp.data) {
                    $('#funcErrorArea').show();
                    $('#funcErrorMsg').text(resp.msg || '查询失败，无返回数据');
                    return;
                }
                var d = resp.data;
                $('#funcResultArea').show();

                // 基本信息
                $('#funcName').text(d.name || '-');
                $('#funcFullname').text(d.fullname || '-');
                $('#funcLineno').text(d.lineno || '-');
                $('#funcFilepath').text(d.file_path || '-');
                $('#funcTaintType').text(d.taint_type || '-');

                // 参数列表
                if (d.params && d.params.length > 0) {
                    $('#funcParamsBox').show();
                    var $ul = $('#funcParamsList').empty();
                    $.each(d.params, function (i, p) {
                        $ul.append('<li><code>' + escHtml(typeof p === 'string' ? p : (p.name || JSON.stringify(p))) + '</code></li>');
                    });
                } else { $('#funcParamsBox').hide(); }

                // Return Nodes
                if (d.return_nodes && d.return_nodes.length > 0) {
                    $('#funcReturnBox').show();
                    var $ul = $('#funcReturnList').empty();
                    $.each(d.return_nodes, function (i, r) {
                        $ul.append('<li><code>' + escHtml(typeof r === 'string' ? r : (r.name || JSON.stringify(r))) + '</code></li>');
                    });
                } else { $('#funcReturnBox').hide(); }

                // Callers
                if (d.callers && d.callers.length > 0) {
                    $('#funcCallersBox').show();
                    var $tb = $('#funcCallersBody').empty();
                    $.each(d.callers, function (i, c) {
                        var vid = c.vid;
                        var viewBtn = vid != null ? ' <button type="button" class="btn btn-default btn-sm btn-view-graph" data-vid="' + vid + '" title="在图可视化中查看"><i class="fa fa-project-diagram"></i></button>' : '';
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(c.name || c) + '">' + escHtml(c.name || c) + '</a>' + viewBtn + '</td><td>' + (c.lineno || '-') + '</td><td>' + escHtml(c.file_path || '-') + '</td></tr>');
                    });
                } else { $('#funcCallersBox').hide(); }

                // Callees
                if (d.callees && d.callees.length > 0) {
                    $('#funcCalleesBox').show();
                    var $tb = $('#funcCalleesBody').empty();
                    $.each(d.callees, function (i, c) {
                        var vid = c.vid;
                        var viewBtn = vid != null ? ' <button type="button" class="btn btn-default btn-sm btn-view-graph" data-vid="' + vid + '" title="在图可视化中查看"><i class="fa fa-project-diagram"></i></button>' : '';
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(c.name || c) + '">' + escHtml(c.name || c) + '</a>' + viewBtn + '</td><td>' + (c.lineno || '-') + '</td><td>' + escHtml(c.file_path || '-') + '</td></tr>');
                    });
                } else { $('#funcCalleesBox').hide(); }

                // 自动加载调用关系图
                if (d.name && !d.error) { loadCallGraph(scanId, funcName, 'both'); }
            },
            error: function (xhr) {
                $('#funcErrorArea').show();
                $('#funcErrorMsg').text('请求失败: ' + (xhr.statusText || '网络错误'));
            }
        });
    }

    // ===== 调用关系图 =====
    $('#btnCallGraphBoth').on('click', function () { loadCallGraph(currentScanId, $('#funcQueryInput').val().trim(), 'both'); });
    $('#btnCallGraphIn').on('click', function () { loadCallGraph(currentScanId, $('#funcQueryInput').val().trim(), 'in'); });
    $('#btnCallGraphOut').on('click', function () { loadCallGraph(currentScanId, $('#funcQueryInput').val().trim(), 'out'); });

    function loadCallGraph(scanId, funcName, direction) {
        if (!scanId || !funcName) return;
        var $row = $('#funcCallGraphRow');
        $row.show();
        var $container = $('#funcCallGraphContainer');
        $container.html('<div class="gp-empty">加载调用图...</div>');
        $.ajax({
            url: '/api/graph/query',
            data: { scan_id: scanId, query_type: 'call_graph', query_arg: funcName, direction: direction || 'both', depth: 2 },
            dataType: 'json',
            success: function (resp) {
                if (resp.code !== 200 || !resp.data || resp.data.error) {
                    $container.html('<div class="gp-empty">' + escHtml(resp.data ? resp.data.error : '无数据') + '</div>');
                    return;
                }
                renderCallGraph($container[0], resp.data);
            },
            error: function () { $container.html('<div class="gp-err-state">请求失败</div>'); }
        });
    }

    function renderCallGraph(container, data) {
        var nodes = data.nodes || [];
        var edges = data.edges || [];
        if (nodes.length === 0) {
            container.innerHTML = '<div class="gp-empty">无节点数据</div>';
            return;
        }
        var cyNodes = [];
        var cyEdges = [];
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            var bg = n.label === 'function' ? '#2ecc71' : '#95a5a6';
            var shape = n.label === 'function' ? 'roundrectangle' : 'ellipse';
            var borderW = (data.center_vid && n.data.id == data.center_vid) ? 3 : 1;
            cyNodes.push({ data: { id: n.data.id, label: n.data.label || n.data.name || '', name: n.data.name || '', _label: n.label || '' }, style: { 'background-color': bg, 'label': n.data.name || '', 'shape': shape, 'border-width': borderW, 'border-color': '#fff', 'color': '#fff', 'text-valign': 'center', 'font-size': 11, 'width': 60, 'height': 30 }, position: { x: 0, y: 0 } });
        }
        for (var i = 0; i < edges.length; i++) {
            var e = edges[i];
            cyEdges.push({ data: { source: e.data.source, target: e.data.target, label: e.data.label || '' }, style: { 'line-color': '#2ecc71', 'target-arrow-color': '#2ecc71', 'width': 2, 'curve-style': 'bezier' }, classes: '' });
        }
        cytoscape({ container: container, elements: { nodes: cyNodes, edges: cyEdges }, style: [], layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.5 } });
    }

    // ===== Tab 4: 污点追踪 =====
    $('#btnTrace').on('click', function () {
        var fileLine = $('#traceInput').val().trim();
        if (!fileLine) { alert('请输入 file:line'); return; }
        traceLine(currentScanId, fileLine);
    });

    $('#traceInput').on('keypress', function (e) {
        if (e.which === 13) { $('#btnTrace').click(); }
    });

    function traceLine(scanId, fileLine) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        requireGraph(function() { _doTraceLine(scanId, fileLine); });
    }
    function _doTraceLine(scanId, fileLine) {
        $('#traceResultArea').html('<div class="text-center km-muted gp-pad20"><i class="fa fa-spinner fa-spin"></i> 加载中...</div>');
        $('#traceErrorArea').hide();

        $.ajax({
            url: '/api/graph/query',
            type: 'GET',
            data: { scan_id: scanId, query_type: 'trace', query_arg: fileLine },
            dataType: 'json',
            success: function (resp) {
                if (resp.code !== 200 || !resp.data) {
                    $('#traceErrorArea').show();
                    $('#traceErrorMsg').text(resp.msg || '追踪失败，无返回数据');
                    $('#traceResultArea').empty();
                    return;
                }
                renderTraceResults(resp.data);
            },
            error: function (xhr) {
                $('#traceErrorArea').show();
                $('#traceErrorMsg').text('请求失败: ' + (xhr.statusText || '网络错误'));
                $('#traceResultArea').empty();
            }
        });
    }

    function renderTraceResults(data) {
        var $container = $('#traceResultArea').empty();
        if (!data || data.length === 0) {
            $container.html('<div class="card"><div class="box-body text-center km-muted">无追踪结果</div></div>');
            return;
        }

        $.each(data, function (idx, item) {
            var sink = item.sink || {};
            var result = item.result || {};
            var chain = result.chain || [];

            // 结果状态样式
            var resultCode = result.code;
            var statusClass = resultCode === 0 ? 'label-success' : (resultCode === 1 ? 'label-danger' : 'label-warning');
            var statusText = resultCode === 0 ? '安全' : (resultCode === 1 ? '危险' : '未知');

            var html = '<div class="row"><div class="col-12"><div class="card">';
            html += '<div class="card-header d-flex align-items-center justify-content-between"><h3 class="card-title">Sink #' + (idx + 1) + ': ' + escHtml(sink.name || '-') + '</h3></div>';
            html += '<div class="card-body">';

            // Sink 信息
            html += '<table class="table km-table gp-mb10">';
            html += '<tr><td class="km-muted gp-w80">名称</td><td>' + escHtml(sink.name || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">行号</td><td>' + (sink.lineno || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">类型</td><td>' + escHtml(sink.type || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">参数索引</td><td>' + (item.arg_index != null ? item.arg_index : '-') + '</td></tr>';
            html += '</table>';

            // Result
            html += '<div class="gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10 gp-mb10">';
            html += '<span class="label ' + statusClass + '">' + statusText + '</span> ';
            html += '<strong>code:</strong> ' + (resultCode != null ? resultCode : '-') + '&nbsp;&nbsp;';
            if (result.reason) html += '<strong>原因:</strong> ' + escHtml(result.reason);
            if (result.description) html += '<br><strong>描述:</strong> ' + escHtml(result.description);
            html += '</div>';

            // Chain
            if (chain.length > 0) {
                html += '<h4>追踪链</h4>';
                html += '<div class="row"><div class="col-12 col-md-6">';
                html += '<div class="gp-quote-block">';
                $.each(chain, function (ci, step) {
                    html += '<div class="gp-card-mb">';
                    html += '<div><strong>Step ' + (ci + 1) + '</strong>';
                    if (step.type) html += ' <span class="badge bg-info">' + escHtml(step.type) + '</span>';
                    html += '</div>';
                    if (step.name) html += '<div>名称: <code>' + escHtml(step.name) + '</code></div>';
                    if (step.path || step.file_path) html += '<div>路径: ' + escHtml(step.path || step.file_path) + '</div>';
                    if (step.lineno) html += '<div>行号: ' + step.lineno + '</div>';
                    html += '</div>';
                });
                html += '</div></div>';
                // 迷你链路图容器
                var traceVids = [];
                $.each(chain, function(ci, step) {
                    if (step.vid != null) traceVids.push(step.vid);
                });
                if (traceVids.length > 1) {
                    html += '<div class="col-12 col-md-6"><div class="km-chain-graph-container" style="display:block;" id="traceGraph_' + idx + '">';
                    html += '<div class="km-chain-graph-placeholder">加载中...</div>';
                    html += '</div></div>';
                }
                html += '</div>';
            }

            html += '</div></div></div></div>';
            $container.append(html);
        });

        // 异步加载每个 trace 的链路图
        if (currentScanId) {
            data.forEach(function (item, idx) {
                var chain = (item.result || {}).chain || [];
                var traceVids = [];
                chain.forEach(function (step) { if (step.vid != null) traceVids.push(step.vid); });
                if (traceVids.length > 1) {
                    (function (traceIdx, vids) {
                        var containerId = 'traceGraph_' + traceIdx;
                        var $gc = $('#' + containerId);
                        if (!$gc.length) return;
                        $.ajax({
                            url: '/api/graph/chain_subgraph',
                            data: { scan_id: currentScanId, vids: vids.join(',') },
                            dataType: 'json',
                            success: function (resp) {
                                if (resp.code === 200 && resp.data && resp.data.nodes && resp.data.nodes.length > 0) {
                                    renderChainMiniGraph(containerId, resp.data);
                                } else {
                                    $gc.html('<div class="km-chain-graph-placeholder">无图数据</div>');
                                }
                            },
                            error: function () {
                                $gc.html('<div class="km-chain-graph-placeholder">加载失败</div>');
                            }
                        });
                    })(idx, traceVids);
                }
            });
        }
    }

    // 渲染链路迷你图（复用于 task_detail 和 graph_analysis trace）
    function renderChainMiniGraph(containerId, data) {
        var container = document.getElementById(containerId);
        if (!container) return;

        // 销毁旧实例
        if (container._cyreg && container._cyreg.cy) {
            try { container._cyreg.cy.destroy(); } catch(e) {}
            container._cyreg = null;
        }
        // 清除占位
        var ph = container.querySelector('.km-chain-graph-placeholder');
        if (ph) ph.remove();

        var nodes = data.nodes || [];
        var edges = data.edges || [];

        var colorMap = {
            'file': '#3498db', 'function': '#2ecc71', 'class': '#9b59b6',
            'operator': '#e67e22', 'identifier': '#95a5a6', 'branch': '#e74c3c',
            'parameter': '#1abc9c', 'return': '#3498db', 'import': '#f1c40f'
        };
        var edgeColorMap = {
            'dfg': '#f44336', 'use': '#4CAF50', 'cg': '#2196F3',
            'own': '#555', 'member': '#795548', 'control': '#FF9800'
        };

        var cyNodes = [];
        var cyEdges = [];
        nodes.forEach(function (nd) {
            var c = colorMap[nd.label] || '#95a5a6';
            cyNodes.push({
                data: {
                    id: 'n' + nd.id, label: nd.name || nd.label || ('v' + nd.id),
                    nodeLabel: nd.label, color: c
                }
            });
        });
        edges.forEach(function (ed) {
            var ec = edgeColorMap[ed.label] || '#666';
            cyEdges.push({
                data: {
                    id: 'e' + ed.source + '_' + ed.target,
                    source: 'n' + ed.source, target: 'n' + ed.target,
                    label: ed.label, color: ec
                }
            });
        });

        var cy = cytoscape({
            container: container,
            elements: [].concat(cyNodes, cyEdges),
            style: [
                { selector: 'node', style: { 'label': 'data(label)', 'text-valign': 'center', 'text-halign': 'center', 'font-size': '10px', 'color': '#fff', 'text-outline-width': 2, 'text-outline-color': '#333', 'background-color': 'data(color)', 'width': 24, 'height': 24 } },
                { selector: 'edge', style: { 'width': 1.5, 'line-color': 'data(color)', 'target-arrow-shape': 'triangle', 'target-arrow-color': 'data(color)', 'curve-style': 'bezier', 'arrow-scale': 0.8 } }
            ],
            layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.2 },
            userZoomingEnabled: true, userPanningEnabled: true,
            boxSelectionEnabled: false,
            minZoom: 0.3, maxZoom: 3
        });
        container._cyreg = { cy: cy };
    }

    // ===== 工具函数 =====
    function escHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ===== 变量追踪 =====
    $('#btnTraceVar').on('click', function () {
        var varName = $('#varTraceInput').val().trim();
        if (!varName) { alert('请输入变量名'); return; }
        traceVariable(currentScanId, varName);
    });
    $('#varTraceInput').on('keypress', function (e) {
        if (e.which === 13) { $('#btnTraceVar').click(); }
    });

    function traceVariable(scanId, varName) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        requireGraph(function() { _doTraceVariable(scanId, varName); });
    }
    function _doTraceVariable(scanId, varName) {
        var $r = $('#varTraceResult');
        $r.html('<div class="text-center km-muted gp-pad20">追踪中...</div>');
        $.ajax({
            url: '/api/graph/query',
            data: { scan_id: scanId, query_type: 'trace_variable', query_arg: varName },
            dataType: 'json',
            success: function (resp) {
                if (resp.code !== 200 || !resp.data) {
                    $r.html('<div class="text-center text-danger gp-pad20">追踪失败</div>');
                    return;
                }
                var d = resp.data;
                if (d.total_seeds === 0) {
                    $r.html('<div class="text-center km-muted gp-pad20">未找到匹配的变量节点</div>');
                    return;
                }
                var html = '<div class="row"><div class="col-12"><div class="card"><div class="card-header d-flex align-items-center justify-content-between"><h3 class="card-title">找到 ' + d.total_seeds + ' 个匹配节点</h3></div><div class="box-body table-responsive"><table class="table table-hover km-table"><thead><tr><th>变量名</th><th>文件</th><th>行号</th><th></th></tr></thead><tbody>';
                $.each(d.seed_nodes, function (i, s) {
                    var viewBtn = ' <button type="button" class="btn btn-default btn-sm btn-view-graph" data-vid="' + s.vid + '" title="在图可视化中查看"><i class="fa fa-project-diagram"></i></button>';
                    html += '<tr><td><code>' + escHtml(s.name) + '</code></td><td>' + escHtml(s.file_path || '-') + '</td><td>' + s.lineno + '</td><td>' + viewBtn + '</td></tr>';
                });
                html += '</tbody></table></div></div></div></div>';
                if (d.subgraph && d.subgraph.nodes && d.subgraph.nodes.length > 0) {
                    html += '<div class="row gp-mt10"><div class="col-12"><div class="card"><div class="card-header d-flex align-items-center justify-content-between"><h3 class="card-title">数据流传播图（' + d.subgraph.total_nodes + ' 节点, ' + d.subgraph.total_edges + ' 边）</h3></div><div class="card-body"><div id="varTraceGraphContainer" class="gp-canvas-dark"></div></div></div></div></div>';
                }
                $r.html(html);
                if (d.subgraph && d.subgraph.nodes && d.subgraph.nodes.length > 0) {
                    setTimeout(function () {
                        var $gc = $('#varTraceGraphContainer');
                        if ($gc.length) { renderVarTraceGraph($gc[0], d.subgraph, d.seed_nodes); }
                    }, 100);
                }
            },
            error: function () { $r.html('<div class="text-center text-danger gp-pad20">请求失败</div>'); }
        });
    }

    function renderVarTraceGraph(container, subgraph, seedNodes) {
        var nodes = subgraph.nodes || [];
        var edges = subgraph.edges || [];
        if (nodes.length === 0) return;
        var seedSet = {};
        $.each(seedNodes || [], function (i, s) { seedSet[s.vid] = true; });
        var cyNodes = [];
        var cyEdges = [];
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            var bg = seedSet[n.data.id] ? '#e74c3c' : (nodeColorMap[n.label] || '#95a5a6');
            var borderW = seedSet[n.data.id] ? 3 : 1;
            cyNodes.push({
                data: { id: n.data.id, label: n.data.name || '', _label: n.label || '' },
                style: { 'background-color': bg, 'label': n.data.name || '', 'shape': 'ellipse', 'border-width': borderW, 'border-color': '#fff', 'color': '#fff', 'text-valign': 'center', 'font-size': 10, 'width': 40, 'height': 25 },
                position: { x: 0, y: 0 }
            });
        }
        for (var i = 0; i < edges.length; i++) {
            var e = edges[i];
            var eLabel = e.data.label || '';
            var lineColor = (eLabel === 'dfg') ? '#e74c3c' : (eLabel === 'use' ? '#2ecc71' : '#555');
            cyEdges.push({
                data: { source: e.data.source, target: e.data.target, label: eLabel },
                style: { 'line-color': lineColor, 'target-arrow-color': lineColor, 'width': 2, 'curve-style': 'bezier' }
            });
        }
        cytoscape({ container: container, elements: { nodes: cyNodes, edges: cyEdges }, style: [], layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.2 } });
    }

    // ===== Tab 5: 图可视化 =====
    var cy = null;  // Cytoscape instance
    var graphElements = null;  // raw elements from API (for filtering)
    var nodeColorMap = {
        'file': '#3498db', 'class': '#9b59b6', 'function': '#2ecc71',
        'operator': '#e67e22', 'parameter': '#1abc9c', 'identifier': '#95a5a6',
        'branch': '#e74c3c', 'import': '#f1c40f', 'const': '#ecf0f1',
        'return': '#3498db', 'annotation': '#e91e63', 'dependency': '#ff9800'
    };
    var edgeColorMap = {
        'own': '#555', 'cg': '#2196F3', 'dfg': '#f44336', 'use': '#4CAF50',
        'ast': '#FF9800', 'frg': '#9C27B0', 'crg': '#00BCD4',
        'member': '#795548', 'alias': '#607D8B'
    };

    function initCytoscape() {
        if (cy) { cy.destroy(); cy = null; }
        cy = cytoscape({
            container: document.getElementById('cyGraphContainer'),
            elements: [],
            style: [
                { selector: 'node', style: {
                    'label': 'data(name)',
                    'text-valign': 'center', 'text-halign': 'center',
                    'font-size': '10px', 'color': '#fff',
                    'text-outline-width': 2, 'text-outline-color': '#000',
                    'background-color': '#999', 'width': 30, 'height': 30,
                    'text-max-width': '80px', 'text-wrap': 'wrap'
                }},
                { selector: 'node[file]', style: { 'shape': 'rectangle', 'width': 50, 'height': 30, 'font-size': '11px', 'font-weight': 'bold' }},
                { selector: 'node[class]', style: { 'shape': 'diamond', 'width': 35, 'height': 35 }},
                { selector: 'node[function]', style: { 'shape': 'round-rectangle', 'width': 45, 'height': 25, 'font-size': '11px' }},
                { selector: 'node[operator]', style: { 'shape': 'round-rectangle', 'width': 35, 'height': 22, 'font-size': '9px' }},
                { selector: 'node[sink]', style: { 'border-width': 3, 'border-color': '#ff0000' }},
                { selector: 'node[taint="source"]', style: { 'border-width': 3, 'border-color': '#ffeb3b' }},
                { selector: '.highlighted', style: { 'border-width': 4, 'border-color': '#ffeb3b' }},
                { selector: 'edge', style: {
                    'width': 2, 'line-color': '#666',
                    'target-arrow-shape': 'triangle', 'target-arrow-color': '#666',
                    'curve-style': 'bezier', 'arrow-scale': 0.8,
                    'label': 'data(label)', 'font-size': '8px', 'color': '#aaa',
                    'text-rotation': 'autorotate', 'text-background-color': '#1a1a2e',
                    'text-background-opacity': 0.8, 'text-background-padding': '2px'
                }},
                { selector: 'edge[cg]', style: { 'line-color': '#2196F3', 'target-arrow-color': '#2196F3' }},
                { selector: 'edge[dfg]', style: { 'line-color': '#f44336', 'target-arrow-color': '#f44336', 'width': 3, 'line-style': 'dashed' }},
                { selector: 'edge[use]', style: { 'line-color': '#4CAF50', 'target-arrow-color': '#4CAF50' }},
            ],
            layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.5 },
            // user zooming/panning
            userZoomingEnabled: true, userPanningEnabled: true,
            boxSelectionEnabled: false,
            autoungrabify: false
        });

        // Click node -> show detail + highlight
        cy.on('tap', 'node', function(e) {
            var node = e.target;
            showNodeDetail(node.data());
        });

        // Double-click node -> expand
        cy.on('dbltap', 'node', function(e) {
            var node = e.target;
            var vid = node.data().id;
            $('#graphVidInput').val(vid);
            loadSubgraph(currentScanId, vid);
        });
    }

    function applyNodeStyles(elements) {
        // Set color based on label, set boolean type attr for selectors, mark sinks/taint
        var nodeElements = [];
        var edgeElements = [];
        for (var i = 0; i < elements.length; i++) {
            var el = elements[i];
            if (el.data.source !== undefined) {
                // edge — store display text in data.label, set boolean attr for selector
                var edgeData = Object.assign({}, el.data);
                var elbl = edgeData.edgeLabel || edgeData.label || '';
                edgeData.label = elbl;            // display text on edge
                edgeData.edgeType = elbl;         // preserve original
                if (elbl) edgeData[elbl] = true;  // e.g. edgeData.cg = true for selector
                edgeElements.push({ data: edgeData });
            } else {
                // node
                var nodeData = Object.assign({}, el.data);
                var nlbl = nodeData.label || '';
                nodeData.color = nodeColorMap[nlbl] || '#999';
                if (nlbl) nodeData[nlbl] = true;   // e.g. nodeData.file = true for selector
                // Mark sinks (operators with known sink names)
                var sinkNames = ['system','exec','passthru','shell_exec','eval','assert',
                    'echo','print','printf','file_put_contents','fopen','unlink',
                    'mysqli_query','curl_exec','include','require','subprocess.run','HttpResponse'];
                if (nlbl === 'operator' && sinkNames.indexOf(nodeData.name) >= 0) {
                    nodeData.sink = true;
                }
                // Mark taint sources
                if (nodeData.taint_type === 'source') {
                    nodeData.taint = 'source';
                }
                nodeElements.push({ data: nodeData });
            }
        }
        return nodeElements.concat(edgeElements);
    }

    function renderGraph(apiData) {
        if (!apiData || !apiData.nodes) return;
        $('#graphStats').text(
            apiData.total_nodes + ' nodes, ' + apiData.total_edges + ' edges'
        );
        // Convert API format to Cytoscape elements
        var elements = [];
        for (var i = 0; i < apiData.nodes.length; i++) {
            var n = apiData.nodes[i];
            elements.push({
                data: {
                    id: String(n.id), label: n.label, name: n.name || n.id,
                    type: n.type, file_path: n.file_path, lineno: n.lineno,
                    taint_type: n.taint_type
                }
            });
        }
        for (var i = 0; i < apiData.edges.length; i++) {
            var e = apiData.edges[i];
            elements.push({
                data: {
                    id: 'e' + e.source + '_' + e.target,
                    source: String(e.source), target: String(e.target),
                    edgeLabel: e.label, label: e.label, type: e.type
                }
            });
        }

        graphElements = elements;
        var styled = applyNodeStyles(elements);
        cy.elements().remove();
        cy.add(styled);
        var layoutName = $('#graphLayoutSelect').val();
        var nNodes = apiData.nodes.length;
        if (nNodes > 250) {
            // 大图布局是浏览器卡顿主因：>250 节点自动切 grid（快一个量级），可手动换回
            layoutName = 'grid';
        }
        var t0 = Date.now();
        cy.layout({ name: layoutName, directed: true, spacingFactor: 1.2, animate: nNodes <= 250, animationDuration: 500 }).run();
        cy.fit(undefined, 50);
        if (nNodes > 250) {
            $('#graphStats').text(apiData.total_nodes + ' nodes, ' + apiData.total_edges + ' edges（大图已自动切换快速布局，可在布局下拉换回）');
        }
    }

    function showNodeDetail(data) {
        var html = '<table class="table km-table" style="margin-bottom:0; font-size:12px;">';
        html += '<tr><td class="km-muted gp-w60">VID</td><td><code>' + escHtml(data.id) + '</code></td></tr>';
        html += '<tr><td class="km-muted">Label</td><td><span style="display:inline-block;width:12px;height:12px;border-radius:3px;background:' + (nodeColorMap[data.label] || '#999') + ';vertical-align:middle;margin-right:5px;"></span>' + escHtml(data.label) + '</td></tr>';
        if (data.name) html += '<tr><td class="km-muted">Name</td><td><code>' + escHtml(data.name) + '</code></td></tr>';
        if (data.type) html += '<tr><td class="km-muted">Type</td><td><code>' + escHtml(data.type) + '</code></td></tr>';
        if (data.file_path) html += '<tr><td class="km-muted">File</td><td class="gp-break-all">' + escHtml(data.file_path) + '</td></tr>';
        if (data.lineno) html += '<tr><td class="km-muted">Line</td><td>' + data.lineno + '</td></tr>';
        if (data.taint_type) html += '<tr><td class="km-muted">Taint</td><td><span class="badge bg-' + (data.taint_type === 'source' ? 'warning' : 'info') + '">' + escHtml(data.taint_type) + '</span></td></tr>';
        html += '</table>';

        // Action buttons
        html += '<div class="gp-mt10">';
        html += '<button class="btn btn-primary btn-sm" onclick="loadSubgraph(currentScanId(), ' + data.id + ')"><i class="fa fa-expand"></i> 展开此节点</button> ';
        if (data.file_path) {
            html += '<button class="btn btn-default btn-sm" onclick="loadFileGraph(currentScanId(), \'' + escHtml(data.file_path).replace(/'/g, "\\'") + '\')"><i class="fa fa-file-code-o"></i> 查看文件</button>';
        }
        if (data.file_path && data.lineno) {
            html += ' <a href="#" class="btn btn-default btn-sm" title="在源码浏览器中查看" onclick="event.preventDefault(); openFileBrowse(' + data.id + ',\'' + escHtml(data.file_path).replace(/'/g, "\\'") + '\',' + data.lineno + ')"><i class="fa fa-external-link"></i> 源码</a>';
        }
        html += '<button class="btn btn-default btn-sm" onclick="loadNodeSource(currentScanId, ' + data.id + ')" title="查看此节点的源码上下文"><i class="fa fa-code"></i> 查看源码</button>';
        html += '</div>';

        $('#nodeDetailContent').html(html);

        // 异步加载关联漏洞
        var vid = parseInt(data.id);
        var sid = currentScanId;
        if (sid && !isNaN(vid)) {
            // 异步加载源码上下文
            if (data.file_path && data.lineno) {
                $('#nodeDetailContent').append('<div id="nodeSourceArea" class="gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10 gp-mt10"><span class="km-muted gp-fs11">加载源码...</span></div>');
                loadNodeSource(sid, vid);
            }
            $('#nodeDetailContent').append('<div id="nodeVulnsArea" style="margin-top:10px;"><span class="km-muted gp-fs11">加载关联漏洞...</span></div>');
            $.ajax({
                url: '/api/graph/node_vulns',
                data: { scan_id: sid, vid: vid },
                dataType: 'json',
                success: function (resp) {
                    var $va = $('#nodeVulnsArea');
                    if (!resp.data || resp.data.length === 0) {
                        $va.html('<div class="gp-muted-sm">无关联漏洞</div>');
                        return;
                    }
                    var vulnHtml = '<div class="gp-kb-title-red"><i class="fa fa-bug"></i> 关联漏洞 (' + resp.data.length + ')</div>';
                    vulnHtml += '<table class="table km-table gp-kb-sub-end">';
                    $.each(resp.data, function (i, v) {
                        vulnHtml += '<tr><td><code>' + escHtml(v.node_content || '-') + '</code></td>';
                        vulnHtml += '<td>' + escHtml(v.node_type || '-') + '</td>';
                        var loc = '';
                        if (v.node_path) loc += v.node_path.split('/').pop();
                        if (v.node_lineno) loc += ':' + v.node_lineno;
                        vulnHtml += '<td>' + escHtml(loc || '-') + '</td></tr>';
                    });
                    vulnHtml += '</table>';
                    $va.html(vulnHtml);
                },
                error: function () {
                    $('#nodeVulnsArea').html('<div class="gp-muted-sm">加载失败</div>');
                }
            });
        }
    }

    function loadNodeSource(scanId, vid) {
        var $sa = $('#nodeSourceArea');
        if (!$sa.length) {
            // 如果源码区域不存在，追加到节点详情面板末尾
            $('#nodeDetailContent').append('<div id="nodeSourceArea" style="margin-top:10px;"><span class="km-muted gp-fs11">加载源码...</span></div>');
            $sa = $('#nodeSourceArea');
        }
        $sa.html('<span class="km-muted gp-fs11">加载源码...</span>');
        $.ajax({
            url: '/api/graph/node_source',
            data: { scan_id: scanId, vid: vid, context_lines: 8 },
            dataType: 'json',
            success: function(resp) {
                if (resp.code !== 200 || resp.data.error) {
                    $sa.html('<div class="gp-muted-sm">' + escHtml(resp.data.error || '加载失败') + '</div>');
                    return;
                }
                var d = resp.data;
                var targetLine = d.lineno;
                var lines = d.lines || [];
                if (lines.length === 0) {
                    $sa.html('<div class="gp-muted-sm">无源码数据</div>');
                    return;
                }
                // 推断语言
                var lang = 'plain';
                var ext = (d.file_path || '').split('.').pop().toLowerCase();
                var langMap = {php:'php',py:'python',js:'javascript',java:'java',rb:'ruby',go:'go',c:'c',cpp:'cpp',cs:'csharp',ts:'typescript',sol:'solidity',swift:'swift',kt:'kotlin'};
                if (langMap[ext]) lang = langMap[ext];

                // 构建代码表格
                var html = '<div class="gp-kb-title"><i class="fa fa-code"></i> 源码 <span class="gp-kb-normal">' + escHtml(d.file_path.split('/').pop()) + ':' + d.lineno + '</span></div>';
                html += '<div class="gp-code-wrap"><table class="gp-code-table">';
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i];
                    var isTarget = (line.lineno === targetLine);
                    var lineHtml = escHtml(line.code);
                    // Prism 高亮
                    try {
                        if (window.Prism && Prism.languages[lang]) {
                            lineHtml = Prism.highlight(line.code, Prism.languages[lang], lang);
                        }
                    } catch(e) {}
                    var bgStyle = isTarget ? 'background:rgba(231,76,60,0.15);' : '';
                    var numStyle = isTarget ? 'color:#e74c3c;font-weight:bold;' : 'color:#666;';
                    html += '<tr style="' + bgStyle + 'border:none;">';
                    html += '<td style="' + numStyle + 'padding:1px 8px;text-align:right;user-select:none;border:none;vertical-align:top;white-space:nowrap;">' + line.lineno + '</td>';
                    html += '<td style="padding:1px 10px;border:none;white-space:pre;font-family:Consolas,Monaco,monospace;color:#cdd6f4;">' + lineHtml + '</td>';
                    html += '</tr>';
                }
                html += '</table></div>';
                $sa.html(html);
            },
            error: function() {
                $sa.html('<div class="gp-muted-sm">加载失败</div>');
            }
        });
    }

    function loadSubgraph(scanId, vid, depth) {
        requireGraph(function() {
            ensureCytoscape(function() {
                if (!scanId || vid === undefined || vid === null) { kmToast('请先选择 Scan 并输入节点 VID', 'error'); return; }
                depth = depth || parseInt($('#graphDepthInput').val()) || 2;
                $('#btnLoadSubgraph').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> ...');

                var edgeLabels = [];
                $('.graph-edge-filter:checked').each(function() { edgeLabels.push($(this).val()); });
                var params = {
                    scan_id: scanId, vid: vid, depth: depth,
                    edge_labels: edgeLabels.join(','),
                    max_nodes: 500
                };

                $('#btnLoadSubgraph').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> 加载中...');
                $.ajax({
                    url: '/api/graph/subgraph',
                    type: 'GET', data: params, dataType: 'json',
                    success: function(resp) {
                        $('#btnLoadSubgraph').prop('disabled', false).html('<i class="fa fa-project-diagram"></i> 加载子图');
                        if (resp.code === 200 && resp.data) {
                            if (resp.data.error) {
                                kmToast(resp.data.error, 'error'); return;
                            }
                            renderGraph(resp.data);
                            // Highlight center node
                            cy.$('#' + String(vid)).addClass('highlighted');
                        } else {
                            kmToast(resp.error || '加载失败', 'error');
                        }
                    },
                    error: function() {
                        $('#btnLoadSubgraph').prop('disabled', false).html('<i class="fa fa-project-diagram"></i> 加载子图');
                        kmToast('请求失败', 'error');
                    }
                });
            }); // ensureCytoscape
        }); // requireGraph
    }

    function kmToast(msg, type) {
        var colors = {error: '#dc2626', success: '#16a34a', info: '#2563eb'};
        var $t = $('<div style="position:fixed;top:18px;right:18px;z-index:2000;padding:10px 16px;border-radius:8px;color:#fff;font-size:13px;box-shadow:0 6px 24px rgba(0,0,0,0.18);background:' + (colors[type] || colors.info) + ';">' + msg + '</div>');
        $('body').append($t);
        setTimeout(function() { $t.fadeOut(300, function() { $t.remove(); }); }, 3500);
    }

    function loadFileGraph(scanId, filePath) {
        requireGraph(function() {
            ensureCytoscape(function() {
                if (!scanId || !filePath) { kmToast('请先选择 Scan 并输入文件路径', 'error'); return; }
                var params = { scan_id: scanId, file_path: filePath, max_nodes: 1000 };

            $('#btnLoadFileGraph').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> ...');
            $.ajax({
                url: '/api/graph/subgraph',
                type: 'GET', data: params, dataType: 'json',
                success: function(resp) {
                    $('#btnLoadFileGraph').prop('disabled', false).html('<i class="fa fa-file-code-o"></i> 加载文件图');
                    if (resp.code === 200 && resp.data) {
                        if (resp.data.error) { kmToast(resp.data.error, 'error'); return; }
                        renderGraph(resp.data);
                        kmToast('文件图已加载', 'success');
                    } else {
                        kmToast(resp.error || '加载失败', 'error');
                    }
                },
                error: function() {
                    $('#btnLoadFileGraph').prop('disabled', false).html('<i class="fa fa-file-code-o"></i> 加载文件图');
                    kmToast('请求失败', 'error');
                }
            }); // ajax
            }); // ensureCytoscape
        }); // requireGraph
    }


    // Init Cytoscape lazily — only when graph tab is first shown
    var cyInitialized = false;
    function ensureCytoscape(callback) {
        if (cyInitialized) {
            try { cy.resize(); } catch(e) {}
            if (callback) callback();
            return;
        }
        // Force reflow so container has correct dimensions
        var container = document.getElementById('cyGraphContainer');
        if (container) void container.offsetWidth;
        initCytoscape();
        cyInitialized = true;
        if (callback) callback();
    }

    $('#btnLoadSubgraph').on('click', function() {
        var vid = $('#graphVidInput').val();
        if (vid === '' || vid === null || vid === undefined) { alert('请输入节点 VID'); return; }
        loadSubgraph(currentScanId, parseInt(vid));
    });

    $('#graphVidInput').on('keypress', function(e) {
        if (e.which === 13) { $('#btnLoadSubgraph').click(); }
    });

    $('#btnLoadFileGraph').on('click', function() {
        var filePath = selectedFilePath || prompt('输入文件路径:', '');
        if (!filePath) return;
        loadFileGraph(currentScanId, filePath);
    });

    $('#btnFitGraph').on('click', function() {
        if (cy) cy.fit(undefined, 50);
    });

    $('#btnClearGraph').on('click', function() {
        if (cy) { cy.elements().remove(); }
        graphElements = null;
        $('#graphStats').text('');
        $('#nodeDetailContent').html('<div class="km-muted text-center gp-pad20">点击图中的节点查看详情</div>');
    });

    // Layout change
    $('#graphLayoutSelect').on('change', function() {
        if (cy && cy.elements().length > 0) {
            cy.layout({ name: $(this).val(), directed: true, spacingFactor: 1.2, animate: true, animationDuration: 500 }).run();
            setTimeout(function() { cy.fit(undefined, 50); }, 600);
        }
    });

    // Node/Edge type filter — rebuild graph from stored elements
    function applyFilters() {
        if (!graphElements) return;
        var nodeTypes = new Set();
        var edgeTypes = new Set();
        $('.graph-node-filter:checked').each(function() { nodeTypes.add($(this).val()); });
        $('.graph-edge-filter:checked').each(function() { edgeTypes.add($(this).val()); });

        var filtered = graphElements.filter(function(el) {
            if (el.data.source !== undefined) {
                // edge — check edgeLabel
                return edgeTypes.has(el.data.edgeLabel || el.data.label);
            } else {
                // node — check label
                return nodeTypes.has(el.data.label);
            }
        });

        var styled = applyNodeStyles(filtered);
        cy.elements().remove();
        cy.add(styled);
    }
    $('.graph-node-filter, .graph-edge-filter').on('change', applyFilters);

    // Jump to graph tab from other tabs
    function jumpToGraph(vid) {
        $('.tab-btn').removeClass('btn-primary').addClass('btn-default');
        $('.tab-btn[data-tab="tab-graph"]').removeClass('btn-default').addClass('btn-primary');
        $('.tab-pane').hide();
        $('#tab-graph').show();
        ensureCytoscape(function() {
            $('#graphVidInput').val(vid);
            loadSubgraph(currentScanId, vid);
        });
    }

    // Add "查看图" button to file list items and function detail (dynamic)
    // When clicking file-link or func-link, also show a "graph" button
    // 通过 scan_id(=task_id) 反查 project_id，跳转到源码浏览器
    function openFileBrowse(vid, filePath, lineno) {
        var sid = currentScanId;
        if (!sid) { alert('请先选择 Scan'); return; }
        // 先尝试从缓存获取
        if (scanProjectMap[sid]) {
            window.open('/dashboard/projects/' + scanProjectMap[sid] + '/files?file=' + encodeURIComponent(filePath) + '&lineno=' + lineno, '_blank');
            return;
        }
        // 异步查询 — 用 scans 列表的 session 认证 API 反查
        $.ajax({
            url: '/api/graph/scans',
            dataType: 'json',
            success: function(resp) {
                if (resp.code !== 200 || !resp.scans) { alert('查询项目失败'); return; }
                var found = null;
                for (var i = 0; i < resp.scans.length; i++) {
                    if (resp.scans[i].id == sid) { found = resp.scans[i]; break; }
                }
                if (!found || !found.project_id) { alert('无法获取项目 ID'); return; }
                scanProjectMap[sid] = found.project_id;
                window.open('/dashboard/projects/' + found.project_id + '/files?file=' + encodeURIComponent(filePath) + '&lineno=' + lineno, '_blank');
            },
            error: function() { alert('查询项目失败'); }
        });
    }

    // ===== 暴露全局函数供外部调用（URL 参数、task_detail 跳转等）=====
    window.loadSubgraph = loadSubgraph;
    window.loadNodeSource = loadNodeSource;
    window.loadFileGraph = loadFileGraph;
    window.loadCallGraph = loadCallGraph;
    window.traceVariable = traceVariable;
    window.selectScan = selectScan;
    window.ensureCytoscape = ensureCytoscape;
    window.jumpToGraph = jumpToGraph;
    window.currentScanId = function() { return currentScanId; };
});

  

$(function(){
  $.getJSON("{% url 'api:stats_dashboard' %}", function(data){
    if(data.code !== 200) return;

    var colors = ['#e74c3c','#3498db','#2ecc71','#f39c12','#9b59b6','#1abc9c','#e67e22','#34495e'];

    // 语言分布饼图
    var langLabels = data.lang_dist.map(function(d){ return d.language; });
    var langData = data.lang_dist.map(function(d){ return d.count; });
    new Chart(document.getElementById('chartLang'), {
      type: 'doughnut',
      data: {
        labels: langLabels,
        datasets: [{ data: langData, backgroundColor: colors.slice(0, langLabels.length) }]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
    });

    // 等级分布柱状图
    var ld = data.level_dist;
    new Chart(document.getElementById('chartLevel'), {
      type: 'bar',
      data: {
        labels: Object.keys(ld),
        datasets: [{
          label: '漏洞数',
          data: Object.values(ld),
          backgroundColor: ['#e74c3c','#f39c12','#3498db','#95a5a6']
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }, plugins: { legend: { display: false } } }
    });

    // 最近 7 天折线图
    var dailyLabels = data.daily_tasks.map(function(d){ return d.date.slice(5); });
    var dailyData = data.daily_tasks.map(function(d){ return d.count; });
    new Chart(document.getElementById('chartDaily'), {
      type: 'line',
      data: {
        labels: dailyLabels,
        datasets: [{
          label: '扫描次数',
          data: dailyData,
          borderColor: '#2ecc71',
          backgroundColor: 'rgba(46,204,113,0.1)',
          fill: true,
          tension: 0.3
        }]
      },
      options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }, plugins: { legend: { display: false } } }
    });
  });
});

  

$(document).ready(function () {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#user").addClass("active");
});

 