 

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
                    $.each(resp.scans, function (i, s) {
                        var opt = '<option value="' + s.id + '">'
                            + 'ID:' + s.id + ' | ' + (s.language || '?') + ' | '
                            + (s.target || '-') + ' (节点:' + (s.node_count || 0) + ' 边:' + (s.edge_count || 0) + ')'
                            + '</option>';
                        $sel.append(opt);
                    });
                    // 自动选择最新的（第一个）
                    $sel.val(resp.scans[0].id);
                    selectScan(resp.scans[0].id);
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
    });

    // ===== Tab 1: 概览 =====
    $('#btnLoadOverview').on('click', function () {
        loadOverview(currentScanId);
    });

    function loadOverview(scanId) {
        if (!scanId) { alert('请先选择一个 Scan'); return; }
        var $btn = $('#btnLoadOverview');
        $btn.prop('disabled', true).text('加载中...');

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

                // Label Summary
                var $lb = $('#labelSummaryBody').empty();
                if (d.label_summary) {
                    $.each(d.label_summary, function (label, count) {
                        $lb.append('<tr><td><code>' + escHtml(label) + '</code></td><td style="text-align:right;">' + count + '</td></tr>');
                    });
                } else {
                    $lb.append('<tr><td colspan="2" class="text-center km-muted">无数据</td></tr>');
                }

                // 文件列表
                var $fl = $('#fileListBody').empty();
                if (d.files && d.files.length > 0) {
                    $.each(d.files, function (i, f) {
                        $fl.append('<tr><td><a href="#" class="file-link" data-path="' + escHtml(f.path || f.name || '') + '">' + escHtml(f.path || f.name || '-') + '</a></td>'
                            + '<td>' + escHtml(f.language || '-') + '</td>'
                            + '<td style="text-align:right;">' + (f.node_count || 0) + '</td></tr>');
                    });
                } else {
                    $fl.append('<tr><td colspan="3" class="text-center km-muted">无数据</td></tr>');
                }
            },
            error: function () {
                $btn.prop('disabled', false).html('<i class="fa fa-refresh"></i> 加载概览');
                $('#labelSummaryBody').html('<tr><td colspan="2" class="text-center text-danger">请求失败</td></tr>');
            }
        });
    }

    // 文件列表中的链接点击 -> 跳到文件查询 Tab
    $(document).on('click', '.file-link', function (e) {
        e.preventDefault();
        var path = $(this).data('path');
        $('#fileQueryInput').val(path);
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
                        $tb.append('<tr><td>' + escHtml(c.name || c) + '</td><td>' + (c.lineno || '-') + '</td></tr>');
                    });
                } else { $('#fileClassesBox').hide(); }

                // Functions
                if (d.functions && d.functions.length > 0) {
                    $('#fileFunctionsBox').show();
                    var $tb = $('#fileFunctionsBody').empty();
                    $.each(d.functions, function (i, f) {
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(f.name || f) + '">' + escHtml(f.name || f) + '</a></td><td>' + (f.lineno || '-') + '</td></tr>');
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
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(c.name || c) + '">' + escHtml(c.name || c) + '</a></td><td>' + (c.lineno || '-') + '</td><td>' + escHtml(c.file_path || '-') + '</td></tr>');
                    });
                } else { $('#funcCallersBox').hide(); }

                // Callees
                if (d.callees && d.callees.length > 0) {
                    $('#funcCalleesBox').show();
                    var $tb = $('#funcCalleesBody').empty();
                    $.each(d.callees, function (i, c) {
                        $tb.append('<tr><td><a href="#" class="func-link" data-name="' + escHtml(c.name || c) + '">' + escHtml(c.name || c) + '</a></td><td>' + (c.lineno || '-') + '</td><td>' + escHtml(c.file_path || '-') + '</td></tr>');
                    });
                } else { $('#funcCalleesBox').hide(); }
            },
            error: function (xhr) {
                $('#funcErrorArea').show();
                $('#funcErrorMsg').text('请求失败: ' + (xhr.statusText || '网络错误'));
            }
        });
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
        $('#traceResultArea').html('<div class="text-center km-muted" style="padding:20px;">加载中...</div>');
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
            $container.html('<div class="box"><div class="box-body text-center km-muted">无追踪结果</div></div>');
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

            var html = '<div class="row"><div class="col-xs-12"><div class="box">';
            html += '<div class="box-header"><h3 class="box-title">Sink #' + (idx + 1) + ': ' + escHtml(sink.name || '-') + '</h3></div>';
            html += '<div class="box-body">';

            // Sink 信息
            html += '<table class="table km-table" style="margin-bottom:10px;">';
            html += '<tr><td class="km-muted" style="width:80px;">名称</td><td>' + escHtml(sink.name || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">行号</td><td>' + (sink.lineno || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">类型</td><td>' + escHtml(sink.type || '-') + '</td></tr>';
            html += '<tr><td class="km-muted">参数索引</td><td>' + (item.arg_index != null ? item.arg_index : '-') + '</td></tr>';
            html += '</table>';

            // Result
            html += '<div style="margin-bottom:10px;">';
            html += '<span class="label ' + statusClass + '">' + statusText + '</span> ';
            html += '<strong>code:</strong> ' + (resultCode != null ? resultCode : '-') + '&nbsp;&nbsp;';
            if (result.reason) html += '<strong>原因:</strong> ' + escHtml(result.reason);
            if (result.description) html += '<br><strong>描述:</strong> ' + escHtml(result.description);
            html += '</div>';

            // Chain
            if (chain.length > 0) {
                html += '<h4>追踪链</h4>';
                html += '<div style="border-left:3px solid #3c8dbc;padding-left:15px;margin-left:10px;">';
                $.each(chain, function (ci, step) {
                    html += '<div style="margin-bottom:10px;padding:8px;background:#f9f9f9;border-radius:3px;">';
                    html += '<div><strong>Step ' + (ci + 1) + '</strong>';
                    if (step.type) html += ' <span class="label label-info">' + escHtml(step.type) + '</span>';
                    html += '</div>';
                    if (step.name) html += '<div>名称: <code>' + escHtml(step.name) + '</code></div>';
                    if (step.path || step.file_path) html += '<div>路径: ' + escHtml(step.path || step.file_path) + '</div>';
                    if (step.lineno) html += '<div>行号: ' + step.lineno + '</div>';
                    html += '</div>';
                });
                html += '</div>';
            }

            html += '</div></div></div></div>';
            $container.append(html);
        });
    }

    // ===== 工具函数 =====
    function escHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
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
          label: '扫描任务数',
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

 