 

$(document).ready(function(){
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#tasks").addClass("menu-open");
  $("#tasks").find("ul").css("display","block");

  var taskId = {{ task.id }};
  var $tree = $("#fileTree");

  // 文件夹展开/折叠
  $tree.on("click", "li[data-dir='True'] > a", function(e){
    e.preventDefault();
    var $sub = $(this).siblings("ul");
    var $icon = $(this).find("i");
    if ($sub.is(":visible")) {
      $sub.slideUp(200);
      $icon.removeClass("fa-folder-open").addClass("fa-folder");
    } else {
      $sub.slideDown(200);
      $icon.removeClass("fa-folder").addClass("fa-folder-open");
    }
  });

  // 文件点击
  $tree.on("click", "li[data-dir='False'] > a", function(e){
    e.preventDefault();
    var path = $(this).parent().data("path");
    window.location.href = "{% url 'dashboard:task_code_view' task.id %}?file=" + encodeURIComponent(path);
  });

  // 高亮当前选中文件
  $tree.find("li[data-dir='False']").each(function(){
    if ($(this).data("path") === "{{ rel_path }}") {
      $(this).addClass("active");
      // 展开父目录
      $(this).closest("ul").slideDown(0);
    }
  });
});

  

$(document).ready(function () {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#tasks").addClass("menu-open");
  $("#tasks").find("ul").find("li#task_new").addClass("active");
  $("#tasks").find("ul").css("display","block");

  var btn = document.getElementById('toggleAdvanced');
  var panel = document.getElementById('advancedPanel');
  var arrow = document.getElementById('advancedArrow');
  var sub = document.getElementById('advancedSub');
  if (btn && panel) {
    function toggleAdvanced() {
      var open = panel.style.display !== 'none';
      panel.style.display = open ? 'none' : 'block';
      btn.setAttribute('aria-expanded', open ? 'false' : 'true');
      if (sub) {
        sub.textContent = open ? '点击展开' : '点击收起';
      }
      if (arrow) {
        arrow.className = open ? 'km-advanced-arrow' : 'km-advanced-arrow is-open';
      }
    }
    btn.addEventListener('click', toggleAdvanced);
    btn.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleAdvanced();
      }
    });
  }
});

  

// 注入漏洞链数据（Django 后端渲染）—— 必须在 chain-panel.js 之前
var chainDataMap = {{ chain_json|safe }};

  

var activeVulRow = null;
function toggleVulDetail(row) {
  var vulId = row.getAttribute('data-vul-id');
  var detailRow = row.nextElementSibling;
  if (!detailRow || !detailRow.classList.contains('km-vul-detail-row')) return;

  // 关闭之前打开的
  if (activeVulRow && activeVulRow !== row) {
    var prevDetail = activeVulRow.nextElementSibling;
    if (prevDetail && prevDetail.classList.contains('km-vul-detail-row')) {
      prevDetail.style.display = 'none';
      activeVulRow.classList.remove('km-vul-row-active');
    }
  }

  if (detailRow.style.display === 'none') {
    detailRow.style.display = 'table-row';
    row.classList.add('km-vul-row-active');
    activeVulRow = row;
    // 渲染右侧传播链/代码区
    renderVulChainArea(vulId);
  } else {
    detailRow.style.display = 'none';
    row.classList.remove('km-vul-row-active');
    activeVulRow = null;
  }
}

function renderVulChainArea(vulId) {
  var $area = $('#vulChain_' + vulId);
  if (!$area.length) return;
  var nodes = chainDataMap[vulId];

  if (nodes && nodes.length > 0) {
    // 有传播链数据 → 渲染链面板
    var html = '<div class="km-chain-panel" style="height:100%;border:none;">';
    html += '<div class="km-chain-sidebar" id="chainSidebar_' + vulId + '"></div>';
    html += '<div class="km-chain-code" id="chainCode_' + vulId + '"></div>';
    html += '</div>';
    $area.html(html);
    renderChainNodes(vulId, nodes);
  } else {
    // 没有传播链 → 提示
    $area.html('<div style="padding:20px;text-align:center;color:#999;font-size:13px;">暂无传播链数据</div>');
  }
}

// 渲染传播链节点（复用 chain-panel.js 的逻辑，但填充到当前行对应的容器）
function renderChainNodes(vulId, nodes) {
  var sidebar = document.getElementById('chainSidebar_' + vulId);
  var codeArea = document.getElementById('chainCode_' + vulId);
  if (!sidebar || !codeArea) return;

  var html = '<div class="km-chain-title">漏洞传播链</div><div class="km-chain-nodes">';
  for (var i = 0; i < nodes.length; i++) {
    var node = nodes[i];
    var style = getNodeStyle(node.type);
    var isActive = (i === nodes.length - 1);
    html += '<div class="km-chain-node' + (isActive ? ' km-chain-node-active' : '') + '" data-idx="' + i + '" onclick="selectChainNodeInline(\'' + vulId + '\',' + i + ')">';
    html += '  <div class="km-chain-node-icon" style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i></div>';
    html += '  <div class="km-chain-node-info">';
    html += '    <div class="km-chain-node-type" style="color:' + style.color + '">' + (style.label || node.type) + '</div>';
    html += '    <div class="km-chain-node-content" title="' + escapeHtml(node.content) + '">' + escapeHtml(node.content) + '</div>';
    if (node.path && node.lineno) {
      html += '    <div class="km-chain-node-loc">' + escapeHtml(node.path.split('/').pop()) + ':' + node.lineno + '</div>';
    }
    html += '  </div></div>';
    if (i < nodes.length - 1) html += '<div class="km-chain-connector"><div class="km-chain-connector-line"></div></div>';
  }
  html += '</div>';
  sidebar.innerHTML = html;
  selectChainNodeInline(vulId, nodes.length - 1);
}

function selectChainNodeInline(vulId, idx) {
  var nodes = chainDataMap[vulId];
  if (!nodes || !nodes[idx]) return;
  var node = nodes[idx];
  var style = getNodeStyle(node.type);

  // 更新左侧高亮
  var sidebar = document.getElementById('chainSidebar_' + vulId);
  if (sidebar) {
    sidebar.querySelectorAll('.km-chain-node').forEach(function(el) { el.classList.remove('km-chain-node-active'); });
    var activeNode = sidebar.querySelector('.km-chain-node[data-idx="' + idx + '"]');
    if (activeNode) activeNode.classList.add('km-chain-node-active');
  }

  // 右侧渲染代码
  var codeArea = document.getElementById('chainCode_' + vulId);
  if (!codeArea) return;

  if (node.source) {
    var sourceLines = node.source.split('\n');
    var rawLines = [], lineNums = [];
    for (var i = 0; i < sourceLines.length; i++) {
      var m = sourceLines[i].match(/^(\s*)(\d+):\s?(.*)/);
      if (m) { lineNums.push(parseInt(m[2])); rawLines.push(m[3]); }
      else { rawLines.push(sourceLines[i]); lineNums.push(0); }
    }
    var fullText = rawLines.join('\n');
    var lang = inferLang(node.path);
    var highlightedText = fullText;
    try {
      if (window.Prism && Prism.languages[lang]) highlightedText = Prism.highlight(fullText, Prism.languages[lang], lang);
    } catch (e) {}
    var highlightedLines = highlightedText.split('\n');
    var targetLineno = parseInt(node.lineno) || 0;

    var html = '<div class="km-chain-code-header">';
    html += '<span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span>';
    if (node.path) html += ' <span class="km-chain-code-path">' + escapeHtml(node.path.split('/').pop()) + ':' + node.lineno + '</span>';
    html += '</div><div class="km-chain-code-body"><table class="km-chain-code-table"><tbody>';
    for (var i = 0; i < highlightedLines.length; i++) {
      var isTarget = (lineNums[i] === targetLineno);
      html += '<tr class="' + (isTarget ? 'km-chain-line-highlight' : '') + '">';
      html += '<td class="km-chain-lineno">' + (lineNums[i] || '') + '</td>';
      html += '<td class="km-chain-code-line">' + highlightedLines[i] + '</td></tr>';
    }
    html += '</tbody></table></div>';
    codeArea.innerHTML = html;
  } else {
    codeArea.innerHTML = '<div class="km-chain-code-header"><span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span></div>'
      + '<div class="km-chain-code-body"><pre style="margin:0;padding:12px;font-size:14px;font-family:\'Fira Code\',Consolas,monospace;background:#eaedf1;color:#24292e;">' + escapeHtml(node.content || '(无代码)') + '</pre></div>';
  }
}

function delVul(vulid){
  $.get("{% url 'dashboard:vul_del' 654321 %}".replace('654321', vulid), function(data){
      if(data.code == 200){
          location.reload();
      }else{
          alert(data.message)
      }
  })
}

$(document).ready(function(){
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#tasks").addClass("menu-open");
  $("#tasks").find("ul").find("li#task_list").addClass("active");
  $("#tasks").find("ul").css("display","block");

  // 查看完整日志
  $("button#result").click(function () {
      location.href = "{% url 'backend:tasklog' task.id %}?token={{ visit_token }}";
  });

  // 实时日志
  var logPollTimer = null;
  var logPaused = false;
  var lastLogLen = 0;
  $("button#btnLogLive").click(function(){
    $("#logPanel").show();
    lastLogLen = 0;
    logPaused = false;
    $("#btnLogPause").html('<i class="fa fa-pause"></i> 暂停');
    pollLog();
  });
  $("#btnLogPause").click(function(){
    logPaused = !logPaused;
    $(this).html(logPaused ? '<i class="fa fa-play"></i> 继续' : '<i class="fa fa-pause"></i> 暂停');
  });
  function pollLog(){
    if(logPaused) { logPollTimer = setTimeout(pollLog, 2000); return; }
    $.getJSON("{% url 'api:tasklogtail' task.id %}?token={{ visit_token }}", function(data){
      if(data.code==200){
        var txt = (data.data || []).join("\n");
        var $pre = $("#logContent");
        if(txt.length > lastLogLen){
          $pre.text(txt);
          lastLogLen = txt.length;
          $pre.scrollTop($pre[0].scrollHeight);
        }
        if(data.finished){
          $pre.append("\n\n--- 任务已结束 ---");
          return;
        }
      }
      logPollTimer = setTimeout(pollLog, 2000);
    }).fail(function(){ logPollTimer = setTimeout(pollLog, 5000); });
  }

  // 取消任务
  $("button#btnCancel").click(function(){
    if(!confirm("确定取消此任务？")) return;
    $.post("{% url 'api:taskcancel' task.id %}?token={{ visit_token }}", {
      csrfmiddlewaretoken: $("input[name='csrfmiddlewaretoken']").val()
    }, function(data){
      if(data.code==200){ alert("任务已取消"); location.reload(); }
      else alert(data.message || "操作失败");
    });
  });

  // 重试任务
  $("button#btnRetry").click(function(){
    if(!confirm("确定重试此任务？")) return;
    $.post("{% url 'api:taskretry' task.id %}?token={{ visit_token }}", {
      csrfmiddlewaretoken: $("input[name='csrfmiddlewaretoken']").val()
    }, function(data){
      if(data.code==200){ alert("任务已重新提交"); location.reload(); }
      else alert(data.message || "操作失败");
    });
  });

  // 结果筛选
  var currentFilter = 'all';
  var currentSearch = '';
  function applyFilters(){
    var $rows = $("#resultTable tbody tr.km-vul-row");
    var visible = 0;
    $rows.each(function(){
      var $r = $(this);
      var $detail = $r.next('.km-vul-detail-row');
      var text = $r.text().toLowerCase();
      var matchSearch = !currentSearch || text.indexOf(currentSearch) >= 0;
      var matchLevel = currentFilter === 'all' ||
        (currentFilter === 'confirmed' && $r.data('confirm') === 'confirmed') ||
        (currentFilter === 'unconfirmed' && $r.data('confirm') === 'unconfirmed') ||
        $r.data('level') === currentFilter;
      var show = matchSearch && matchLevel;
      $r.toggle(show);
      $detail.toggle(show);
      if(show) visible++;
    });
  }
  $("#filterBar").on("click", ".filter-btn", function(){
    $(".filter-btn").removeClass("active btn-danger btn-warning btn-info").addClass("btn-default");
    var f = $(this).data('filter');
    currentFilter = f;
    var cls = {'critical':'btn-danger','high':'btn-danger','medium':'btn-warning','low':'btn-info'};
    $(this).removeClass('btn-default').addClass(cls[f] || 'active');
    applyFilters();
  });
  $("#resultFilter").on("input", function(){
    currentSearch = $(this).val().toLowerCase().trim();
    applyFilters();
  });

});

  

$(document).ready(function () {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#tasks").addClass("menu-open");
  $("#tasks").find("ul").find("li#task_new").addClass("active");
  $("#tasks").find("ul").css("display","block");

  // Tab 切换
  $('.km-tab:not(:disabled)').on('click', function () {
    var target = $(this).data('target');
    $('.km-tab').removeClass('active');
    $(this).addClass('active');
    $('.km-tab-pane').removeClass('active');
    $('#' + target).addClass('active');
  });

  // 文件上传逻辑（保留原有）
  var dz = document.getElementById('dropzone');
  var input = document.getElementById('archiveInput');
  var nameBox = document.getElementById('fileName');
  var statusBox = document.getElementById('uploadStatus');
  var form = document.getElementById('uploadForm');
  var submitting = false;

  function submitNow() {
    if (submitting) return;
    submitting = true;
    statusBox.textContent = '正在上传并准备项目，请稍候...';
    dz.style.pointerEvents = 'none';
    dz.style.opacity = '0.72';
    form.submit();
  }

  function setFile(f) {
    if (!f) return;
    nameBox.textContent = '已选择：' + f.name;
    setTimeout(function () {
      submitNow();
    }, 150);
  }

  dz.addEventListener('click', function () {
    input.click();
  });

  input.addEventListener('change', function () {
    if (input.files && input.files[0]) setFile(input.files[0]);
  });

  dz.addEventListener('dragover', function (e) {
    e.preventDefault();
    dz.style.background = '#f0f7ff';
  });

  dz.addEventListener('dragleave', function (e) {
    e.preventDefault();
    dz.style.background = '#fafcff';
  });

  dz.addEventListener('drop', function (e) {
    e.preventDefault();
    dz.style.background = '#fafcff';
    if (!e.dataTransfer || !e.dataTransfer.files || !e.dataTransfer.files[0]) return;
    input.files = e.dataTransfer.files;
    setFile(e.dataTransfer.files[0]);
  });

  form.addEventListener('submit', function () {
    if (submitting) return;
    submitNow();
  });
});

  

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#tasks").addClass("menu-open");
          $("#tasks").find("ul").find("li#task_list").addClass("active");
          $("#tasks").find("ul").css("display","block");

          $("#allTaskFilterInput").on("input", function () {
              var text = $(this).val().toLowerCase();
              $("#allTaskTable tbody tr").each(function () {
                  var rowText = $(this).text().toLowerCase();
                  $(this).toggle(rowText.indexOf(text) > -1);
              });
          });
      });

 