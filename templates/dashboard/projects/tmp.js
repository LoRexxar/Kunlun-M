 

var chainDataMap = {{ chain_json|safe }};

  


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
  $("#projects").addClass("menu-open");
  $("#projects").find("ul").find("li#task_list").addClass("active");
  $("#projects").find("ul").css("display","block");

});

  

var project_id = $('#projectId').val();
var source_root = $('#sourceRoot').val();
var current_file = '';
var current_lines = [];
var current_highlight = null;

// ── 扩展名 → 图标 ──
var extIcons = {
  'py':'fa-file-code-o','php':'fa-file-code-o','java':'fa-file-code-o',
  'js':'fa-file-code-o','ts':'fa-file-code-o','go':'fa-file-code-o',
  'c':'fa-file-code-o','cpp':'fa-file-code-o','h':'fa-file-code-o',
  'html':'fa-file-code-o','htm':'fa-file-code-o','css':'fa-file-code-o',
  'json':'fa-file-code-o','xml':'fa-file-code-o','yml':'fa-file-code-o','yaml':'fa-file-code-o',
  'md':'fa-file-text-o','txt':'fa-file-text-o','log':'fa-file-text-o',
  'sql':'fa-database','sh':'fa-terminal','bat':'fa-terminal',
  'zip':'fa-file-archive-o','tar':'fa-file-archive-o','gz':'fa-file-archive-o',
  'png':'fa-file-image-o','jpg':'fa-file-image-o','gif':'fa-file-image-o',
  'pdf':'fa-file-pdf-o',
};
function fileIcon(name) {
  var i = name.lastIndexOf('.');
  var ext = i > 0 ? name.substring(i+1).toLowerCase() : '';
  return extIcons[ext] || 'fa-file-o';
}

// ── 扩展名 → Prism 语言 ──
var extLang = {
  'py':'python','php':'php','java':'java','js':'javascript','ts':'typescript',
  'go':'go','c':'c','cpp':'cpp','h':'c','html':'markup','htm':'markup',
  'css':'css','json':'json','xml':'markup','yml':'yaml','yaml':'yaml',
  'sh':'bash','bash':'bash','sql':'sql','rb':'ruby','swift':'swift',
  'rs':'rust','kt':'kotlin','jsx':'jsx','tsx':'tsx',
};
function getLang(name) { var i=name.lastIndexOf('.'); return extLang[(i>0?name.substring(i+1):'').toLowerCase()]||''; }

// ── Prism 语言映射确认 ──
var prismLoaded = (typeof Prism !== 'undefined');

// ── 加载根目录 ──
function loadRoot() {
  var $tree = $('#fileTree');
  $tree.html('<li class="km-tree-loading"><i class="fa fa-spinner fa-spin"></i> 加载中...</li>');
  $.getJSON('/dashboard/projects/' + project_id + '/files/api', {root: source_root}, function(data) {
    $tree.empty();
    renderTree($tree, data.entries || [], '');
  }).fail(function() {
    $tree.html('<li style="color:#c00;">加载失败</li>');
  });
}

// ── 渲染目录项 ──
function renderTree($parent, entries, parentPath) {
  entries.forEach(function(entry) {
    var $li = $('<li>').addClass('km-tree-node');
    var fullPath = entry.path;
    var $item = $('<div>').addClass('km-tree-item').attr('data-path', fullPath).attr('data-dir', entry.is_dir ? '1' : '0');
    $item.attr('data-name', entry.name.toLowerCase());

    if (entry.is_dir) {
      $item.html(
        '<span class="km-tree-chevron"><i class="fa fa-caret-right"></i></span>' +
        '<i class="fa fa-folder"></i> ' + escHtml(entry.name) +
        '<span style="float:right;color:#666;font-size:11px;">' + (entry.size > 0 ? entry.size : '') + '</span>'
      );
      var $children = $('<ul>').addClass('km-tree-children');
      $li.append($item).append($children);
      $item.on('click', function() {
        var $chevron = $item.find('.km-tree-chevron');
        var $folderIcon = $item.find('.fa-folder, .fa-folder-open');
        if ($children.hasClass('open')) {
          $children.removeClass('open');
          $chevron.removeClass('open');
          $folderIcon.removeClass('fa-folder-open').addClass('fa-folder');
        } else {
          // 懒加载
          if ($children.children().length === 0) {
            $children.html('<li class="km-tree-loading"><i class="fa fa-spinner fa-spin"></i></li>');
            $.getJSON('/dashboard/projects/' + project_id + '/files/api', {root: source_root, dir: fullPath}, function(data) {
              $children.empty();
              if (data.entries && data.entries.length > 0) {
                renderTree($children, data.entries, fullPath);
              } else {
                $children.html('<li style="color:#999;padding:2px 6px;font-size:12px;">（空目录）</li>');
              }
            }).fail(function() {
              $children.html('<li style="color:#c00;padding:2px 6px;">加载失败</li>');
            });
          }
          $children.addClass('open');
          $chevron.addClass('open');
          $folderIcon.removeClass('fa-folder').addClass('fa-folder-open');
        }
      });
    } else {
      $item.html(
        '<span class="km-tree-chevron" style="visibility:hidden;"><i class="fa fa-caret-right"></i></span>' +
        '<i class="fa ' + fileIcon(entry.name) + '"></i> ' + escHtml(entry.name) +
        '<span style="float:right;color:#666;font-size:11px;">' + formatSize(entry.size) + '</span>'
      );
      $li.append($item);
      $item.on('click', function() {
        openFile(fullPath);
        $('#fileTree .km-tree-item').removeClass('active');
        $item.addClass('active');
      });
    }
    $parent.append($li);
  });
}

// ── 打开文件 ──
function openFile(filePath) {
  current_file = filePath;
  var $codePanel = $('#codePanel');
  var $welcome = $('#welcomePanel');
  var $error = $('#errorPanel');
  $codePanel.hide(); $welcome.hide(); $error.hide();

  // 面包屑
  var parts = filePath.split('/');
  var bc = '<a onclick="loadRoot()"><i class="fa fa-home"></i></a>';
  var accumulated = '';
  parts.forEach(function(p, i) {
    if (i < parts.length - 1) {
      accumulated += p + '/';
      bc += ' / <a onclick="expandTo(\'' + escAttr(accumulated) + '\')">' + escHtml(p) + '</a>';
    } else {
      bc += ' / <strong>' + escHtml(p) + '</strong>';
    }
  });
  $('#breadcrumb').html(bc);

  // 读取高亮行号（从 URL 参数）
  var urlParams = new URLSearchParams(window.location.search);
  var lineno = urlParams.get('lineno');

  $.getJSON('/dashboard/projects/' + project_id + '/files/content', {
    root: source_root, file: filePath, lineno: lineno || ''
  }, function(data) {
    if (data.error) {
      $error.show();
      $('#errorMessage').text(data.error);
      return;
    }
    current_lines = data.lines;
    current_highlight = data.highlight || null;
    renderCode(data.lines, data.highlight, data.total_lines);
    $codePanel.show();
  }).fail(function(jqxhr) {
    $error.show();
    $('#errorMessage').text('加载失败: HTTP ' + jqxhr.status);
  });
}

// ── 渲染代码行 ──
function renderCode(lines, highlight, totalLines) {
  var $body = $('#codeBody');
  $body.empty();
  var lang = getLang(current_file);

  // 整段高亮再按行拆分（保持跨行语法正确）
  var fullText = lines.join('\n');
  var highlightedHtml;
  if (prismLoaded && lang && Prism.languages[lang]) {
    try { highlightedHtml = Prism.highlight(fullText, Prism.languages[lang], lang); } catch(e) { highlightedHtml = escHtml(fullText); }
  } else {
    highlightedHtml = escHtml(fullText);
  }
  // 用 \n 拆分（保留每行末尾换行）
  var hLines = highlightedHtml.split('\n');
  // 最后一个元素是空串（trailing \n 产生），去掉
  if (hLines.length > lines.length) hLines.pop();

  for (var i = 0; i < hLines.length; i++) {
    var lineno = i + 1;
    var isHighlight = (highlight === lineno);
    var cls = isHighlight ? 'km-line-hl-anchor' : '';
    if (!isHighlight && highlight && Math.abs(lineno - highlight) <= 5) {
      cls = 'km-line-highlight';
    }
    var $tr = $('<tr>').addClass(cls).attr('data-lineno', lineno);
    $tr.append($('<td>').addClass('km-code-line-num').text(lineno));
    $tr.append($('<td>').addClass('km-code-line').html(hLines[i] || ' '));
    $body.append($tr);
  }
  // 滚动到高亮行
  setTimeout(function() {
    if (highlight) {
      var $hl = $body.find('.km-line-hl-anchor');
      if ($hl.length) {
        $hl[0].scrollIntoView({behavior: 'smooth', block: 'center'});
      }
    }
  }, 100);
}

// ── 展开 tree 到指定路径 ──
function expandTo(dirPath) {
  var parts = dirPath.replace(/\/$/, '').split('/');
  var $ul = $('#fileTree');
  var accumulated = '';
  function expandLevel(idx) {
    if (idx >= parts.length) return;
    accumulated += (idx > 0 ? '/' : '') + parts[idx];
    var $item = $ul.find('.km-tree-item[data-path="' + accumulated + '"]');
    if (!$item.length) return;
    var $children = $item.siblings('.km-tree-children').first();
    if (!$children.length) return;
    if (!$children.hasClass('open')) {
      // 加载
      if ($children.children().length === 0) {
        $.getJSON('/dashboard/projects/' + project_id + '/files/api', {root: source_root, dir: accumulated}, function(data) {
          $children.empty();
          renderTree($children, data.entries || [], accumulated);
          $children.addClass('open');
          $item.find('.km-tree-chevron').addClass('open');
          $item.find('.fa-folder').removeClass('fa-folder').addClass('fa-folder-open');
          expandLevel(idx + 1);
        });
      } else {
        $children.addClass('open');
        $item.find('.km-tree-chevron').addClass('open');
        $item.find('.fa-folder').removeClass('fa-folder').addClass('fa-folder-open');
      }
    }
    $ul = $children;
    expandLevel(idx + 1);
  }
  expandLevel(0);
}

// ── 文件树过滤 ──
$('#treeFilter').on('input', function() {
  var q = $(this).val().toLowerCase().trim();
  if (!q) {
    $('#fileTree .km-tree-node').removeClass('km-tree-hidden');
    return;
  }
  $('#fileTree .km-tree-item').each(function() {
    var $item = $(this);
    var name = $item.data('name') || '';
    if (name.indexOf(q) >= 0) {
      $item.closest('.km-tree-node').removeClass('km-tree-hidden');
      // 展开所有父级
      $item.parents('.km-tree-children').addClass('open');
      $item.parents('.km-tree-children').prev('.km-tree-item').find('.km-tree-chevron').addClass('open');
    } else if ($item.data('dir') === '1') {
      // 目录：如果有子项匹配则保持可见
      var $children = $item.siblings('.km-tree-children');
      var hasMatch = $children.find('.km-tree-item[data-name*="' + q + '"]').length > 0;
      $item.closest('.km-tree-node').toggleClass('km-tree-hidden', !hasMatch);
    } else {
      $item.closest('.km-tree-node').addClass('km-tree-hidden');
    }
  });
});

// ── 工具函数 ──
function escHtml(s) { return $('<span>').text(s).html(); }
function escAttr(s) { return s.replace(/'/g, "\\'").replace(/"/g, '\\"'); }
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/1024/1024).toFixed(1) + ' MB';
}

// ── 行号点击复制 ──
$(document).on('click', '.km-code-line-num', function() {
  var lineno = $(this).closest('tr').data('lineno');
  var text = current_lines[lineno - 1] || '';
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text);
    toast('已复制第 ' + lineno + ' 行');
  }
});

// ── 初始化 ──
$(document).ready(function() {
  // 侧边栏状态
  $("#dashboard").removeClass("active menu-open");
  $("#projects").addClass("menu-open");
  $("#projects").find("ul").css("display","block");

  if (!source_root) {
    $('#fileTree').html('<li style="color:#d9534f;padding:12px 8px;font-size:13px;font-weight:bold;"><i class="fa fa-exclamation-circle"></i> 暂无源码目录</li>');
    return;
  }
  loadRoot();

  // URL 参数：自动打开文件+高亮
  var params = new URLSearchParams(window.location.search);
  var initFile = params.get('file') || '';
  var initLine = params.get('lineno') || '';
  // 支持 vulfile_path 格式: "v.php:58" → file=v.php, lineno=58
  if (initFile && !initLine) {
    var colonIdx = initFile.lastIndexOf(':');
    if (colonIdx > 0) {
      var possibleLine = initFile.substring(colonIdx + 1);
      if (/^\d+$/.test(possibleLine)) {
        initLine = possibleLine;
        initFile = initFile.substring(0, colonIdx);
      }
    }
  }
  if (initFile) {
    // 先展开到文件所在目录
    var lastSlash = initFile.lastIndexOf('/');
    if (lastSlash > 0) {
      expandTo(initFile.substring(0, lastSlash + 1));
    }
    // 延迟打开文件（等 tree 加载完）
    setTimeout(function() {
      // 先更新 URL（去掉冒号行号格式）
      if (initLine) {
        var newUrl = new URL(window.location);
        newUrl.searchParams.set('lineno', initLine);
        newUrl.searchParams.set('file', initFile);
        window.history.replaceState(null, '', newUrl);
      }
      openFile(initFile);
    }, 500);
  }
});

  

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#projects").addClass("menu-open");
          $("#projects").find("ul").find("li#task_list").addClass("active");
          $("#projects").find("ul").css("display","block");
      });

 