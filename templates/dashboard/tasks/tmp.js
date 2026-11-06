 

$(document).ready(function(){
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#projects").addClass("menu-open");
  $("#projects").find("ul").css("display","block");

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
  $("#projects").addClass("menu-open");
  $("#projects").find("ul").find("li#task_new").addClass("active");
  $("#projects").find("ul").css("display","block");

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

  

$(function(){
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
});

  

$(document).ready(function () {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#projects").addClass("menu-open");
  $("#projects").find("ul").find("li#task_new").addClass("active");
  $("#projects").find("ul").css("display","block");

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

  

function setTaskFilter(st) {
  document.querySelectorAll('.tk-chip').forEach(function(b) {
    var on = b.getAttribute('data-st') === st;
    b.classList.toggle('btn-primary', on);
    b.classList.toggle('btn-default', !on);
  });
  var n = 0;
  document.querySelectorAll('#allTaskTable tbody tr').forEach(function(tr) {
    var show = (st === 'all') || (tr.getAttribute('data-status') === st);
    tr.style.display = show ? '' : 'none';
    if (show) n++;
  });
  document.getElementById('tkFilterHint').textContent = st === 'all' ? '' : n + ' 条';
}
      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#projects").addClass("menu-open");
          $("#projects").find("ul").find("li#task_list").addClass("active");
          $("#projects").find("ul").css("display","block");

          $("#allTaskFilterInput").on("input", function () {
              var text = $(this).val().toLowerCase();
              $("#allTaskTable tbody tr").each(function () {
                  var rowText = $(this).text().toLowerCase();
                  $(this).toggle(rowText.indexOf(text) > -1);
              });
          });
      });

 