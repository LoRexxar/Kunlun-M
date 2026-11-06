 

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#rules").addClass("menu-open");
          $("#rules").find("ul").find("li#rule_list").addClass("active");
          $("#rules").find("ul").css("display","block");
      });

  

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#rules").addClass("menu-open");
          $("#rules").find("ul").find("li#rule_list").addClass("active");
          $("#rules").find("ul").css("display","block");

          var $list = $("#ruleList");
          var $detailTitle = $("#ruleDetailTitle");
          var detailCodeEl = document.getElementById("ruleDetailCode");
          var cache = {};
          var currentId = null;

          function loadSource(id, callback) {
              if (cache[id]) { callback(cache[id]); return; }
              $.get("{% url 'dashboard:rule_source' 0 %}".replace(/\/0$/, "/" + id), function (data) {
                  cache[id] = data;
                  callback(data);
              }).fail(function () {
                  callback({ source: '', error: true });
              });
          }

          function setActive($btn) {
              $list.find(".km-tamper-item").removeClass("is-active");
              $btn.addClass("is-active");
          }

          function showDetail($btn) {
              var id = $btn.attr("data-id");
              var title = $btn.find(".km-tamper-item-name").text() + " - " + $btn.find(".km-tamper-item-sub").text();
              $detailTitle.text(title);
              detailCodeEl.textContent = "";
              currentId = id;
              loadSource(id, function (data) {
                  // 确保用户还在看同一条规则
                  if (currentId !== id) return;
                  detailCodeEl.textContent = data.source || "(源文件未找到)";
                  if (window.Prism) Prism.highlightElement(detailCodeEl);
              });
          }

          function pickFirstVisible() {
              var $first = $list.find(".km-tamper-item:visible").first();
              if ($first.length) {
                  var $group = $first.closest(".km-tamper-group");
                  $group.removeClass("is-collapsed");
                  $group.find(".km-tamper-children").show();
                  $group.find(".km-tamper-lang-arrow").text("▼");
                  setActive($first);
                  showDetail($first);
              } else {
                  $list.find(".km-tamper-item").removeClass("is-active");
                  $detailTitle.text("没有匹配的规则");
                  detailCodeEl.textContent = "";
              }
          }

          // 语言分组折叠
          $list.on("click", ".km-tamper-lang", function (e) {
              e.stopPropagation();
              var $group = $(this).closest(".km-tamper-group");
              var $children = $group.find(".km-tamper-children");
              var $arrow = $(this).find(".km-tamper-lang-arrow");
              $children.slideToggle(150);
              $group.toggleClass("is-collapsed");
              $arrow.text($group.hasClass("is-collapsed") ? "▶" : "▼");
          });

          // 点击规则
          $list.on("click", ".km-tamper-item", function (e) {
              e.stopPropagation();
              setActive($(this));
              showDetail($(this));
          });

          // 搜索过滤
          $("#ruleFilterInput").on("input", function () {
              var q = ($(this).val() || "").toLowerCase().trim();
              $list.find(".km-tamper-group").each(function () {
                  var $group = $(this);
                  var lang = ($group.attr("data-lang") || "").toLowerCase();
                  var hasMatch = !q;
                  $group.find(".km-tamper-item").each(function () {
                      var name = ($(this).attr("data-name") || "");
                      var sub = ($(this).find(".km-tamper-item-sub").text() || "").toLowerCase();
                      var ok = !q || name.indexOf(q) > -1 || lang.indexOf(q) > -1 || sub.indexOf(q) > -1;
                      $(this).toggle(ok);
                      if (ok) hasMatch = true;
                  });
                  $group.toggle(hasMatch);
                  if (q && hasMatch) {
                      $group.removeClass("is-collapsed");
                      $group.find(".km-tamper-children").show();
                      $group.find(".km-tamper-lang-arrow").text("▼");
                  }
              });
              pickFirstVisible();
          });

          // 复制
          $("#ruleCopyBtn").on("click", function () {
              var text = detailCodeEl.textContent || "";
              if (!text) return;
              if (navigator.clipboard && navigator.clipboard.writeText) {
                  navigator.clipboard.writeText(text);
              } else {
                  var $tmp = $("<textarea>");
                  $("body").append($tmp);
                  $tmp.val(text).select();
                  document.execCommand("copy");
                  $tmp.remove();
              }
          });

          // 初始化：默认折叠所有语言分组
          $list.find(".km-tamper-children").hide();
          $list.find(".km-tamper-group").addClass("is-collapsed");
          $list.find(".km-tamper-lang-arrow").text("▶");

          // 展开第一个分组并选中第一条规则
          pickFirstVisible();
      });

  

$('#aiRuleGo').on('click', function(){
  var out = document.getElementById('aiRuleOut');
  var sink = $('#aiRuleSink').val().trim();
  if(!sink){ out.innerHTML='<div class="alert alert-warning">请填写 sink</div>'; return; }
  out.innerHTML = '<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> AI 正在生成规则...</div>';
  var body = 'language=' + encodeURIComponent($('#aiRuleLang').val()) + '&sink=' + encodeURIComponent(sink) + '&extra=' + encodeURIComponent($('#aiRuleExtra').val()) + '&csrfmiddlewaretoken=' + ($('[name=csrfmiddlewaretoken]').val() || '');
  fetch('{% url "dashboard:ai_rule_generate" %}', {method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRFToken':body.match(/csrfmiddlewaretoken=([^&]*)/)[1]},
    body: body, credentials:'same-origin'})
  .then(r=>r.json()).then(function(res){
    if(res.not_configured){ out.innerHTML='<div class="alert alert-warning"><i class="fa fa-magic"></i> AI 功能未配置。<a href="/dashboard/ai/settings">去配置 AI</a> 后可使用规则生成。</div>'; return; }
    if(res.code!==200){ out.innerHTML='<div class="alert alert-danger">'+(res.message||'生成失败')+'</div>'; return; }
    var d=res.data;
    out.innerHTML =
      '<table class="table table-sm"><tbody>'+
      '<tr><th style="width:120px;">规则名</th><td>'+esc(d.rule_name)+'</td></tr>'+
      '<tr><th>mode</th><td>'+esc(d.match_mode)+'</td></tr>'+
      '<tr><th>match</th><td><code>'+esc(d.match)+'</code> '+(d.match_valid?'<span style="color:#16a34a;">✓ 可编译</span>':'<span style="color:#dc2626;">✗ '+esc(d.match_error||'')+'</span>')+'</td></tr>'+
      '<tr><th>unmatch</th><td><code>'+esc(d.unmatch||'-')+'</code></td></tr>'+
      '<tr><th>等级</th><td>'+esc(d.level)+'</td></tr>'+
      '<tr><th>说明</th><td>'+esc(d.description||'')+'</td></tr>'+
      '<tr><th>设计理由</th><td>'+esc(d.reason||'')+'</td></tr>'+
      '</tbody></table>'+
      '<div style="margin-top:10px;"><button class="btn btn-success btn-sm" id="aiRuleSave" '+(d.match_valid?'':'disabled')+'><i class="fa fa-save"></i> 落库并同步</button> '+
      '<span class="text-muted" style="font-size:12px;">写入 rules/ 目录并同步数据库（等价 CLI generate rule --sync）</span></div>'+
      '<div id="aiRuleSaveOut" style="margin-top:8px;"></div>';
    var payload = {language: $('#aiRuleLang').val(), rule_name: d.rule_name, match_mode: d.match_mode,
                   match: d.match, unmatch: d.unmatch, description: d.description, level: d.level};
    $('#aiRuleSave').on('click', function(){
      var so = document.getElementById('aiRuleSaveOut');
      so.innerHTML = '<div class="text-muted"><i class="fa fa-spinner fa-spin"></i> 正在写入规则文件并同步数据库...</div>';
      fetch('{% url "dashboard:ai_rule_generate" %}', {method:'PUT',
        headers:{'Content-Type':'application/json','X-CSRFToken': getCookie('csrftoken') || '{{ csrf_token }}'},
        body: JSON.stringify(payload), credentials:'same-origin'})
      .then(r=>r.json()).then(function(res){
        if(res.code===200 && res.data.synced){
          so.innerHTML = '<div class="alert alert-success" style="margin-bottom:0;">已落库：CVI-'+res.data.svid+'（'+esc(res.data.rule_path)+'），数据库已同步。刷新规则列表可见。</div>';
        } else if(res.code===200){
          so.innerHTML = '<div class="alert alert-warning" style="margin-bottom:0;">文件已写入 CVI-'+res.data.svid+'，但 DB 同步失败：'+esc(res.data.sync_error||'')+'</div>';
        } else {
          so.innerHTML = '<div class="alert alert-danger" style="margin-bottom:0;">'+esc(res.message||'落库失败')+'</div>';
        }
      }).catch(e=>{ so.innerHTML='<div class="alert alert-danger">请求失败: '+e+'</div>'; });
    });
  }).catch(e=>{ out.innerHTML='<div class="alert alert-danger">请求失败: '+e+'</div>'; });
});
function esc(s){ return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function getCookie(n){ var m = document.cookie.match(new RegExp('(?:^|; )'+n+'=([^;]*)')); return m ? decodeURIComponent(m[1]) : ''; }

 