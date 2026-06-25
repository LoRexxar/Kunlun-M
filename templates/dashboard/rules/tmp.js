 

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

 