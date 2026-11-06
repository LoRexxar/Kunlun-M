 

$(document).ready(function(){
    $("#dashboard").removeClass("active menu-open");
    $("#dashboard").find("ul li").removeClass("active");
    $("#tampers").addClass("menu-open");
    $("#tampers").find("ul").find("li#tamper_list").addClass("active");
    $("#tampers").find("ul").css("display","block");
});

  

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#tampers").addClass("menu-open");
          $("#tampers").find("ul").find("li#tamper_list").addClass("active");
          $("#tampers").find("ul").css("display","block");

          var $list = $("#tamperList");
          var $detailTitle = $("#tamperDetailTitle");
          var detailCodeEl = document.getElementById("tamperDetailCode");
          var sourceCache = {};
          var sourceLoaded = false;

          function loadAllSources(callback) {
              if (sourceLoaded) { callback(); return; }
              $.get("{% url 'dashboard:tamper_sources' %}", function (data) {
                  sourceCache = data;
                  sourceLoaded = true;
                  callback();
              }).fail(function () {
                  callback();
              });
          }

          function setActive($btn) {
              $list.find(".km-tamper-item").removeClass("is-active");
              $btn.addClass("is-active");
          }

          function showDetail($btn) {
              var name = $btn.attr("data-name");
              var lang = $btn.attr("data-lang") || "";
              var title = $btn.find(".km-tamper-item-name").text() || name;
              $detailTitle.text(title + (lang ? "  [" + lang + "]" : ""));
              detailCodeEl.textContent = sourceCache[name] || "";
              if (window.Prism) {
                  Prism.highlightElement(detailCodeEl);
              }
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
                  $detailTitle.text("没有匹配的拓展插件");
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

          // 点击 tamper 子项
          $list.on("click", ".km-tamper-item", function (e) {
              e.stopPropagation();
              setActive($(this));
              showDetail($(this));
          });

          // 搜索过滤
          $("#tamperFilterInput").on("input", function () {
              var q = ($(this).val() || "").toLowerCase().trim();
              $list.find(".km-tamper-group").each(function () {
                  var $group = $(this);
                  var lang = ($group.attr("data-lang") || "").toLowerCase();
                  var hasMatch = !q;
                  $group.find(".km-tamper-item").each(function () {
                      var name = ($(this).attr("data-name") || "");
                      var ok = !q || name.indexOf(q) > -1 || lang.indexOf(q) > -1;
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
          $("#tamperCopyBtn").on("click", function () {
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

          // 初始：折叠所有分组，加载源码后展开第一个
          $list.find(".km-tamper-children").hide();
          $list.find(".km-tamper-group").addClass("is-collapsed");
          $list.find(".km-tamper-lang-arrow").text("▶");
          loadAllSources(function () {
              pickFirstVisible();
          });
      });

 