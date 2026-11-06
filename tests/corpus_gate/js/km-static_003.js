(function () {
  function navigateQuick(keyword) {
    var value = (keyword || '').toLowerCase();
    if (!value) return;
    var routes = [
      { keys: ['task', '任务'], url: '/dashboard/tasks/list' },
      { keys: ['project', '项目'], url: '/dashboard/projects/list' },
      { keys: ['rule', '规则'], url: '/dashboard/rules/list' },
      { keys: ['vendor', '依赖'], url: '/dashboard/vendors/list' },
      { keys: ['tamper'], url: '/dashboard/tampers/list' },
      { keys: ['doc', '文档'], url: '/dashboard/docs' },
      { keys: ['user', 'profile'], url: '/dashboard/userinfo' }
    ];

    for (var i = 0; i < routes.length; i++) {
      if (routes[i].keys.some(function (k) { return value.indexOf(k) > -1; })) {
        window.location.href = routes[i].url;
        return;
      }
    }
  }

  function setTheme(mode) {
    var body = document.body;
    body.classList.remove('light-mode', 'dark-mode', 'theme-dark', 'theme-light');
    body.classList.add(mode + '-mode');
    body.classList.add(mode === 'dark' ? 'theme-dark' : 'theme-light');
    localStorage.setItem('dashboard_theme', mode);
    var icon = document.getElementById('themeIcon');
    if (icon) {
      icon.className = mode === 'dark' ? 'fa fa-sun-o' : 'fa fa-moon-o';
    }
    var btn = document.getElementById('themeToggle');
    var text = document.getElementById('themeText');
    var nextLabel = mode === 'dark' ? '浅色' : '深色';
    var nextTitle = mode === 'dark' ? '切换到浅色模式' : '切换到深色模式';
    if (text) {
      text.textContent = nextLabel;
    }
    if (btn) {
      btn.setAttribute('title', nextTitle);
      btn.setAttribute('aria-label', nextTitle);
      btn.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
    }
  }

  function initTheme() {
    var mode = localStorage.getItem('dashboard_theme') || 'light';
    setTheme(mode);

    var btn = document.getElementById('themeToggle');
    if (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        var nextMode = document.body.classList.contains('dark-mode') ? 'light' : 'dark';
        setTheme(nextMode);
      });
    }
  }

  function initQuickSearch() {
    var quickSearch = document.getElementById('quickSearch');
    if (!quickSearch) return;

    quickSearch.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        navigateQuick(quickSearch.value);
      }
    });
  }

  function initTaskFilter() {
    var input = document.getElementById('taskFilterInput');
    var table = document.getElementById('latestTaskTable');
    if (!input || !table) return;

    input.addEventListener('input', function () {
      var text = input.value.toLowerCase();
      var rows = table.querySelectorAll('tbody tr');
      rows.forEach(function (row) {
        row.style.display = row.innerText.toLowerCase().indexOf(text) > -1 ? '' : 'none';
      });
    });
  }

  function splitDateTime(raw) {
    var text = (raw || '').trim();
    if (!text) return null;
    var m = text.match(/^(\d{4}[-\/]\d{2}[-\/]\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)/);
    if (m) return { date: m[1].replace(/\//g, '-'), time: m[2] };
    return null;
  }

  function formatTimeCells(root) {
    var scope = root || document;
    var cells = scope.querySelectorAll('.km-td-time');
    cells.forEach(function (cell) {
      var raw = cell.getAttribute('data-time') || cell.textContent;
      raw = (raw || '').trim();
      if (!raw) return;
      cell.setAttribute('title', raw);
      var split = splitDateTime(raw);
      while (cell.firstChild) cell.removeChild(cell.firstChild);
      if (split) {
        var d = document.createElement('div');
        d.className = 'km-time-date';
        d.textContent = split.date;
        var t = document.createElement('div');
        t.className = 'km-time-clock';
        t.textContent = split.time;
        cell.appendChild(d);
        cell.appendChild(t);
      } else {
        var r = document.createElement('div');
        r.className = 'km-time-raw';
        r.textContent = raw;
        cell.appendChild(r);
      }
    });
  }

  function updateOverview() {
    var panel = document.getElementById('overviewPanel');
    if (!panel) return;

    $.getJSON('/dashboard/overview', function (resp) {
      if (resp.status !== 'ok') return;

      $('#statusSuccess').text(resp.task_status.success);
      $('#statusRunning').text(resp.task_status.running);
      $('#statusError').text(resp.task_status.error);
      $('#statusOther').text(resp.task_status.other);
      $('#lastScanTime').text(resp.latest_scan_time || '无');

      if (resp.latest_task) {
        $('#lastTaskName').text(resp.latest_task.task_name || ('任务 #' + resp.latest_task.id));
      }
    });
  }

  $(document).ready(function () {
    initTheme();
    initQuickSearch();
    initTaskFilter();
    formatTimeCells(document);

    var refreshBtn = document.getElementById('refreshOverview');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', function () {
        updateOverview();
      });
      updateOverview();
    }
  });
})();
