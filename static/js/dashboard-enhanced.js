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
    body.classList.remove('light-mode', 'dark-mode');
    body.classList.add(mode + '-mode');
    localStorage.setItem('dashboard_theme', mode);
    var icon = document.getElementById('themeIcon');
    if (icon) {
      icon.className = mode === 'dark' ? 'fa fa-moon-o' : 'fa fa-sun-o';
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

  function updateOverview() {
    var panel = document.getElementById('overviewPanel');
    if (!panel) return;

    $.getJSON('/dashboard/overview', function (resp) {
      if (resp.status !== 'ok') return;

      $('#statusSuccess').text(resp.task_status.success);
      $('#statusRunning').text(resp.task_status.running);
      $('#statusError').text(resp.task_status.error);
      $('#statusOther').text(resp.task_status.other);
      $('#lastScanTime').text(resp.latest_scan_time || 'N/A');

      if (resp.latest_task) {
        $('#lastTaskName').text(resp.latest_task.task_name || ('Task #' + resp.latest_task.id));
      }
    });
  }

  $(document).ready(function () {
    initTheme();
    initQuickSearch();
    initTaskFilter();

    var refreshBtn = document.getElementById('refreshOverview');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', function () {
        updateOverview();
      });
      updateOverview();
    }
  });
})();
