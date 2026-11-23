(function () {
  function setSidebarDefaultOpen() {
    document.body.classList.remove('sidebar-collapsed');
    if (window.matchMedia('(max-width: 900px)').matches) {
      document.body.classList.add('sidebar-open');
    }
  }

  function toggleSidebar() {
    if (window.matchMedia('(max-width: 900px)').matches) {
      document.body.classList.toggle('sidebar-open');
      return;
    }
    document.body.classList.toggle('sidebar-collapsed');
  }

  function initSidebarToggle() {
    var btn = document.querySelector('.sidebar-toggle');
    if (!btn) return;
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      toggleSidebar();
    });
  }

  function initTreeMenus() {
    var treeRoots = document.querySelectorAll('.sidebar-menu .treeview > a');
    for (var i = 0; i < treeRoots.length; i++) {
      treeRoots[i].addEventListener('click', function (e) {
        e.preventDefault();
        this.parentElement.classList.toggle('menu-open');
        var menu = this.parentElement.querySelector('.treeview-menu');
        if (menu) {
          menu.style.display = this.parentElement.classList.contains('menu-open') ? 'block' : '';
        }
      });
    }

    var treeItems = document.querySelectorAll('.sidebar-menu .treeview');
    for (var j = 0; j < treeItems.length; j++) {
      treeItems[j].classList.add('menu-open');
      var child = treeItems[j].querySelector('.treeview-menu');
      if (child) {
        child.style.display = 'block';
      }
    }
  }

  function initUserDropdown() {
    var toggles = document.querySelectorAll('.dropdown-toggle');
    for (var i = 0; i < toggles.length; i++) {
      toggles[i].addEventListener('click', function (e) {
        e.preventDefault();
        var parent = this.parentElement;
        if (parent) {
          parent.classList.toggle('open');
        }
      });
    }

    document.addEventListener('click', function (e) {
      if (!e.target.closest('.dropdown')) {
        var opens = document.querySelectorAll('.dropdown.open');
        for (var i = 0; i < opens.length; i++) {
          opens[i].classList.remove('open');
        }
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    setSidebarDefaultOpen();
    initSidebarToggle();
    initTreeMenus();
    initUserDropdown();
  });
})();
