 

(function () {
  var authModal = document.getElementById('auth-modal');
  if (!authModal) {
    return;
  }

  var bsModal = null;
  if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
    bsModal = bootstrap.Modal.getOrCreateInstance(authModal, { backdrop: true });
  }

  function switchAuthPanel(target) {
    var tabs = authModal.querySelectorAll('.auth-tab');
    var panels = authModal.querySelectorAll('.auth-panel');
    var resolved = target || 'login';
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].classList.toggle('active', tabs[i].getAttribute('data-auth-target') === resolved);
    }
    for (var j = 0; j < panels.length; j++) {
      panels[j].classList.toggle('d-none', panels[j].getAttribute('data-auth-panel') !== resolved);
    }
  }

  function openAuthModal(target) {
    switchAuthPanel(target);
    if (bsModal) {
      bsModal.show();
    } else {
      authModal.classList.add('show');
      authModal.style.display = 'block';
      authModal.removeAttribute('aria-hidden');
      document.body.classList.add('modal-open');
    }
  }

  function closeAuthModal() {
    if (bsModal) {
      bsModal.hide();
    } else {
      authModal.classList.remove('show');
      authModal.style.display = '';
      authModal.setAttribute('aria-hidden', 'true');
      document.body.classList.remove('modal-open');
    }
  }

  var openTriggers = document.querySelectorAll('.js-open-auth');
  for (var i = 0; i < openTriggers.length; i++) {
    openTriggers[i].addEventListener('click', function (e) {
      e.preventDefault();
      openAuthModal(this.getAttribute('data-auth-target') || 'login');
    });
  }

  var closeTriggers = authModal.querySelectorAll('.js-close-auth');
  for (var j = 0; j < closeTriggers.length; j++) {
    closeTriggers[j].addEventListener('click', function (e) {
      e.preventDefault();
      closeAuthModal();
    });
  }

  var tabs = authModal.querySelectorAll('.auth-tab');
  for (var k = 0; k < tabs.length; k++) {
    tabs[k].addEventListener('click', function () {
      switchAuthPanel(this.getAttribute('data-auth-target'));
    });
  }

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      closeAuthModal();
    }
  });

{% if auth_modal == 'register' %}
  openAuthModal('register');
{% elif auth_modal == 'login' %}
  openAuthModal('login');
{% endif %}
})();

(function () {
  var numbers = document.querySelectorAll('.km-stat-number');
  if (!numbers.length) { return; }

  function animate(el) {
    var raw = el.getAttribute('data-target') || '0';
    var target = parseFloat(raw);
    var decimals = (raw.split('.')[1] || '').length;
    var duration = 1600;
    var startTime = null;

    function step(ts) {
      if (startTime === null) { startTime = ts; }
      var progress = Math.min((ts - startTime) / duration, 1);
      var eased = 1 - Math.pow(1 - progress, 3);
      var current = target * eased;
      el.textContent = decimals > 0 ? current.toFixed(decimals) : Math.floor(current);
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        el.textContent = decimals > 0 ? target.toFixed(decimals) : target;
      }
    }
    requestAnimationFrame(step);
  }

  var started = false;
  function start() {
    if (started) { return; }
    started = true;
    for (var i = 0; i < numbers.length; i++) { animate(numbers[i]); }
  }

  if (document.readyState === 'complete') {
    setTimeout(start, 150);
  } else {
    window.addEventListener('load', function () { setTimeout(start, 150); });
  }
})();

  

document.getElementById("login-btn").addEventListener("click", function(e){
  e.preventDefault();
  e.stopPropagation();
  document.getElementById("login").submit();
  return false;
});

  

document.getElementById("reg-btn").addEventListener("click", function(e){
  e.preventDefault();
  e.stopPropagation();
  document.getElementById("reg").submit();
  return false;
});

document.getElementById("cancel-btn").addEventListener("click", function(e){
  e.preventDefault();
  e.stopPropagation();
  location.href = '{% url 'index:index' %}';
  return false;
});

  
{{ js }}
 