 

(function () {
  var authModal = document.getElementById('auth-modal');
  if (!authModal) {
    return;
  }

  function switchAuthPanel(target) {
    var tabs = authModal.querySelectorAll('.auth-tab');
    var panels = authModal.querySelectorAll('.auth-panel');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].classList.toggle('is-active', tabs[i].getAttribute('data-auth-target') === target);
    }
    for (var j = 0; j < panels.length; j++) {
      panels[j].classList.toggle('is-hidden', panels[j].getAttribute('data-auth-panel') !== target);
    }
  }

  function openAuthModal(target) {
    switchAuthPanel(target || 'login');
    authModal.classList.add('is-active');
    document.body.classList.add('modal-open');
  }

  function closeAuthModal() {
    authModal.classList.remove('is-active');
    document.body.classList.remove('modal-open');
  }

  var openTriggers = document.querySelectorAll('.js-open-auth');
  for (var i = 0; i < openTriggers.length; i++) {
    openTriggers[i].addEventListener('click', function (e) {
      e.preventDefault();
      openAuthModal(this.getAttribute('data-auth-target') || 'login');
    });
  }

  var closeTriggers = authModal.querySelectorAll('.js-close-auth, .modal-background');
  for (var j = 0; j < closeTriggers.length; j++) {
    closeTriggers[j].addEventListener('click', closeAuthModal);
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
 