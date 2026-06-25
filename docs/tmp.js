 

    (function(){
      var q = document.getElementById('q');
      var sevBtns = Array.prototype.slice.call(document.querySelectorAll('[data-filter-sev]'));
      var rows = Array.prototype.slice.call(document.querySelectorAll('tr.row'));
      var items = Array.prototype.slice.call(document.querySelectorAll('details.item'));
      var activeSev = 'all';
      function apply(){
        var text = (q.value || '').toLowerCase().trim();
        function ok(el){
          var sev = el.getAttribute('data-sev') || 'unknown';
          var hay = el.getAttribute('data-text') || '';
          if(activeSev !== 'all' && sev !== activeSev) return false;
          if(text && hay.indexOf(text) === -1) return false;
          return true;
        }
        rows.forEach(function(r){ r.style.display = ok(r) ? '' : 'none'; });
        items.forEach(function(d){ d.style.display = ok(d) ? '' : 'none'; });
      }
      sevBtns.forEach(function(b){
        b.addEventListener('click', function(){
          sevBtns.forEach(function(x){ x.classList.remove('active'); });
          b.classList.add('active');
          activeSev = b.getAttribute('data-filter-sev') || 'all';
          apply();
        });
      });
      q.addEventListener('input', apply);
      document.getElementById('expand').addEventListener('click', function(){ items.forEach(function(d){ d.open = true; }); });
      document.getElementById('collapse').addEventListener('click', function(){ items.forEach(function(d){ d.open = false; }); });
      apply();
    })();
  
 