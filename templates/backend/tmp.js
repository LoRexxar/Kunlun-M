 

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#tasks").addClass("menu-open");
          $("#tasks").find("ul").find("li#task_list").addClass("active");
          $("#tasks").find("ul").css("display","block");
      });

  

function delVul(vulid){
  $.get("{% url 'dashboard:vul_del' 654321 %}".replace('654321', vulid), function(data){
      if(data.code == 200){
          location.reload();
      }else{
          alert(data.message)
      }
  })
}
$(document).ready(function () {
  $("#dashboard").removeClass("active menu-open");
  $("#dashboard").find("ul li").removeClass("active");
  $("#tasks").addClass("menu-open");
  $("#tasks").find("ul").find("li#task_list").addClass("active");
  $("#tasks").find("ul").css("display","block");

  $("button#dlog").click(function () {
      location.href="{% url 'backend:debuglog' task.id %}?token={{ visit_token }}";
  })

  $("button#ddlog").click(function () {
      location.href="{% url 'backend:downloadlog' task.id %}?token={{ visit_token }}";
  })
});

 