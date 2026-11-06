 

      $(document).ready(function () {
          $("#dashboard").removeClass("active menu-open");
          $("#dashboard").find("ul li").removeClass("active");
          $("#tasks").addClass("menu-open");
          $("#projects").addClass("menu-open");
          $("#projects").find("ul").find("li#task_list").addClass("active");
          $("#projects").find("ul").css("display","block");
          $("#tasks").find("ul").css("display","block");
      });

 