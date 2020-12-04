$("input.register").click(function(){
	window.location.href='./register.php';
});
$("input.back").click(function(){
	window.location.href='./user.php';
});

function update(){
	
	var	email = document.getElementById("email").innerHTML.substr(7);
	var message = document.getElementById("mess").innerHTML.substr(9);
	var csrftoken = document.getElementById("csrft").innerHTML.substr(11);
	
	var x = new XMLHttpRequest();
	x.open('POST', './api/update.php', true); 
	x.setRequestHeader("Content-type","application/x-www-form-urlencoded");
	x.send('message='+message+'&email='+email+'&csrftoken='+csrftoken);
}

function edit(){
	var newWin = window.open("./edit.php?callback=EditProfile",'','width=600,height=600');
	var loop = setInterval(function() { 
	  if(newWin.closed) {  
	    clearInterval(loop);  
	    update();
	  }  
	}, 1000);

};

function random(){
	var newWin = window.open("./edit.php?callback=RandomProfile",'','width=600,height=600');
	var loop = setInterval(function() { 
	  if(newWin.closed) {  
	    clearInterval(loop);  
	    update();
	  }  
	}, 1000);

};