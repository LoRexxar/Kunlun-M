<?php
class a{

    function __construct($test=1,$message="2333"){
        $this->test = $test;
        $this->message = $message;
    }
    function __toString(){
    	$b = $_GET['b'];
    	return $b;
    }

    function eval_function($a){
        eval($a);
    }

    function eval_function2(){
        $a = $_GET['a'];
        eval($a);
    }

    function eval_function3(){
        eval($this->test);
    }

    function eval_function4(){
        eval($this->message);
    }
}


$x = $_GET['a'];
$y = "echo 233;";

$A = new a($x, $y);
$A->eval_function($x);
$A->eval_function2();
$A->eval_function3();
$A->eval_function4();

$z = $A;
eval($z);


function d($a){
    eval($a);
}

d($_GET['a']);