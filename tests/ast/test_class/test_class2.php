<?php
class a2{

    function __construct($test=1,$message="2333"){
        $this->test = $test;
        $this->message = $message;
    }
    function __toString(){
    	$b = $_GET['b'];
    	return $b;
    }

    function eval_function($a){
        curl_setopt($curl, CURLOPT_URL, $a);
    }

    function eval_function2(){
        $a = $_GET['a'];
        curl_setopt($curl, CURLOPT_URL, $a);
    }

    function eval_function3(){
        curl_setopt($curl, CURLOPT_URL, $this->test);
    }

    function eval_function4(){
        curl_setopt($curl, CURLOPT_URL, $this->message);
    }
}


$x = $_GET['a'];
$y = "test";

$A = new a2($x, $y);
$A->eval_function($y);
$A->eval_function2();
$A->eval_function3();
$A->eval_function4();

$z = $A;
curl_setopt($curl, CURLOPT_URL, $z);