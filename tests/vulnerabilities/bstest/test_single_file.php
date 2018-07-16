<?php
include("test1.php");
require "test2.php";


# 不可控
$url = "phpinfo()";
eval($url);

# 可控
$url = $_GET['a'];
eval($url);

# 可控
eval($url2);

# 不可控
eval($url3);

# 经过一次
$url4 = $test;
eval($url4);

# 函数
 function test(){
     return $_GET['a'];
 }

$url5 = test();
eval($url5);

$a = 1;
if($a == 1){
    eval($url4);
}

if($a == 1){
    $test = $_GET['a'];

    $query = "select id, xxx from users where name = $test";
    mysql_query($test);
}else{
    $query = "select id, xxx from users";
}
?>
