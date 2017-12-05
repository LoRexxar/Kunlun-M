<?php
    $a = $_GET['1'];
    echo ($param == 1? 90: $a);

    if($a = 1){
        $b = $_GET['b'];
    }else{
        $b = "test";
    }

    function c($c){
        echo $c;
        echo 'location.replace("'.$c.'");';
    }

    c("test".$b."ccc");
