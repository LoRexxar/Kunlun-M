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

