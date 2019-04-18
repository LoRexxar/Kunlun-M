<?php

$s = escapeshellcmd($_GET['a']);
$s2 = $_GET['a'];
$s3 = test($_GET['a']);

eval($s);
eval($s2);


function b($a){
    eval($a);
}

function curl($url){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_exec($ch);
    curl_close($ch);
}

$url = $_GET['url'];
if (!empty($url)){
    curl($cmd);
}

eval($cmd);

b($s3);

$id = addslashes($_GET['id']);
$id2 = $_GET['id'];

$query = "select name from users where id =$id";
$query2 = "select name from users where id =$id2";