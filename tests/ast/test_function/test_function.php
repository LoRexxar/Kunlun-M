<?php

$s = escapeshellcmd($_GET['a']);
$s2 = $_GET['a'];
$s3 = test($_GET['a']);

eval($s);
eval($s2);


function b($a){
    eval($a);
}

 b($s3);

$id = addslashes($_GET['id']);
$id2 = $_GET['id'];

$query = "select name from users where id =$id";
$query2 = "select name from users where id =$id2";