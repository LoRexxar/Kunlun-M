<?php

$s = escapeshellcmd($_GET['a']);
$s2 = $_GET['a'];

eval($s);
eval($s2);


$id = addslashes($_GET['id']);

$query = "select * from users where id = ".$id;
mysql_query($query);