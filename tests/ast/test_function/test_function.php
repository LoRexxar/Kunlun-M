<?php

$s = escapeshellcmd($_GET['a']);
$s2 = $_GET['a'];
$s3 = test($_GET['a']);

eval($s);
eval($s2);
eval($s3);

$id = addslashes($_GET['id']);

$query = "select * from users where id = ".$id;
mysql_query($query);