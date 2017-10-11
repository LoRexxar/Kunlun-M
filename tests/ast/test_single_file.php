<?php
include("test1.php");
include "test2.php";


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
$url5 = test();
eval($url5);
