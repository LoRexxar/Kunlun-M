<?php

/*
--- HelloCTF - 反序列化靶场 关卡 14 : __invoke() --- 

当尝试以调用函数的方式调用一个对象时，__invoke() 方法会被自动调用。例如 $obj()。

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class FLAG{
    function __invoke($x) {
        if ($x == 'get_flag') {
            include 'flag.php';
            echo $flag;
        }
    }
}

$obj = new FLAG();

if(isset($_POST['o'])) {
    eval($_POST['o']);
} else {
    highlight_file(__FILE__);
}