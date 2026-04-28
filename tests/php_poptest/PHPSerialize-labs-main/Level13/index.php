<?php

/*
--- HelloCTF - 反序列化靶场 关卡 13 __toString()  --- 

__toString() 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class FLAG {
    function __toString() {
        echo "I'm a string ~~~";
        include 'flag.php';
        return $flag;
    }
}

$obj = new FLAG();

if(isset($_POST['o'])) {
    eval($_POST['o']);
} else {
    highlight_file(__FILE__);
}