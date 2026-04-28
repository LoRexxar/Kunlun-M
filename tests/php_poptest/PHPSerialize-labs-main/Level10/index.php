<?php

/*
--- HelloCTF - 反序列化靶场 关卡 10 : weakup! --- 

unserialize() 会检查是否存在一个 __wakeup() 方法。如果存在，则会先调用 __wakeup 方法，预先准备对象需要的资源。
除开构造和析构函数，这应该是你第一个真正意义上开始接触的魔术方法，此后每一个魔术方法对应的题目我都会在这里介绍。
当然你也可以直接查阅PHP官网文档 - 魔术方法部分：https://www.php.net/manual/zh/language.oop5.magic.php

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

error_reporting(0);

class FLAG{
    function __wakeup() {
        include 'flag.php';
        echo $flag;
    }
}

if(isset($_POST['o']))
{
    unserialize($_POST['o']);
}else {
    highlight_file(__FILE__);
}
?>
