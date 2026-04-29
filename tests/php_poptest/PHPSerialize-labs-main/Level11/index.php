<?php

/*
--- HelloCTF - 反序列化靶场 关卡 11 : Bypass weakup! --- 

CVE-2016-7124 - PHP5 < 5.6.25 / PHP7 < 7.0.10
在该漏洞中，当序列化字符串中对象属性的值大于真实属性值时便会跳过__wakeup的执行。

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

error_reporting(0);

include 'flag.php';

class FLAG {
    public $flag = "FAKEFLAG";

    public function  __wakeup(){
        global $flag;
        $flag = NULL;
    }
    public function __destruct(){
        global $flag;
        if ($flag !== NULL) {
            echo $flag;
        }else
        {
            echo "sorry,flag is gone!";
        }
    }
}

if(isset($_POST['o']))
{
    unserialize($_POST['o']);
}else {
    highlight_file(__FILE__);
    phpinfo();
}

?>
