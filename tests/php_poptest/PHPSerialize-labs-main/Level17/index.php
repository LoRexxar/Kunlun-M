<?php

/*
--- HelloCTF - 反序列化靶场 关卡 17 : 字符串逃逸基础 --- 

序列化和反序列化的规则特性_无中生有：当成员属性的实际数量符合序列化字符串中对应属性值时，似乎不会做任何检查？

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class A {

}
echo "Class A is NULL: '".serialize(new A())."'<br>";

class B {
    public $a = "Hello";
    protected $b = "CTF";
    private $c = "FLAG{TEST}";
}
echo "Class B is a class with 3 properties: '".serialize(new B())."'<br>";

$serliseString = serialize(new B());

$serliseString = str_replace('B', 'A', $serliseString);

echo "After replace B with A,we unserialize it and dump :<br>";
var_dump(unserialize($serliseString));

if(isset($_POST['o'])) {
    $a = unserialize($_POST['o']);
    if ($a instanceof A && $a->helloctfcmd == "get_flag") {
        include 'flag.php';
        echo $flag;
    } else {
        echo "what's rule?";
    }
} else {
    highlight_file(__FILE__);
}
