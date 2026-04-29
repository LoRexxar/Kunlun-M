<?php

/*
--- HelloCTF - 反序列化靶场 关卡 18 : 字符串逃逸基础 --- 

序列化和反序列化的规则特性,字符串尾部判定：进行反序列化时，当成员属性的数量，名称长度，内容长度均一致时，程序会以 ";}" 作为字符串的结尾判定。

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

highlight_file('source');

class Demo {
    public $a = "Hello";
    public $b = "CTF";
    public $key = 'GET_FLAG";}FAKE_FLAG';
}

class FLAG {

}

$serliseStringDemo = serialize(new Demo());
echo "SerliseStringDemo:'".$serliseStringDemo."'<br>";

echo "Change SOMETHING TO GET FLAG";

$target = $_GET['target'];
$change = $_GET['change'];

$serliseStringFLAG = str_replace($target, $change, $serliseStringDemo);

$FLAG = unserialize($serliseStringFLAG);

if ($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG') {
    include 'flag.php';
    echo $flag;
} else {
    echo "Your serliaze string is ".$serliseStringFLAG . "<br> And Here is ";
    var_dump($FLAG);
}