<?php

/*
--- HelloCTF - 反序列化靶场 关卡 6 : 序列化规则_权限修饰 --- 

HINT：各有千秋~特别注意的权限修饰符x

# -*- coding: utf-8 -*-
# @Author: 探姬
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

$flag = "HelloCTF{P3rm1ssi0n_Modif_1s_1mp0rtant}";

class protectedKEY{
    protected $protected_key;

    function get_key(){
        return $this->protected_key;
    }
}

class privateKEY{
    private $private_key;

    function get_key(){
        return $this->private_key;
    }

}

highlight_file('demo');
echo "<br>See Carfully~<br>";
echo "protected's serialize: ".urlencode(serialize(new protectedKEY()))."<br>";
echo "private's serialize: ".urlencode(serialize(new privateKEY()))."<br>";


$protected_key = unserialize($_POST['protected_key']);
$private_key = unserialize($_POST['private_key']);

if(isset($_POST['protected_key'])&&isset($_POST['private_key'])){
    if($protected_key->get_key() == "protected_key" && $private_key->get_key() == "private_key"){
        echo $flag;
    } else {
        echo "We Call it %00_Contr0l_Characters_NULL!";
    }
} else {
    highlight_file('source');
}