<?php

/*
--- HelloCTF - 反序列化靶场 关卡 3 : 对象中值的权限 --- 

public（公有）：公有的类成员可以在任何地方被访问。
protected（受保护）：受保护的类成员则可以被其自身以及其子类和父类访问。(可继承)
private（私有）：私有的类成员则只能被其定义所在的类访问。(不可继承)

# -*- coding: utf-8 -*-
# @Author: 探姬
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class FLAG{
    public $public_flag = "HelloCTF{se3_me_";
    protected $protected_flag = "4nd_g3t_";
    private $private_flag = "mmmme}";

    function get_protected_flag(){
        return $this->protected_flag;
    }

    function get_private_flag(){
        return $this->private_flag;
    }
}

class SubFLAG extends FLAG{
    function show_protected_flag(){
        return $this->protected_flag;
    }

    function show_private_flag(){
        return $this->private_flag;
    }
}

$target = new FLAG();
$sub_target = new SubFLAG();

$code = $_POST['code'];

if(isset($code)){
    eval($code);
} else {
    highlight_file(source);
    echo "Trying to get FLAG...<br>";
    echo "Public Flag: ".$target->public_flag."<br>";

    echo "Protected Flag: Error: Cannot access protected property FLAG::$protected_flag in ? <br>";
    echo "Private Flag: Error: Cannot access private property FLAG::$private_flag in ? <br>";

    echo "...Wait,where is the flag? <br>";
}
?>
