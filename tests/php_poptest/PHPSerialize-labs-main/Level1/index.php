<?php 

/*
--- HelloCTF - 反序列化靶场 关卡 1 : 类的实例化 --- 

HINT：尝实例化下面的FLAG类吧！

# -*- coding: utf-8 -*-
# @Author: 探姬
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/


class FLAG{
    public $flag_string = "HelloCTF{OK_Now_y0u_c4n_se3_me}";

    function __construct(){
        echo $this->flag_string;
    }
}

$code = $_POST['code'];

if(isset($code)){

    if (stripos($code, "new") === false) {
        echo "Not This level!";
    } else {
       eval($code);
    }
}
else{
    highlight_file('source');
}
