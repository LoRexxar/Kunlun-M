<?php

/*
--- HelloCTF - 反序列化靶场 关卡 2 : 对象中值的传递 --- 

HINT：尝试将flag传递出来吧~

# -*- coding: utf-8 -*-
# @Author: 探姬
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

error_reporting(0);

 $flag_string = "HelloCTF{I_giv3_t0_y0u&y0u_giv3_t0_me}";

 class FLAG{
        public $free_flag = "???";

        function get_free_flag(){
            return $this->free_flag;
        }
    }
$target = new FLAG();

$code = $_POST['code'];

if(isset($code)){
       eval($code);
       echo "Now Flag is ". $target->get_free_flag() ."<br>";
}
else{
    highlight_file('source');
    echo "Now Flag is ". $target->get_free_flag() ."<br>";
}
