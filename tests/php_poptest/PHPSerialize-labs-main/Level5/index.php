<?php
/*
--- HelloCTF - 反序列化靶场 关卡 5 : 序列化规则 --- 

HINT：各有千秋~

# -*- coding: utf-8 -*-
# @Author: 探姬
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class a_class{
    public $a_value = "HelloCTF";
}
$a_array = array(a=>"Hello",b=>"CTF");
$a_string = "HelloCTF";
$a_number = 678470;
$a_boolean = true;
$a_null = null;

highlight_file('demo');

echo "<br>See How to serialize:<br>";
echo "a_object: ".serialize(new a_class())."<br>";
echo "a_array: ".serialize($a_array)."<br>";
echo "a_string: ".serialize($a_string)."<br>";
echo "a_number: ".serialize($a_number)."<br>";
echo "a_boolean: ".serialize($a_boolean)."<br>";
echo "a_null: ".serialize($a_null)."<br>";
echo "Now your turn!<br>";

highlight_file('source');

$your_object = $_POST['o'];
$your_string = $_POST['s'];
$your_array = $_POST['a'];
$your_number = $_POST['i'];
$your_boolean = $_POST['b'];
$your_NULL = $_POST['n'];

$your_object = unserialize($your_object);
$your_array = unserialize($your_array);
$your_string = unserialize($your_string);
$your_number = unserialize($your_number);
$your_boolean = unserialize($your_boolean);
$your_NULL = unserialize($your_NULL);

$flag = "HelloCTF{Gre4t,y0u_can_als0_ser4l1ze2se_1n_y0ur_m1nd!}";

if(
    $your_boolean && 
    $your_NULL == null &&
    $your_string == "IWANT" &&
    $your_number == 1 &&
    $your_object->a_value == "FLAG" &&
    $your_array['a'] == "Plz" && $your_array['b'] == "Give_M3"
){
    echo $flag;
}
else{
    echo "You really know how to serialize?";
}
    





