<?php

/*
--- HelloCTF - 反序列化靶场 关卡 8 : 构造函数和析构函数以及GC机制 --- 

HINT：注意顺序和次数

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

global $destruct_flag;
global $construct_flag;
$destruct_flag = 0;
$construct_flag = 0;

class FLAG {
    public function __construct()
    {
        global $construct_flag;
        $construct_flag++;
        echo "Constructor called " . $construct_flag . "<br>";
    }
    public function __destruct()
    {
        global $destruct_flag;
        $destruct_flag++;
        echo "Destructor called " . $destruct_flag . "<br>";
    }
}
highlight_file(demo);

echo "<br>Object created:";
$demo = new FLAG();

echo "Object serialized: But Nothing Happen(:<br>";
$s = serialize($demo);

echo "Object unserialized:But nothing happened either):<br>";
$n = unserialize($s); 
echo "serialized Object destroyed:";
unset($n);
echo "original Object destroyed:";
unset($demo);

/*注意 此处为了方便演示为手动释放，一般情况下，当脚本运行完毕后，php会将未显式销毁的对象自动销毁，该行为也会调用析构函数*/
/*此外 还有比较特殊的情况: PHP的GC(垃圾回收机制)会在脚本运行时自动管理内存，销毁不被引用的对象*/

echo "<br>This object ('new FLAG();') will be destroyed immediately because it is not assigned to any variable:";
new FLAG();


echo "<br>Now Your Turn!, Try to get the flag!<br>";

highlight_file(source);

class RELFLAG {

    public function __construct()
    {
        global $flag;
        $flag = 0;
        $flag++;
        echo "Constructor called " . $flag . "<br>";
    }
    public function __destruct()
    {
        global $flag;
        $flag++;
        echo "Destructor called " . $flag . "<br>";
    }
}

function check(){
    global $flag;
    if($flag > 5){
        echo "FLAG{Construct0r_&_D3struct0r}";
    }else{
        echo "Check Detected flag is ". $flag;
    }
}

if (isset($_POST['code'])) {
    eval($_POST['code']);
    check();
}

