<?php

/*
--- HelloCTF - 反序列化靶场 关卡 12 : sleep! --- 

年轻就是好啊，倒头就睡。

serialize() 函数会检查类中是否存在一个魔术方法 __sleep()。如果存在，该方法会先被调用，然后才执行序列化操作。
该方法必须返回一个数组: return array('属性1', '属性2', '属性3') / return ['属性1', '属性2', '属性3']。
数组中的属性名将决定哪些变量将被序列化，当属性被 static 修饰时，无论有无都无法序列化该属性。
如果需要返回父类中的私有属性，需要使用序列化中的特殊格式 - %00父类名称%00变量名 (%00 是 ASCII 值为 0 的空字符 null,在代码内我们也可以通过 "\0" - 注意在双引号中，PHP 才会解析转义字符和变量。)。
例如，父类 FLAG 的私有属性 private $f; 应该在子类的 __sleep() 方法中以 "\0FLAG\0f" 的格式返回。
如果该方法未返回任何内容，序列化会被制空，并产生一个 E_NOTICE 级别的错误。

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/


class FLAG {

    private $f = 'clean_';
    private $l = 'up_';
    protected $a = '4nd_';
    public  $g = 'select_variab1es}';
    public $x,$y,$z;

    public function __sleep() {
        echo "If you serialize FLAG, you will just get x,y,z<br>";
        return ['x','y','z'];
    }
}

class CHALLENGE extends FLAG {

    public $h = 'HelloCTF{',$e = 'Th3_',$l = '__sleep_function_',$I = '_is_',$o = 'called_',$c = 'before_',$t = 'serialization_',$f = 't0_';
    public $chance;

    function chance() {
        if(isset($_GET['chance'])){
            return $_GET['chance'];
        }
        else{
            return 'you shuold use it';
        }
    }
    public function __sleep() {

        $array_list = ['h','e','l','I','o','c','t','f','f','l','a','g'];
        $_=array_rand($array_list);$__=array_rand($array_list);
        echo "Now __sleep()'s return parameters is array('".$array_list[$_]."','".$array_list[$__]."','".$this->chance()."')<br>";
        return array($array_list[$_],$array_list[$__],$this->chance());
    }

}

/* FLAG is $h + $e + $l + $I + $o + $c + $t + $f + $f + $l + $a + $g */

highlight_file('source');

$FLAG = new FLAG();
echo serialize($FLAG);

echo "<br>------ 每次请求会随机返回两个属性，你也可以用 chance 来指定你想要的属性 ------<br>";

echo serialize(new CHALLENGE());




