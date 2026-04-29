<?php

/*
--- HelloCTF - 反序列化靶场 关卡 16 : zePOP--- 

__wakeUp() 方法用于反序列化时自动调用。例如 unserialize()。
__invoke() 方法用于一个对象被当成函数时应该如何回应。例如 $obj() 应该显示些什么。
__toString() 方法用于一个对象被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。

试着把他们串起来吧ww

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

class A {
    public $a;
    public function __invoke() {
            include $this->a;
            return $flag;
    }
}

class B {
    public $b;
    public function __toString() {
        $f = $this->b;
        return $f();
    }
}


class INIT {
    public $name;
    public function __wakeUp() {
        echo $this->name.' is awake!';
    }
}

if(isset($_POST['o'])) {
    unserialize($_POST['o']);
} else {
    highlight_file(__FILE__);
}
