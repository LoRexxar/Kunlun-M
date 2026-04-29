<?php

/*
--- HelloCTF - 反序列化靶场 关卡 15 : POP链初步 --- 

世界的本质其实就是套娃（x

# -*- coding: utf-8 -*-
# @Author: 探姬(@ProbiusOfficial)
# @Date:   2024-07-01 20:30
# @Repo:   github.com/ProbiusOfficial/PHPSerialize-labs
# @email:  admin@hello-ctf.com
# @link:   hello-ctf.com

*/

/* FLAG in flag.php */

class A {
    public $a;
    public function __construct($a) {
        $this->a = $a;
    }
}
class B {
    public $b;
    public function __construct($b) {
        $this->b = $b;
    }
}
class C {
    public $c;
    public function __construct($c) {
        $this->c = $c;
    }
}

class D {
    public $d;
    public function __construct($d) {
        $this->d = $d;
    }
    public function __wakeUp() {
        $this->d->action();
    }
}

class destnation {
    var $cmd;
    public function __construct($cmd) {
        $this->cmd = $cmd;
    }
    public function action(){
        eval($this->cmd->a->b->c);
    }
}

if(isset($_POST['o'])) {
    unserialize($_POST['o']);
} else {
    highlight_file(__FILE__);
}
