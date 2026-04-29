<?php
error_reporting(0);
function checker($s){
    $ss = str_replace("fakes","fake",$s);
    return $ss;
}

Class A1{
    public $test;
    public $test1;
    public $test2;
    public $test3;
    public function __construct($test1){
        $this->test1=$test1;
    }
    public function __invoke(){
        echo "welcome";
    }

}


Class B1{
    public $test1;
    public $test2;
    public function __construct($test1,$test2){
        $this->test1=$test1;
        $this->test2=$test2;
    }

    public function __destruct(){
        $this -> test1();
    }
}

Class C1{
    public $test1;
    public function __construct(){
        $this->test1="test1";
    }
    public function __destruct()
    {
        if(preg_match('/[a-z0-9]/i', $this->test1))
        {
            echo "sry";
        }
    }
}

Class D1{
    public $test1;
    public $test2;
    public function __construct()
    {
        $this->test1="echo";
        $this->test2="fakes";
    }

    public function __toString()
    {
        // TODO: Implement __toString() method.
        call_user_func($this->test1,$this->test2);

    }
}
$a = $_POST["a"];
$b = $_POST["b"];
if(isset($_POST["a"])&&isset($_POST["b"])){
    $b = new B1($a,$b);
    $c = checker(serialize($b));
    $d = unserialize($c);
}
else{
    highlight_file(__FILE__);
}