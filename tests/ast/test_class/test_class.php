class a{
    $b = $_GET['b'];
    function __construct($test=1,$message="2333"){
        $this->test = $test;
        $this->message = $message;
    }

    function eval_function($a){
        eval($a);
    }

    function eval_function2(){
        $a = $_GET['a']
        eval($a);
    }

    function eval_function3(){
        eval($this->test);
    }

    function eval_function4(){
        eval($this->message);
    }
}


$x = $_GET['a'];
$y = "echo 233";

$A = new a($x, $y);

$z = $A->$b;
eval($z);