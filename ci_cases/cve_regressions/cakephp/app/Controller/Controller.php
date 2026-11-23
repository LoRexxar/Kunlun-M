<?php
// CakePHP 2.x controller base (trimmed from lib/Cake/Controller/Controller.php)
class Object {

}

class Controller extends Object {
    public $uses = array();
    public $request = null;
    public $params = array();
    public $passedArgs = array();

    public function __construct($request = null) {
        $this->request = $request;
    }

    public function loadModel($name) {
        $this->{$name} = new $name();
    }
}
