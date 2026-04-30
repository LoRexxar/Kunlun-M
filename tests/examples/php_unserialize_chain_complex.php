<?php
/**
 * Complex sample for phpunserializechain plugin verification.
 * 4 nested classes: A -> B -> C -> D
 */

class A
{
    public $b;

    public function __destruct()
    {
        $this->b->trigger();
    }
}

class B
{
    public $c;

    public function trigger()
    {
        $this->c->exec();
    }
}

class C
{
    public $d;

    public function exec()
    {
        $this->d->run();
    }
}

class D
{
    public $cmd = "id";

    public function run()
    {
        system($this->cmd);
    }
}

