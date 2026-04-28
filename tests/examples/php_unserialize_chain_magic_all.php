<?php
/**
 * 4-layer dispatch sample + implicit magic methods:
 * A (magic methods) -> B (dispatch) -> C (route) -> D (sink)
 */

class A
{
    public $b;

    public function __wakeup()
    {
        $this->b->dispatchWakeup();
    }

    public function __toString()
    {
        return $this->b->dispatchToString();
    }

    public function __call($name, $arguments)
    {
        return $this->b->dispatchCall($name, $arguments);
    }

    public function __invoke()
    {
        $this->b->dispatchInvoke();
    }

    public function __destruct()
    {
        $this->b->dispatchDestruct();
    }
}

class B
{
    public $c;

    public function dispatchWakeup()
    {
        $this->c->routeWakeup();
    }

    public function dispatchToString()
    {
        return $this->c->routeToString();
    }

    public function dispatchCall($name, $arguments)
    {
        return $this->c->routeCall($name, $arguments);
    }

    public function dispatchInvoke()
    {
        $this->c->routeInvoke();
    }

    public function dispatchDestruct()
    {
        $this->c->routeDestruct();
    }
}

class C
{
    public $d;

    public function routeWakeup()
    {
        $this->d->sinkWakeup();
    }

    public function routeToString()
    {
        return $this->d->sinkToString();
    }

    public function routeCall($name, $arguments)
    {
        return $this->d->sinkCall($name, $arguments);
    }

    public function routeInvoke()
    {
        $this->d->sinkInvoke();
    }

    public function routeDestruct()
    {
        $this->d->sinkDestruct();
    }
}

class D
{
    public $cmd = "id";

    public function sinkWakeup()
    {
        system($this->cmd);
    }

    public function sinkToString()
    {
        system($this->cmd);
        return "ok";
    }

    public function sinkCall($name, $arguments)
    {
        system($this->cmd);
        return "ok";
    }

    public function sinkInvoke()
    {
        system($this->cmd);
    }

    public function sinkDestruct()
    {
        system($this->cmd);
    }
}

/**
 * Implicit trigger examples (for test/demo only):
 * - echo $a;                   => __toString
 * - $a->notExists('x');        => __call
 * - $a();                      => __invoke
 * - unserialize(serialize($a)) => __wakeup
 */
function demoImplicitMagicTriggers()
{
    $a = new A();
    $a->b = new B();
    $a->b->c = new C();
    $a->b->c->d = new D();

    // __toString (implicit)
    echo $a;

    // __call (implicit)
    $a->notExists('payload');

    // __invoke (implicit)
    $a();

    // __wakeup (implicit, during unserialize)
    unserialize(serialize($a));
}
