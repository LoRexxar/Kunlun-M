# -*- coding: utf-8 -*-
from pathlib import Path


def test_magic_all_sample_should_include_4_layer_dispatch_and_implicit_methods():
    sample_path = Path("tests/examples/php_unserialize_chain_magic_all.php")
    content = sample_path.read_text(encoding="utf-8")

    assert "class A" in content
    assert "class B" in content
    assert "class C" in content
    assert "class D" in content

    assert "function __wakeup" in content
    assert "function __toString" in content
    assert "function __call" in content
    assert "function __invoke" in content

    # 4-layer dispatch examples
    assert "$this->b->dispatchToString()" in content
    assert "$this->c->routeToString()" in content
    assert "$this->d->sinkToString()" in content

    # sink
    assert "system($this->cmd);" in content

    # implicit trigger syntax examples
    assert "echo $a;" in content
    assert "$a->notExists('payload');" in content
    assert "$a();" in content
    assert "unserialize(serialize($a));" in content
