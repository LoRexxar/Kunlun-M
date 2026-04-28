# -*- coding: utf-8 -*-
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from core.plugins.phpunserializechain.main import PhpUnSerChain


class DummyNode:
    def __init__(self, node_type, node_locate, source_node, sink_node):
        self.node_type = node_type
        self.node_locate = node_locate
        self.source_node = source_node
        self.sink_node = sink_node


def test_parse_chain_nodes_should_keep_class_only_and_drop_method_tokens():
    plugin = object.__new__(PhpUnSerChain)
    plugin.deep_get_node_name = lambda x, **kwargs: x

    chain = [
        DummyNode('newMethod', 'demo_php.Class-A', 'Method-__destruct', '()'),
        DummyNode('MethodCall', 'demo_php.Class-A.Method-__destruct', 'Variable-$this->b->trigger', '()'),
        DummyNode('newMethod', 'demo_php.Class-B', 'Method-trigger', '()'),
        DummyNode('MethodCall', 'demo_php.Class-B.Method-trigger', 'Variable-$this->c->exec', '()'),
        DummyNode('newMethod', 'demo_php.Class-C', 'Method-exec', '()'),
        DummyNode('MethodCall', 'demo_php.Class-C.Method-exec', 'Variable-$this->d->run', '()'),
        DummyNode('newMethod', 'demo_php.Class-D', 'Method-run', '()'),
        DummyNode('FunctionCall', 'demo_php.Class-D.Method-run', 'system', "('Variable-$this->cmd',)"),
    ]

    chain_id, chain_items, class_sequence, method_sequence = plugin.parse_chain_nodes(chain)

    assert chain_id.startswith('A::__destruct')
    assert class_sequence == ['A', 'B', 'C', 'D']
    assert method_sequence == ['__destruct', 'trigger', 'exec', 'run']
    assert len(chain_items) == 8


def test_extract_first_property_path_for_nested_calls_should_strip_method_later():
    plugin = object.__new__(PhpUnSerChain)
    path = plugin.extract_first_property_path("Variable-$this->b->c->trigger")
    assert path == ['b', 'c', 'trigger']


def test_build_trigger_code_should_support_implicit_magic_methods():
    plugin = object.__new__(PhpUnSerChain)

    assert plugin.build_trigger_code('__toString') == "$trigger_result = (string)$root;"
    assert plugin.build_trigger_code('__call') == "$root->undefinedMethod('PAYLOAD_CALL');"
    assert plugin.build_trigger_code('__invoke') == "$root();"
    assert "@unserialize" in plugin.build_trigger_code('__wakeup')
