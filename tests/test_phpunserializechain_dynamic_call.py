# -*- coding: utf-8 -*-
import os

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from core.plugins.phpunserializechain.main import PhpUnSerChain


class DummyNode:
    id = 1
    node_locate = 'File-0.Class-A.Method-x'


def _build_plugin(controllable_result=True):
    plugin = object.__new__(PhpUnSerChain)
    called = []

    def _fake_check_param_controllable(param_name, now_node):
        called.append((param_name, now_node))
        return controllable_result

    plugin.check_param_controllable = _fake_check_param_controllable
    return plugin, called


def test_normal_method_call_with_object_param_should_not_be_dynamic_dispatch():
    plugin, called = _build_plugin(controllable_result=True)

    result = plugin.check_dynamic_class_var_exist(
        "MethodCall-Variable-$this->normalizeFormat('Variable-$format->name',)",
        DummyNode(),
    )

    assert result is False
    assert called == []


def test_dynamic_chain_call_target_should_trigger_controllability_check():
    plugin, called = _build_plugin(controllable_result=True)

    result = plugin.check_dynamic_class_var_exist(
        "MethodCall-Variable-$this->formatter->normalizeFormat('Variable-$format',)",
        DummyNode(),
    )

    assert result is True
    assert len(called) == 1
    assert called[0][0] == 'Variable-$this->formatter'


def test_dynamic_chain_call_target_returns_false_when_not_controllable():
    plugin, called = _build_plugin(controllable_result=False)

    result = plugin.check_dynamic_class_var_exist(
        "MethodCall-Variable-$this->formatter->normalizeFormat('Variable-$format',)",
        DummyNode(),
    )

    assert result is False
    assert len(called) == 1
    assert called[0][0] == 'Variable-$this->formatter'


def test_function_call_with_arrow_inside_arguments_should_not_be_dynamic_dispatch():
    plugin, called = _build_plugin(controllable_result=True)

    result = plugin.check_dynamic_class_var_exist(
        "FunctionCall-format('Variable-$this->formatter->name')",
        DummyNode(),
    )

    assert result is False
    assert called == []


def test_non_call_dynamic_property_chain_still_supported():
    plugin, called = _build_plugin(controllable_result=True)

    result = plugin.check_dynamic_class_var_exist('Variable-$this->a->b', DummyNode())

    assert result is True
    assert len(called) == 1
    assert called[0][0] == 'Variable-$this->a'
