#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    core
    ~~~~~

    Implements core main

    :author:    BlBana <635373043@qq.com>
    :homepage:  https://github.com/wufeifei/cobra
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 Feei. All rights reserved
"""
import os

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

from Kunlun_M.settings import PROJECT_DIRECTORY
from core.core_engine.php.parser import anlysis_params
from core.core_engine.php.parser import new_class_back
from core.core_engine.php.parser import parameters_back
from core.core_engine.php.parser import scan_parser
from core.pretreatment import ast_object
from core.pretreatment import Pretreatment
from phply import phpast as php

files = [('.php', {'list': ["v_parser.php", "v.php"]})]
ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
ast_object.pre_ast_all(['php'])


target_projects = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_parser.php'
target_projects2 = PROJECT_DIRECTORY + '/tests/vulnerabilities/v.php'

with open(target_projects, 'r') as fi:
    code_contents = fi.read()
with open(target_projects, 'r') as fi2:
    code_contents2 = fi2.read()

sensitive_func = ['system']
lineno = 7

param = '$callback'
lineno2 = 10


def test_scan_parser():
    assert scan_parser(sensitive_func, lineno, target_projects)


def test_anlysis_params():
    assert anlysis_params(param, target_projects2, lineno2)


def test_new_class_back_handles_php_new_with_string_name():
    """
    回归测试：new_class_back 处理 php.New(name=str, ...) 时不应抛异常。
    """
    return_node = php.Return(php.Variable('$_GET'), lineno=3)
    tostring_method = php.Method('__toString', [], [], [return_node], False, lineno=2)
    class_node = php.Class('Demo', None, None, [], [], [tostring_method], lineno=1)

    is_co, cp, expr_lineno = new_class_back(php.New('Demo', [], lineno=10), [class_node])

    assert is_co == 1
    assert cp.name == '$_GET'
    assert isinstance(expr_lineno, int)


def test_parameters_back_foreach_return_shape():
    """
    回归测试：Foreach 分支返回值固定为三元组，避免拆包异常。
    """
    foreach_var = php.ForeachVariable(php.Variable('$item'), False)
    foreach_block = php.Block([], lineno=6)
    foreach_node = php.Foreach(php.Variable('$arr'), None, foreach_var, foreach_block, lineno=5)

    result = parameters_back(php.Variable('$x'), [foreach_node], lineno=10, file_path=target_projects2)

    assert isinstance(result, tuple)
    assert len(result) == 3


def test_anlysis_params_new_class_tostring_integration():
    """
    集成回归：真实 PHP 文件中 $obj = new Demo() 时，
    可沿 __toString() 回溯到 $_GET，判定为可控。
    """
    code = """<?php
class Demo {
    function __toString() {
        return $_GET['name'];
    }
}
$obj = new Demo();
echo $obj;
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_new_class_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_new_class_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$obj', temp_file, 8)

        assert is_co == 1
        assert cp.name == '$_GET'
        assert isinstance(chain, list)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_anlysis_params_foreach_flow_integration():
    """
    集成回归：真实 foreach 数据流回溯不应出现返回值拆包异常。
    """
    code = """<?php
$list = $_GET['items'];
foreach ($list as $item) {
    $x = $item;
}
print($x);
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_foreach_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_foreach_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        result = anlysis_params('$x', temp_file, 6)

        assert isinstance(result, tuple)
        assert len(result) == 4
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_pre_ast_php_parenthesized_callable_variable():
    """
    回归测试：($a)() 语法不应导致整个文件 AST 预处理失败。
    """
    code = """<?php
$a = "phpinfo";
($a)();
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_parenthesized_callable.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_parenthesized_callable.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        assert temp_file in ast_object.pre_result
        assert ast_object.pre_result[temp_file]['ast_nodes']
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_repair_php_code_for_parser_token_safe():
    """
    回归测试：仅修复真实 token 模式的 ($var)(...)，
    不应误伤字符串中的同样文本。
    """
    code = """<?php
$a = "phpinfo";
($a)();
$s = "($a)() should stay";
"""
    repaired = Pretreatment._repair_php_code_for_parser(code)
    assert '$a();' in repaired
    assert '"($a)() should stay"' in repaired


def test_anlysis_params_require_assignment_in_private_method():
    """
    回归测试：类私有方法中 `$var = require($file)` 的赋值链应可继续回溯。
    """
    code = """<?php
class LangLoader {
    private function getLangFileFullPath($local, $module) {
        return $local;
    }

    private function getArrayFromPhp($file) {
        $array = require($file);
        return $array;
    }

    public function getPhpLangArrayByModule($local, $module) {
        return $this->getArrayFromPhp($this->getLangFileFullPath($local, $module));
    }
}

$loader = new LangLoader();
$input = $_GET['lang'];
$ret = $loader->getPhpLangArrayByModule($input, 'common');
print($ret);
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_require_assignment_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_require_assignment_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$ret', temp_file, 20)

        assert is_co == 1
        assert cp.name == '$_GET'
        assert isinstance(chain, list)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])
