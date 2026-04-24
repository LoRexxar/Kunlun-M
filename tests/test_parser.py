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


def test_anlysis_params_foreach_from_functioncall_source():
    """
    回归测试：foreach 源为函数调用时，应继续沿函数返回值回溯污点来源。
    """
    code = """<?php
function getItems() {
    return $_GET['items'];
}
foreach (getItems() as $item) {
    $x = $item;
}
print($x);
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_foreach_function_source_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_foreach_function_source_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$x', temp_file, 8)

        assert is_co == 1
        assert cp.name == '$_GET'
        assert isinstance(chain, list)
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


def test_repair_php_code_for_parser_null_coalesce():
    """
    回归测试：PHP7 null coalescing（??）语法应被降级修复为可解析形式。
    """
    code = """<?php
$a = $_GET["name"] ?? "guest";
"""
    repaired = Pretreatment._repair_php_code_for_parser(code)
    assert '??' not in repaired
    assert '?:' in repaired


def test_pre_ast_php_null_coalesce_operator():
    """
    回归测试：包含 ?? 的 PHP 文件不应导致整个文件 AST 预处理失败（Issue #130）。
    """
    code = """<?php
$name = $_GET['name'] ?? 'guest';
echo $name;
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_php7_null_coalesce.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_php7_null_coalesce.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        assert temp_file in ast_object.pre_result
        assert ast_object.pre_result[temp_file]['ast_nodes']
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_anlysis_params_array_offset_respects_key_mismatch():
    """
    回归测试：数组元素回溯时应区分 key，避免把 $c['a'] 污点错误传播到 $c['d']。
    """
    code = """<?php
$c['a'] = $_GET['a'];
$a = $c['d'];
echo $a;
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_array_key_mismatch_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_array_key_mismatch_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$a', temp_file, 4)

        assert is_co != 1
        assert isinstance(chain, list)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_anlysis_params_array_offset_respects_key_match():
    """
    回归测试：数组元素回溯在 key 一致时仍应正确识别可控来源。
    """
    code = """<?php
$c['d'] = $_GET['d'];
$a = $c['d'];
echo $a;
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_array_key_match_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_array_key_match_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$a', temp_file, 4)

        assert is_co == 1
        assert cp.name == '$_GET'
        assert isinstance(chain, list)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_pre_ast_define_namespace_concat_key():
    """
    回归测试：define(__NAMESPACE__ . "X", ...) 不应在预处理阶段触发
    `TypeError: unhashable type: 'BinaryOp'`。
    """
    code = """<?php
namespace Demo;
define(__NAMESPACE__ . "1", __NAMESPACE__ . "2");
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_define_namespace_concat.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_define_namespace_concat.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        assert temp_file in ast_object.pre_result
        # 关键断言：预处理执行完成且常量键可成功写入 define_dict。
        assert "__NAMESPACE__1" in ast_object.define_dict
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_scan_parser_echo_assignment_with_user_input():
    """
    回归测试：`echo $a = $_GET['a'];` 应识别为 echo sink 且可追踪到可控来源。
    """
    code = """<?php
echo $a = $_GET['a'];
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_echo_assignment_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_echo_assignment_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        result = scan_parser(['echo'], 2, temp_file)

        assert isinstance(result, list)
        assert result
        assert result[0].get('source') is not None
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


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


def test_anlysis_params_interpolated_string_var_from_outer_if_scope():
    """
    回归测试：if/else 分支中的拼接列表回溯失败时，
    应继续向外层作用域回溯变量来源（Issue #231）。
    """
    code = """<?php
$html = '';
if(isset($_GET['submit']) && $_GET['message'] != null){
    $message= $_GET['message'];
    if($message == 'yes'){
        $html.="<p>那就去人民广场一个人坐一会儿吧!</p>";
    }else{
        $html = "<p>别说这些'{$message}'的话,不要怕,就是干!</p>";
        echo $html;
    }
}
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_issue_231_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_issue_231_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        is_co, cp, expr_lineno, chain = anlysis_params('$html', temp_file, 9)

        assert is_co == 1
        assert cp.name == '$_GET'
        assert isinstance(chain, list)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])


def test_anlysis_params_self_concat_assignment_tracks_other_rhs_vars():
    """
    回归测试：`$pid = $pid . $did` 这类右值包含自身变量的拼接赋值，
    仍应继续追踪 `$did` 等其他变量来源（Issue #62）。
    """
    code = """<?php
function add_func($did){
    $did = $_GET['maple'];
    $pid = "random";
    $pid = $pid . $did;
    $a = $pid ^ 'randow';
    $b = $a . 'aaaaaaaaaaaaaaaaaaaaaaaaaaa';
    mysql_query($b);
}
"""
    temp_file = PROJECT_DIRECTORY + '/tests/vulnerabilities/v_issue_62_runtime.php'
    try:
        with open(temp_file, 'w') as f:
            f.write(code)

        runtime_files = [('.php', {'list': ["v_issue_62_runtime.php"]})]
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', runtime_files)
        ast_object.pre_ast_all(['php'])

        result = scan_parser(['mysql_query'], 8, temp_file)

        assert isinstance(result, list)
        assert result
        assert result[0].get('code') == 1
        assert result[0].get('source') is not None
        assert result[0].get('source').name == '$_GET'
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        ast_object.init_pre(PROJECT_DIRECTORY + '/tests/vulnerabilities/', files)
        ast_object.pre_ast_all(['php'])
