<?php
// Case 34: PHP 跨作用域 — 函数参数传递函数引用
// 将 'system' 作为字符串参数传入 executor
// 预期: 检出 CVI-1011

function executor($op, $arg) {
    $op($arg);
}

$user_input = $argv[1];
executor('system', $user_input);
