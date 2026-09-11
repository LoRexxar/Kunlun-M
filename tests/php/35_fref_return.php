<?php
// Case 35: PHP 跨作用域 — 函数返回函数引用
// getFunc 返回 'system'，外部接收后调用
// 预期: 检出 CVI-1011

function getFunc() {
    return 'system';
}

$user_input = $argv[1];
$func = getFunc();
$func($user_input);
