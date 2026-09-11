<?php
// Case 33: PHP 跨作用域 — 全局函数引用在函数内调用
// 模块级 $func = 'system'，在 handler 中调用 $func
// 预期: 检出 CVI-1011

$func = 'system';

function handler($user_input) {
    global $func;
    $func($user_input);
}

$user_input = $argv[1];
handler($user_input);
