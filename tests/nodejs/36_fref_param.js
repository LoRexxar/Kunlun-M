// Case 36: NodeJS 跨作用域 — 函数参数传递函数引用
// 将 eval 作为参数传入 executor，executor 通过参数调用
// 预期: 检出 CVI-3003
function executor(op, arg) {
    op(arg);
}

const input = process.argv[2];
executor(eval, input);
