// Case 35: NodeJS 跨作用域 — 全局函数引用在函数内调用
// 模块级 func = eval，在 handler 中调用 func
// 预期: 检出 CVI-3003
const func = eval;

function handler(userInput) {
    func(userInput);
}

const input = process.argv[2];
handler(input);
