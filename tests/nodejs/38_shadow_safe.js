// Case 38: NodeJS 跨作用域 — 同名遮蔽（安全）
// 全局 func = eval，函数内局部 func = console.log 遮蔽
// 预期: 不应检出
const func = eval;

function handler(userInput) {
    const func = console.log;
    func(userInput);
}

const input = process.argv[2];
handler(input);
