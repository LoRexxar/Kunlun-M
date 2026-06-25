// Case 37: NodeJS 跨作用域 — 函数返回函数引用
// getFunc 返回 eval，外部接收后调用
// 预期: 检出 CVI-3003
function getFunc() {
    return eval;
}

const input = process.argv[2];
const func = getFunc();
func(input);
