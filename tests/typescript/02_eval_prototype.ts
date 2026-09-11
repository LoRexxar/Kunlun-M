// TypeScript eval + prototype pollution
const code: string = process.argv[3] as string;
const config: string = process.argv[4] as string;

// 漏洞 - 代码注入
eval(code);
new Function(code)();

// 漏洞 - 原型污染
Object.assign({}, JSON.parse(config));
const merged = Object.assign({}, JSON.parse(config));

// 安全
eval('1 + 1');
Object.assign({a: 1}, {b: 2});
