// TypeScript 测试
import * as fs from 'fs';
import { exec } from 'child_process';
import * as http from 'http';

const userInput: string = process.argv[2] as string;
const url: string = process.env.TARGET_URL || '';

// 漏洞 - 命令注入
exec(userInput);
exec('echo ' + userInput);

// 漏洞 - 路径遍历
fs.readFile(userInput, 'utf8');
fs.writeFileSync(userInput, 'data');

// 漏洞 - SSRF
http.get(url);
fetch(url);

// 漏洞 - XSS
document.getElementById('output').innerHTML = userInput;

// 安全
exec('ls -la');
fs.readFile('config.json', 'utf8');
document.getElementById('output').textContent = 'hello';
