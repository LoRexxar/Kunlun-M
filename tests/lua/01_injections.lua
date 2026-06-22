local userInput = os.getenv("INPUT") or ""
local filename = os.getenv("FILE") or ""

-- 漏洞 - 命令执行
os.execute(userInput)
os.execute("cat " .. userInput)
local handle = io.popen(userInput)

-- 漏洞 - 代码注入
loadstring(userInput)
dofile(filename)

-- 漏洞 - 文件操作
local f = io.open(filename, "r")
os.remove(filename)

-- 安全
os.execute("ls -la")
local f = io.open("config.lua", "r")
