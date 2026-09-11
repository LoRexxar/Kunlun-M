-- Lua Open Redirect, Template Injection, Log Injection, XPath, Deserialization Tests

local userInput = os.getenv("INPUT") or ""
local targetUrl = os.getenv("URL") or ""
local jsonData = os.getenv("DATA") or ""

-- CVI_9607 - 开放重定向
ngx.redirect(targetUrl)
redirect(targetUrl)

-- CVI_9608 - 模板注入
local tmpl = template.compile(userInput)
template.render(userInput)
template.process(userInput)

-- CVI_9609 - 日志注入
log.info("User input: " .. userInput)
log.warn("Warning: " .. userInput)
log.error("Error: " .. userInput)

-- CVI_9610 - XPath注入
local result = xpath.parse(userInput)
xpath.selectNodes(userInput)

-- CVI_9611 - 不安全反序列化
local data = json.decode(jsonData)
local obj = cjson.decode(jsonData)
local msg = msgpack.unpack(jsonData)

-- False positives
ngx.redirect("/dashboard")
log.info("Server started")
json.decode("{}")
template.render("hello")
