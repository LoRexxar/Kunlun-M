// TS Log Injection and Open Redirect Tests

const userInput = req.query.name;
const targetUrl = req.query.redirect;

// CVI_9709 - 日志注入
console.log("User input: " + userInput);
console.warn("Suspicious: " + userInput);
console.error("Error: " + userInput);
console.info("Info: " + userInput);

// CVI_9710 - 开放重定向
res.redirect(targetUrl);
ctx.redirect(targetUrl);
redirect(targetUrl);

// False positives
console.log("Server started");
res.redirect("/dashboard");
