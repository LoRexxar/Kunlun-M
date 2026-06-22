// TS XPath and Template Injection Tests

const xpath = req.query.xpath;
const tmpl = req.query.template;

// CVI_9711 - XPath注入
doc.evaluate(xpath, doc, null, XPathResult.STRING_TYPE, null);
node.selectNodes(xpath);

// CVI_9712 - 模板注入
EJS.compile(tmpl);
Handlebars.compile(tmpl);
Pug.compile(tmpl);

// False positives
doc.evaluate("//book/title", doc, null, XPathResult.STRING_TYPE, null);
EJS.compile("<h1><%= name %></h1>");
