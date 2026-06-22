// C# XPath, LDAP, Template Injection Tests

string userName = Request.QueryString["name"];
string filter = Request.QueryString["filter"];
string tmpl = Request.QueryString["template"];

// CVI_9211 - XPath注入
doc.SelectNodes("//user[name='" + userName + "']");
node.SelectSingleNode("//*[@id='" + userName + "']");

// CVI_9212 - LDAP注入
new DirectorySearcher("(cn=" + filter + ")");

// CVI_9213 - 模板注入
Razor.Parse(tmpl);

// False positives
doc.SelectNodes("//users/user");
new DirectorySearcher("(objectClass=person)");
Razor.Parse("Hello @Model.Name");
