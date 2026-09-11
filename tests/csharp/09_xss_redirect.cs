// C# XSS and Open Redirect Tests

string userInput = Request.QueryString["q"];

// CVI_9210 - XSS
Response.Write("<div>" + userInput + "</div>");
Html.Raw(userInput);

// CVI_9209 - Open Redirect
string targetUrl = Request.QueryString["redirect"];
Response.Redirect(targetUrl);

// False positives
Response.Write("Hello World");
Html.Raw("<b>bold</b>");
Response.Redirect("/home");
