// C# Log Injection Tests

// CVI_9209 - Open Redirect
string targetUrl = Request.QueryString["redirect"];

Response.Redirect(targetUrl);
Redirect(targetUrl);

// False positive
Response.Redirect("/dashboard");
