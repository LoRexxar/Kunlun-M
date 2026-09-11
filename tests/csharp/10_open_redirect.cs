// C# Open Redirect Tests (merged with above)
string url = Request.QueryString["next"];
Response.Redirect(url);

// False positive
Response.Redirect("/home");
