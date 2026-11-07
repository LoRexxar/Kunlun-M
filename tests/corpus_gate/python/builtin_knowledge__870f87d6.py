"""
C# 内置函数/方法可控性知识库

为静态分析引擎提供 C# 内置函数的返回值可控性信息。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
    - param_flow: 参数间数据流映射（可选）。
"""
from typing import Dict, List, Optional, Union

# {"函数名": {"passthrough": [参数位置列表], "safe": bool}}
KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {

    # ================================================================
    #  SOURCES — 用户可控输入（返回值不安全，透传参数）
    # ================================================================

    # ===== ASP.NET Core Request Sources =====
    "HttpRequest.QueryString":       {"passthrough": [0], "safe": False},
    "HttpRequest.Form":              {"passthrough": [0], "safe": False},
    "HttpRequest.Cookies":           {"passthrough": [0], "safe": False},
    "HttpRequest.Headers":           {"passthrough": [0], "safe": False},
    "HttpRequest.UserAgent":         {"passthrough": [0], "safe": False},
    "HttpRequest.Url":               {"passthrough": [0], "safe": False},
    "HttpRequest.RawUrl":            {"passthrough": [0], "safe": False},
    "HttpRequest.Path":              {"passthrough": [0], "safe": False},
    "HttpRequest.InputStream":       {"passthrough": [0], "safe": False},
    "HttpRequest.Files":             {"passthrough": [0], "safe": False},
    "HttpRequest.Body":              {"passthrough": [0], "safe": False},
    "HttpRequest.FilePath":          {"passthrough": [0], "safe": False},
    "Request.QueryString":           {"passthrough": [0], "safe": False},
    "Request.Form":                  {"passthrough": [0], "safe": False},
    "Request.Cookies":               {"passthrough": [0], "safe": False},
    "Request.Headers":               {"passthrough": [0], "safe": False},
    "Request.Url":                   {"passthrough": [0], "safe": False},
    "Request.Path":                  {"passthrough": [0], "safe": False},
    "Request.Body":                  {"passthrough": [0], "safe": False},
    "Request.InputStream":           {"passthrough": [0], "safe": False},

    # ===== HttpContext =====
    "HttpContext.Request":           {"passthrough": [0], "safe": False},
    "HttpContext.Current.Request":   {"passthrough": [0], "safe": False},
    "HttpContext.Response":          {"passthrough": [0], "safe": False},

    # ===== ASP.NET MVC Controller =====
    "ControllerBase.Request":        {"passthrough": [0], "safe": False},
    "ControllerBase.User":            {"passthrough": [0], "safe": False},
    "ControllerBase.HttpContext":     {"passthrough": [0], "safe": False},
    "Controller.Request":             {"passthrough": [0], "safe": False},
    "PageModel.Request":             {"passthrough": [0], "safe": False},

    # ===== Environment =====
    "Environment.GetEnvironmentVariable": {"passthrough": [0], "safe": False},

    # ===== Configuration =====
    "IConfiguration.GetValue":        {"passthrough": [0], "safe": False},
    "Configuration.GetValue":        {"passthrough": [0], "safe": False},
    "IConfiguration.GetSection":      {"passthrough": [0], "safe": False},
    "Configuration.GetSection":       {"passthrough": [0], "safe": False},
    "IConfiguration.Bind":            {"passthrough": [0], "safe": False},

    # ===== Console =====
    "Console.ReadLine":               {"passthrough": [0], "safe": False},
    "Console.Read":                   {"passthrough": [0], "safe": False},

    # ===== 文件读取 Sources =====
    "File.ReadAllText":               {"passthrough": [0], "safe": False},
    "File.ReadAllTextAsync":         {"passthrough": [0], "safe": False},
    "File.ReadAllBytes":              {"passthrough": [0], "safe": False},
    "File.ReadAllLines":              {"passthrough": [0], "safe": False},
    "StreamReader.ReadToEnd":         {"passthrough": [0], "safe": False},
    "StreamReader.ReadLine":          {"passthrough": [0], "safe": False},
    "StreamReader.Read":              {"passthrough": [0], "safe": False},

    # ===== 编解码 Sources =====
    "HttpUtility.UrlDecode":          {"passthrough": [0], "safe": False},
    "HttpUtility.HtmlDecode":         {"passthrough": [0], "safe": False},
    "WebUtility.UrlDecode":           {"passthrough": [0], "safe": False},
    "WebUtility.HtmlDecode":          {"passthrough": [0], "safe": False},

    # ================================================================
    #  SINKS — 危险操作（标记为不安全）
    # ================================================================

    # ===== System.Diagnostics — 命令注入 =====
    "Process.Start":                  {"passthrough": [0], "safe": False},

    # ===== System.Data.SqlClient — SQL 注入 =====
    "SqlCommand.CommandText":         {"passthrough": [0], "safe": False},
    "SqlCommand":                    {"passthrough": [0], "safe": False},
    "SqlConnection.ConnectionString":  {"passthrough": [0], "safe": False},
    "SqlDataAdapter":                 {"passthrough": [0], "safe": False},
    "DataSet":                        {"passthrough": [0], "safe": False},
    "OleDbCommand.CommandText":       {"passthrough": [0], "safe": False},
    "OleDbCommand":                   {"passthrough": [0], "safe": False},
    "OracleCommand.CommandText":      {"passthrough": [0], "safe": False},
    "OracleCommand":                  {"passthrough": [0], "safe": False},
    "MySqlCommand.CommandText":      {"passthrough": [0], "safe": False},
    "MySqlCommand":                  {"passthrough": [0], "safe": False},
    "NpgsqlCommand.CommandText":      {"passthrough": [0], "safe": False},
    "SqliteCommand.CommandText":      {"passthrough": [0], "safe": False},

    # ===== Entity Framework — SQL 注入（FromSqlRaw） =====
    "DbContext.FromSqlRaw":          {"passthrough": [0], "safe": False},
    "DbContext.FromSqlInterpolated":  {"passthrough": [0], "safe": False},
    "Database.ExecuteSqlRaw":         {"passthrough": [0], "safe": False},
    "Database.ExecuteSqlInterpolated": {"passthrough": [0], "safe": False},
    "DbSet.FromSqlRaw":              {"passthrough": [0], "safe": False},
    "RelationalQueryableExtensions.FromSqlRaw": {"passthrough": [0], "safe": False},

    # ===== System.IO — 路径遍历 =====
    "File.ReadAllText":               {"passthrough": [0], "safe": False},
    "File.WriteAllText":              {"passthrough": [0], "safe": False},
    "File.AppendAllText":             {"passthrough": [0], "safe": False},
    "File.ReadAllBytes":              {"passthrough": [0], "safe": False},
    "File.WriteAllBytes":             {"passthrough": [0], "safe": False},
    "File.Delete":                    {"passthrough": [0], "safe": False},
    "File.Move":                      {"passthrough": [0], "safe": False},
    "File.Copy":                      {"passthrough": [0, 1], "safe": False},
    "File.Create":                    {"passthrough": [0], "safe": False},
    "File.Open":                      {"passthrough": [0], "safe": False},
    "File.OpenRead":                  {"passthrough": [0], "safe": False},
    "File.OpenWrite":                 {"passthrough": [0], "safe": False},
    "File.Replace":                   {"passthrough": [0, 1], "safe": False},
    "Directory.CreateDirectory":       {"passthrough": [0], "safe": False},
    "Directory.Delete":               {"passthrough": [0], "safe": False},
    "Directory.Move":                 {"passthrough": [0, 1], "safe": False},
    "Directory.GetFiles":             {"passthrough": [0], "safe": False},
    "DirectoryInfo.GetFiles":         {"passthrough": [0], "safe": False},
    "FileInfo.FullName":              {"passthrough": [0], "safe": False},
    "Path.Combine":                   {"passthrough": [0, 1], "safe": False},
    "Path.GetFullPath":               {"passthrough": [0], "safe": False},

    # ===== System.Net — SSRF =====
    "HttpWebRequest":                 {"passthrough": [0], "safe": False},
    "WebClient.DownloadString":       {"passthrough": [0], "safe": False},
    "WebClient.DownloadData":         {"passthrough": [0], "safe": False},
    "WebClient.UploadString":         {"passthrough": [0], "safe": False},
    "WebClient.UploadData":           {"passthrough": [0], "safe": False},
    "HttpClient.GetStringAsync":      {"passthrough": [0], "safe": False},
    "HttpClient.GetAsync":            {"passthrough": [0], "safe": False},
    "HttpClient.PostAsync":           {"passthrough": [0], "safe": False},
    "HttpClient.SendAsync":            {"passthrough": [0], "safe": False},
    "HttpClient.PutAsync":            {"passthrough": [0], "safe": False},
    "HttpClient.DeleteAsync":         {"passthrough": [0], "safe": False},
    "HttpRequestMessage":             {"passthrough": [0], "safe": False},

    # ===== ASP.NET Response — XSS =====
    "Response.Write":                {"passthrough": [0], "safe": False},
    "Response.Redirect":              {"passthrough": [0], "safe": False},
    "HttpResponse.Write":             {"passthrough": [0], "safe": False},
    "HttpResponse.Redirect":          {"passthrough": [0], "safe": False},
    "HttpContext.Response.Write":     {"passthrough": [0], "safe": False},
    "HttpContext.Response.Redirect":  {"passthrough": [0], "safe": False},
    "Server.Execute":                 {"passthrough": [0], "safe": False},
    "Server.Transfer":                {"passthrough": [0], "safe": False},
    "HttpServerUtility.Execute":      {"passthrough": [0], "safe": False},
    "HttpServerUtility.Transfer":     {"passthrough": [0], "safe": False},

    # ===== ASP.NET Core XSS Sinks =====
    "ControllerBase.Content":         {"passthrough": [1], "safe": False},
    "ControllerBase.File":            {"passthrough": [0], "safe": False},
    "ControllerBase.Json":            {"passthrough": [1], "safe": False},
    "ControllerBase.Redirect":         {"passthrough": [0], "safe": False},
    "ControllerBase.PhysicalFile":     {"passthrough": [0], "safe": False},
    "ControllerBase.View":             {"passthrough": [0], "safe": False},
    "ControllerBase.ViewComponent":    {"passthrough": [0], "safe": False},
    "PageModel.Redirect":              {"passthrough": [0], "safe": False},

    # ===== XML — XXE =====
    "XDocument.Parse":                {"passthrough": [0], "safe": False},
    "XDocument.Load":                 {"passthrough": [0], "safe": False},
    "XElement.Parse":                 {"passthrough": [0], "safe": False},
    "XmlDocument.LoadXml":            {"passthrough": [0], "safe": False},
    "XmlDocument.Load":               {"passthrough": [0], "safe": False},
    "XmlTextReader":                  {"passthrough": [0], "safe": False},
    "XmlReader.Create":               {"passthrough": [0], "safe": False},
    "XmlSerializer.Deserialize":      {"passthrough": [0], "safe": False},

    # ===== JSON 反序列化 =====
    "JavaScriptSerializer.Deserialize": {"passthrough": [0], "safe": False},
    "DataContractJsonSerializer.ReadObject": {"passthrough": [0], "safe": False},
    "JsonSerializer.Deserialize":     {"passthrough": [0], "safe": False},
    "Newtonsoft.Json.JsonConvert.DeserializeObject": {"passthrough": [1], "safe": False},
    "JsonConvert.DeserializeObject":    {"passthrough": [0], "safe": False},
    "JsonConvert.DeserializeObjectAsync": {"passthrough": [0], "safe": False},

    # ===== Reflection — 不安全 =====
    "Assembly.Load":                  {"passthrough": [0], "safe": False},
    "Assembly.LoadFrom":              {"passthrough": [0], "safe": False},
    "Assembly.LoadFile":               {"passthrough": [0], "safe": False},
    "Type.GetType":                   {"passthrough": [0], "safe": False},
    "Activator.CreateInstance":        {"passthrough": [0], "safe": False},
    "MethodInfo.Invoke":              {"passthrough": [0], "safe": False},

    # ================================================================
    #  字符串操作（透传，不安全）
    # ================================================================

    "String.Format":                  {"passthrough": [0], "safe": False},
    "string.Format":                  {"passthrough": [0], "safe": False},
    "String.Concat":                  {"passthrough": [0], "safe": False},
    "string.Concat":                  {"passthrough": [0], "safe": False},
    "String.Join":                    {"passthrough": [0], "safe": False},
    "string.Join":                    {"passthrough": [0], "safe": False},
    "String.Replace":                 {"passthrough": [0], "safe": False},
    "string.Replace":                 {"passthrough": [0], "safe": False},
    "String.Substring":               {"passthrough": [0], "safe": False},
    "string.Substring":               {"passthrough": [0], "safe": False},
    "String.Trim":                    {"passthrough": [0], "safe": False},
    "string.Trim":                    {"passthrough": [0], "safe": False},
    "String.TrimStart":               {"passthrough": [0], "safe": False},
    "String.TrimEnd":                {"passthrough": [0], "safe": False},
    "String.ToLower":                 {"passthrough": [0], "safe": False},
    "String.ToUpper":                 {"passthrough": [0], "safe": False},
    "String.Split":                   {"passthrough": [0], "safe": False},
    "StringBuilder.AppendFormat":      {"passthrough": [0], "safe": False},
    "StringBuilder.Append":           {"passthrough": [0], "safe": False},
    "StringBuilder.Replace":           {"passthrough": [0], "safe": False},
    "StringBuilder.Insert":           {"passthrough": [0], "safe": False},

    # ================================================================
    #  编解码（部分安全过滤）
    # ================================================================

    "HttpUtility.UrlEncode":          {"passthrough": [0], "safe": True},
    "HttpUtility.HtmlEncode":         {"passthrough": [0], "safe": True},
    "WebUtility.UrlEncode":           {"passthrough": [0], "safe": True},
    "WebUtility.HtmlEncode":          {"passthrough": [0], "safe": True},
    "Convert.ToBase64String":         {"passthrough": [0], "safe": True},
    "Convert.FromBase64String":       {"passthrough": [0], "safe": False},
    "Uri.EscapeDataString":           {"passthrough": [0], "safe": True},
    "Uri.EscapeUriString":            {"passthrough": [0], "safe": True},
    "Encoding.UTF8.GetString":         {"passthrough": [0], "safe": False},
    "Encoding.UTF8.GetBytes":         {"passthrough": [0], "safe": False},

    # ================================================================
    #  类型转换（返回安全类型）
    # ================================================================

    "Convert.ToInt32":                {"passthrough": [], "safe": True},
    "Convert.ToInt64":                {"passthrough": [], "safe": True},
    "Convert.ToDouble":               {"passthrough": [], "safe": True},
    "Convert.ToDecimal":              {"passthrough": [], "safe": True},
    "Convert.ToBoolean":              {"passthrough": [], "safe": True},
    "Convert.ToString":               {"passthrough": [0], "safe": False},
    "Convert.ToDateTime":             {"passthrough": [], "safe": True},
    "int.Parse":                       {"passthrough": [], "safe": True},
    "long.Parse":                      {"passthrough": [], "safe": True},
    "double.Parse":                    {"passthrough": [], "safe": True},
    "bool.Parse":                      {"passthrough": [], "safe": True},
    "Guid.Parse":                      {"passthrough": [], "safe": True},
    "Guid.NewGuid":                    {"passthrough": [], "safe": True},
    "DateTime.Parse":                  {"passthrough": [], "safe": True},

    # ================================================================
    #  安全函数（不透传，返回值安全）
    # ================================================================

    "String.IsNullOrEmpty":           {"passthrough": [], "safe": True},
    "String.IsNullOrWhiteSpace":     {"passthrough": [], "safe": True},
    "String.Equals":                  {"passthrough": [], "safe": True},
    "String.Compare":                 {"passthrough": [], "safe": True},
    "String.Contains":                {"passthrough": [], "safe": True},
    "String.StartsWith":              {"passthrough": [], "safe": True},
    "String.EndsWith":                {"passthrough": [], "safe": True},
    "String.IndexOf":                 {"passthrough": [], "safe": True},
    "Int32.TryParse":                 {"passthrough": [], "safe": True},
    "Guid.TryParse":                  {"passthrough": [], "safe": True},
    "Regex.IsMatch":                  {"passthrough": [], "safe": True},
    "Regex.Match":                    {"passthrough": [], "safe": True},
    "Regex.Replace":                  {"passthrough": [1], "safe": False},
    "Enumerable.Any":                 {"passthrough": [], "safe": True},
    "Enumerable.Count":               {"passthrough": [], "safe": True},
    "Enumerable.FirstOrDefault":       {"passthrough": [], "safe": True},

    # ================================================================
    #  时间/数学/其他不透传
    # ================================================================

    "DateTime.Now":                   {"passthrough": [], "safe": True},
    "DateTime.UtcNow":                {"passthrough": [], "safe": True},
    "DateTime.Today":                 {"passthrough": [], "safe": True},
    "Math.Abs":                       {"passthrough": [], "safe": True},
    "Math.Max":                       {"passthrough": [], "safe": True},
    "Math.Min":                       {"passthrough": [], "safe": True},
    "Math.Round":                     {"passthrough": [], "safe": True},
    "Random.Next":                    {"passthrough": [], "safe": True},
    "Path.GetExtension":              {"passthrough": [0], "safe": False},
    "Path.GetFileName":                {"passthrough": [0], "safe": False},
    "Path.GetDirectoryName":          {"passthrough": [0], "safe": False},

    # ===== ADO.NET Parameterized (safe) =====
    "SqlCommand.Parameters.AddWithValue": {"passthrough": [], "safe": True},
    "SqlParameter.Value":             {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """
    查询 C# 内置函数知识库

    :param func_name: 函数/方法名
    :return: {"passthrough": [...], "safe": bool} 或 None
    """
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]

    if "." in func_name:
        short_name = func_name.split(".")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]

    return None
