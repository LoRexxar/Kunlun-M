using System;
using System.IO;
using System.Net.Http;

class WebApp {
    static void Main() {
        string url = Request.QueryString["url"];
        string data = Request.Form["data"];
        string file = Request["file"];

        // 漏洞 - SSRF
        HttpClient client = new HttpClient();
        client.GetStringAsync(url);
        client.PostAsync(url, null);

        // 漏洞 - XSS
        Response.Write(data);

        // 漏洞 - 路径遍历
        File.Delete(file);
        DirectoryInfo dir = new DirectoryInfo(file);

        // 安全
        client.GetStringAsync("https://api.example.com/health");
        Response.Write("<h1>Hello</h1>");
        File.Delete("/tmp/cache.dat");
    }
}
