using System;
using System.Diagnostics;
using System.Data.SqlClient;

class Program {
    static void Main() {
        string input = Request.QueryString["cmd"];

        // 漏洞 - 命令注入
        Process.Start(input);
        Process.Start("cmd.exe", "/c " + input);

        // 漏洞 - SQL注入
        string query = "SELECT * FROM users WHERE id = " + input;
        SqlCommand cmd = new SqlCommand(query, conn);
        cmd.ExecuteNonQuery();

        // 漏洞 - 路径遍历
        File.ReadAllText(input);
        File.WriteAllText(input, "data");

        // 安全
        Process.Start("notepad.exe");
        SqlCommand safe = new SqlCommand("SELECT 1", conn);
        File.ReadAllText("config.xml");
    }
}
