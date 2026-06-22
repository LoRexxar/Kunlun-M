import kotlin.system.ProcessBuilder
import java.io.File
import java.sql.Connection

fun main() {
    val userInput = System.getenv("INPUT") ?: ""
    val filename = System.getenv("FILE") ?: ""

    // 漏洞 - 命令注入
    Runtime.getRuntime().exec(userInput)
    ProcessBuilder("sh", "-c", userInput).start()

    // 漏洞 - 路径遍历
    File(filename).readText()
    File(filename).writeText("data")

    // 漏洞 - SQL注入
    val query = "SELECT * FROM users WHERE id = ${userInput}"
    conn.createStatement().executeQuery(query)

    // 安全
    Runtime.getRuntime().exec("ls")
    File("config.xml").readText()
}
