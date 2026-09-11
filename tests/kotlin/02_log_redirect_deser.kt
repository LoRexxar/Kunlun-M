// Kotlin Log Injection, Open Redirect, Deserialization, XPath, LDAP, Template Tests

fun main() {
    val userInput = System.getenv("INPUT") ?: ""
    val targetUrl = System.getenv("URL") ?: ""
    val jsonData = System.getenv("DATA") ?: ""
    val xpathExpr = System.getenv("XPATH") ?: ""
    val filter = System.getenv("FILTER") ?: ""
    val template = System.getenv("TEMPLATE") ?: ""

    // CVI_9307 - 日志注入
    logger.info("User request: $userInput")
    logger.warn("Warning: $userInput")
    logger.error("Error: $userInput")

    // CVI_9308 - 开放重定向
    sendRedirect(targetUrl)
    response.sendRedirect(targetUrl)

    // CVI_9309 - 反序列化
    val result = Gson().fromJson(jsonData, User::class.java)
    val obj = ObjectMapper().readValue(jsonData, Object::class.java)

    // CVI_9310 - XPath注入
    val xpath = XPathFactory.newInstance().newXPath()
    xpath.evaluate(xpathExpr, document)

    // CVI_9311 - LDAP注入
    val ctx = InitialLdapContext()
    val searchControls = SearchControls()

    // CVI_9312 - 模板注入
    val engine = TemplateEngine()
    engine.process(template, context)

    // False positives
    logger.info("Server started")
    sendRedirect("/dashboard")
    Gson().fromJson("{\"name\":\"test\"}", User::class.java)
    xpath.evaluate("//book/title", document)
    engine.process("hello", context)
}
