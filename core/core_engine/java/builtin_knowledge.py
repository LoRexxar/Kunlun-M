"""
JAVA 内置函数/方法可控性知识库

为静态分析引擎提供该语言内置函数的返回值可控性信息，避免对已知函数进行不必要的函数体分析。

知识条目结构:
    {"函数名": {"passthrough": [参数位置列表], "safe": bool}}

    - passthrough: 返回值依赖哪些参数的位置（0-indexed）。
      [] 表示返回值与输入参数无关（如 len() 返回整数）。
    - safe: True 表示该函数做了有效安全过滤，返回值不再构成安全威胁。
    - param_flow: 参数间数据流映射 {输出参数索引: 输入参数索引}（可选）。
      值可以是 int（参数位置）或 str（隐式源如 "stdin"）。
"""
from typing import Dict, List, Optional, Union

# {"函数名": {"passthrough": [参数位置列表], "safe": bool}}
KNOWLEDGE: Dict[str, Dict[str, Union[List[int], bool]]] = {
        # ===== String 方法（透传 this） =====
        "toUpperCase":      {"passthrough": [0], "safe": False},
        "toLowerCase":      {"passthrough": [0], "safe": False},
        "trim":             {"passthrough": [0], "safe": False},
        "strip":            {"passthrough": [0], "safe": False},
        "stripLeading":     {"passthrough": [0], "safe": False},
        "stripTrailing":    {"passthrough": [0], "safe": False},
        "replace":          {"passthrough": [0], "safe": False},
        "replaceAll":       {"passthrough": [0], "safe": False},
        "replaceFirst":     {"passthrough": [0], "safe": False},
        "substring":        {"passthrough": [0], "safe": False},
        "split":            {"passthrough": [0], "safe": False},
        "concat":           {"passthrough": [0], "safe": False},
        "toString":         {"passthrough": [0], "safe": False},
        "valueOf":          {"passthrough": [0], "safe": False},
        "format":           {"passthrough": [1], "safe": False},
        "getBytes":         {"passthrough": [0], "safe": False},
        "toCharArray":      {"passthrough": [0], "safe": False},
        "intern":           {"passthrough": [0], "safe": False},
        "indent":           {"passthrough": [0], "safe": False},
        "stripIndent":      {"passthrough": [0], "safe": False},
        "translateEscapes": {"passthrough": [0], "safe": False},
        "formatted":        {"passthrough": [0], "safe": False},
        "join":             {"passthrough": [1], "safe": False},
        "repeat":           {"passthrough": [0], "safe": False},
        "copyValueOf":      {"passthrough": [0], "safe": False},
        "contentEquals":    {"passthrough": [], "safe": True},
        "subSequence":      {"passthrough": [0], "safe": False},

        # ===== StringBuilder/StringBuffer =====
        "append":           {"passthrough": [0], "safe": False},
        "insert":           {"passthrough": [0], "safe": False},
        "delete":           {"passthrough": [0], "safe": False},
        "reverse":          {"passthrough": [0], "safe": False},

        # ===== 安全过滤 =====
        "StringEscapeUtils.escapeHtml4":        {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeHtml3":        {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeXml":          {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeJava":         {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeEcmaScript":   {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeSql":          {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeXml10":        {"passthrough": [0], "safe": True},
        "StringEscapeUtils.escapeXml11":        {"passthrough": [0], "safe": True},
        "ESAPI.encoder.encodeForHTML":          {"passthrough": [0], "safe": True},
        "ESAPI.encoder.encodeForJavaScript":    {"passthrough": [0], "safe": True},
        "ESAPI.encoder.encodeForSQL":           {"passthrough": [0], "safe": True},
        "Encode.forHtml":                       {"passthrough": [0], "safe": True},
        "Encode.forHtmlContent":                {"passthrough": [0], "safe": True},
        "Encode.forJavaScript":                 {"passthrough": [0], "safe": True},
        "Encode.forUriComponent":               {"passthrough": [0], "safe": True},

        # ===== 不透传 =====
        "length":       {"passthrough": [], "safe": True},
        "isEmpty":      {"passthrough": [], "safe": True},
        "isBlank":      {"passthrough": [], "safe": True},
        "equals":       {"passthrough": [], "safe": True},
        "equalsIgnoreCase": {"passthrough": [], "safe": True},
        "compareTo":    {"passthrough": [], "safe": True},
        "compareToIgnoreCase": {"passthrough": [], "safe": True},
        "hashCode":     {"passthrough": [], "safe": True},
        "contains":     {"passthrough": [], "safe": True},
        "indexOf":      {"passthrough": [], "safe": True},
        "lastIndexOf":  {"passthrough": [], "safe": True},
        "startsWith":   {"passthrough": [], "safe": True},
        "endsWith":     {"passthrough": [], "safe": True},
        "matches":      {"passthrough": [], "safe": True},
        "getClass":     {"passthrough": [], "safe": True},
        "charAt":       {"passthrough": [0], "safe": False},
        "codePointAt":  {"passthrough": [], "safe": True},

        # ===== JDK 核心安全函数 =====
        "Runtime.exec":                    {"passthrough": [0], "safe": False},
        "ProcessBuilder.start":             {"passthrough": [0], "safe": False},
        "Statement.execute":                {"passthrough": [0], "safe": False},
        "Statement.executeQuery":           {"passthrough": [], "safe": False, "param_flow": {"self": 0}},
        "Statement.executeUpdate":          {"passthrough": [], "safe": False, "param_flow": {"self": 0}},
        "Class.forName":                    {"passthrough": [0], "safe": False},
        "ClassLoader.loadClass":           {"passthrough": [0], "safe": False},
        "Class.newInstance":                {"passthrough": [], "safe": False},

        # ===== JDBC PreparedStatement =====
        "PreparedStatement.setString":     {"passthrough": [], "safe": True, "param_flow": {"self": 1}},
        "PreparedStatement.setInt":        {"passthrough": [], "safe": True, "param_flow": {"self": 1}},
        "PreparedStatement.setObject":      {"passthrough": [], "safe": True, "param_flow": {"self": 1}},
        "PreparedStatement.executeQuery":   {"passthrough": [], "safe": False, "param_flow": {"self": 0}},
        "PreparedStatement.executeUpdate":   {"passthrough": [], "safe": False, "param_flow": {"self": 0}},

        # ===== 集合类 param_flow =====
        "HashMap.put":                       {"passthrough": [], "safe": True, "param_flow": {"self": 1}},
        "ArrayList.add":                     {"passthrough": [], "safe": True, "param_flow": {"self": 0}},
        "LinkedList.add":                    {"passthrough": [], "safe": True, "param_flow": {"self": 0}},
        "HashSet.add":                       {"passthrough": [], "safe": True, "param_flow": {"self": 0}},

        # ===== Servlet attribute param_flow =====
        "HttpServletRequest.setAttribute":   {"passthrough": [], "safe": True, "param_flow": {"self": 1}},
        "ServletContext.setAttribute":       {"passthrough": [], "safe": True, "param_flow": {"self": 1}},

        # ===== Spring Framework =====
        "HtmlUtils.htmlEscape":              {"passthrough": [0], "safe": True},
        "HtmlUtils.htmlEscapeDecimal":       {"passthrough": [0], "safe": True},
        "HtmlUtils.htmlEscapeHex":           {"passthrough": [0], "safe": True},
        "JavascriptUtils.javaScriptEscape":  {"passthrough": [0], "safe": True},

        # ===== Servlet =====
        "getParameter":         {"passthrough": [0], "safe": False},
        "getParameterValues":   {"passthrough": [0], "safe": False},
        "getParameterMap":      {"passthrough": [0], "safe": False},
        "getHeader":            {"passthrough": [0], "safe": False},
        "getHeaders":           {"passthrough": [0], "safe": False},
        "getHeaderNames":       {"passthrough": [], "safe": False},
        "getCookies":           {"passthrough": [0], "safe": False},
        "getQueryString":       {"passthrough": [0], "safe": False},
        "getRequestURI":        {"passthrough": [0], "safe": True},  # Server-side, not user input
        "getContextPath":       {"passthrough": [0], "safe": True},  # Server-side config
        "getPathInfo":          {"passthrough": [0], "safe": True},  # Server-side config
        "getInputStream":       {"passthrough": [0], "safe": False},
        "getReader":            {"passthrough": [0], "safe": False},
        "getAttribute":         {"passthrough": [0], "safe": True},  # Server-side attribute
        "getSession":           {"passthrough": [0], "safe": True},  # Server-side session
        "getServletContext":    {"passthrough": [0], "safe": True},  # Server-side context

        # ===== Response sinks =====
        "getWriter":            {"passthrough": [0], "safe": False},
        "getOutputStream":      {"passthrough": [0], "safe": False},
        "setHeader":            {"passthrough": [1], "safe": False},
        "addHeader":            {"passthrough": [1], "safe": False},
        "sendRedirect":         {"passthrough": [0], "safe": False},
        "sendError":            {"passthrough": [0], "safe": False},
        "addCookie":            {"passthrough": [0], "safe": False},

        # ===== MyBatis =====
        # ${} interpolation is unsafe, handled at rule level

        # ===== Jackson/Gson =====
        "readValue":            {"passthrough": [0], "safe": False},
        "readTree":             {"passthrough": [0], "safe": False},
        "writeValueAsString":   {"passthrough": [0], "safe": False},
        "toJson":               {"passthrough": [0], "safe": False},
        "fromJson":             {"passthrough": [0], "safe": False},

        # ===== Spring Boot =====
        "@SpringBootApplication":  {"passthrough": [], "safe": True},
        "@RestController":         {"passthrough": [], "safe": True},
        "@RequestMapping":         {"passthrough": [], "safe": True},
        "@GetMapping":             {"passthrough": [], "safe": True},
        "@PostMapping":            {"passthrough": [], "safe": True},
        "@PutMapping":             {"passthrough": [], "safe": True},
        "@DeleteMapping":          {"passthrough": [], "safe": True},
        "@PatchMapping":           {"passthrough": [], "safe": True},
        "@RequestParam":           {"passthrough": [0], "safe": False},
        "@PathVariable":           {"passthrough": [0], "safe": False},
        "@RequestBody":            {"passthrough": [0], "safe": False},
        "@RequestHeader":          {"passthrough": [0], "safe": False},
        "@CookieValue":            {"passthrough": [0], "safe": False},
        "@ModelAttribute":         {"passthrough": [0], "safe": False},
        "@ResponseBody":           {"passthrough": [], "safe": True},
        "@ResponseStatus":         {"passthrough": [], "safe": True},
        "@ExceptionHandler":       {"passthrough": [], "safe": True},
        "@ControllerAdvice":       {"passthrough": [], "safe": True},
        "ResponseEntity.ok":       {"passthrough": [0], "safe": False},
        "ResponseEntity.status":   {"passthrough": [0], "safe": False},
        "ResponseEntity.body":     {"passthrough": [0], "safe": False},
        "ResponseEntity.of":       {"passthrough": [0], "safe": False},
        "ResponseEntity.notFound": {"passthrough": [], "safe": True},
        "ResponseEntity.badRequest": {"passthrough": [], "safe": True},
        "RequestEntity.getBody":   {"passthrough": [0], "safe": False},
        "RequestEntity.getHeaders": {"passthrough": [0], "safe": False},
        "RequestEntity.getUrl":    {"passthrough": [0], "safe": False},

        # ===== Spring MVC =====
        "ModelAndView.addObject":          {"passthrough": [0], "safe": False},
        "Model.addAttribute":              {"passthrough": [0], "safe": False},
        "ModelMap.addAttribute":           {"passthrough": [0], "safe": False},
        "ModelMap.addAllAttributes":       {"passthrough": [0], "safe": False},
        "RedirectView.setUrl":             {"passthrough": [0], "safe": False},
        "RedirectAttributes.addAttribute": {"passthrough": [0], "safe": False},
        "RedirectAttributes.addFlashAttribute": {"passthrough": [0], "safe": False},
        "WebMvcConfigurer.addInterceptors":    {"passthrough": [0], "safe": False},
        "InternalResourceViewResolver":        {"passthrough": [0], "safe": False},
        "ContentNegotiatingViewResolver":      {"passthrough": [0], "safe": False},
        "MultipartFile.getInputStream":        {"passthrough": [0], "safe": False},
        "MultipartFile.getBytes":              {"passthrough": [0], "safe": False},
        "MultipartFile.getOriginalFilename":   {"passthrough": [0], "safe": False},
        "MultipartFile.transferTo":            {"passthrough": [0], "safe": False},
        "HttpServletRequest.getParameter":     {"passthrough": [0], "safe": False},
        "HttpServletRequest.getParameterValues": {"passthrough": [0], "safe": False},
        "HttpServletRequest.getParameterMap":  {"passthrough": [0], "safe": False},
        "HttpServletRequest.getHeader":        {"passthrough": [0], "safe": False},
        "HttpServletRequest.getQueryString":   {"passthrough": [0], "safe": False},
        "HttpServletRequest.getRequestURI":    {"passthrough": [0], "safe": False},
        "HttpServletRequest.getInputStream":   {"passthrough": [0], "safe": False},
        "HttpServletRequest.getReader":        {"passthrough": [0], "safe": False},
        "HttpServletResponse.getWriter":       {"passthrough": [0], "safe": False},
        "HttpServletResponse.getOutputStream": {"passthrough": [0], "safe": False},
        "HttpServletResponse.sendRedirect":    {"passthrough": [0], "safe": False},
        "HttpServletResponse.setHeader":       {"passthrough": [1], "safe": False},
        "HttpServletResponse.addHeader":       {"passthrough": [1], "safe": False},
        "HttpServletResponse.setStatus":       {"passthrough": [], "safe": True},
        "HttpServletResponse.sendError":       {"passthrough": [0], "safe": False},

        # ===== Spring Security =====
        "@Secured":               {"passthrough": [], "safe": True},
        "@PreAuthorize":          {"passthrough": [], "safe": True},
        "@PostAuthorize":         {"passthrough": [], "safe": True},
        "@RolesAllowed":          {"passthrough": [], "safe": True},
        "@WithMockUser":          {"passthrough": [], "safe": True},
        "@EnableWebSecurity":     {"passthrough": [], "safe": True},
        "@EnableGlobalMethodSecurity": {"passthrough": [], "safe": True},
        "CsrfToken.getToken":     {"passthrough": [], "safe": True},
        "CsrfTokenRepository.loadToken": {"passthrough": [0], "safe": False},
        "CsrfTokenRepository.saveToken": {"passthrough": [0], "safe": False},
        "SecurityContextHolder.getContext":       {"passthrough": [], "safe": True},
        "SecurityContext.getAuthentication":      {"passthrough": [], "safe": True},
        "Authentication.getName":                 {"passthrough": [], "safe": True},
        "Authentication.getAuthorities":          {"passthrough": [], "safe": True},
        "Authentication.getCredentials":          {"passthrough": [0], "safe": False},
        "PasswordEncoder.encode":                 {"passthrough": [0], "safe": True},
        "PasswordEncoder.matches":                {"passthrough": [], "safe": True},
        "BCryptPasswordEncoder.encode":           {"passthrough": [0], "safe": True},
        "BCryptPasswordEncoder.matches":          {"passthrough": [], "safe": True},
        "UserDetails.getAuthorities":             {"passthrough": [], "safe": True},
        "UserDetails.getPassword":                {"passthrough": [0], "safe": True},
        "UserDetails.getUsername":                {"passthrough": [], "safe": True},
        "UsernamePasswordAuthenticationToken":    {"passthrough": [0], "safe": False},
        "OAuth2AuthenticationDetails.getTokenValue": {"passthrough": [0], "safe": False},
        "JwtDecoder.decode":                      {"passthrough": [0], "safe": False},
        "Jwt.getClaims":                          {"passthrough": [0], "safe": False},

        # ===== Hibernate =====
        "Session.createQuery":           {"passthrough": [0], "safe": False},
        "Session.createSQLQuery":        {"passthrough": [0], "safe": False},
        "Session.createCriteria":        {"passthrough": [0], "safe": False},
        "Session.get":                   {"passthrough": [0], "safe": False},
        "Session.load":                  {"passthrough": [0], "safe": False},
        "Session.save":                  {"passthrough": [0], "safe": False},
        "Session.persist":               {"passthrough": [0], "safe": False},
        "Session.update":                {"passthrough": [0], "safe": False},
        "Session.merge":                 {"passthrough": [0], "safe": False},
        "Session.delete":                {"passthrough": [0], "safe": False},
        "Session.evict":                 {"passthrough": [0], "safe": False},
        "Session.flush":                 {"passthrough": [], "safe": True},
        "Session.refresh":               {"passthrough": [0], "safe": False},
        "Query.setParameter":            {"passthrough": [0], "safe": False},
        "Query.setParameterList":        {"passthrough": [0], "safe": False},
        "Query.list":                    {"passthrough": [0], "safe": False},
        "Query.uniqueResult":            {"passthrough": [0], "safe": False},
        "Query.executeUpdate":           {"passthrough": [0], "safe": False},
        "Query.getQueryString":          {"passthrough": [0], "safe": False},
        "Criteria.add":                  {"passthrough": [0], "safe": False},
        "Criteria.list":                 {"passthrough": [0], "safe": False},
        "Criteria.uniqueResult":         {"passthrough": [0], "safe": False},
        "Criteria.setFirstResult":       {"passthrough": [0], "safe": False},
        "Criteria.setMaxResults":        {"passthrough": [0], "safe": False},
        "SQLQuery.addEntity":            {"passthrough": [0], "safe": False},
        "SQLQuery.list":                 {"passthrough": [0], "safe": False},
        "SQLQuery.executeUpdate":        {"passthrough": [0], "safe": False},
        "Transaction.commit":            {"passthrough": [], "safe": True},
        "Transaction.rollback":          {"passthrough": [], "safe": True},

        # ===== Apache Struts =====
        "ActionForm.validate":           {"passthrough": [0], "safe": False},
        "ActionForm.reset":              {"passthrough": [0], "safe": False},
        "ActionForm.getBean":            {"passthrough": [0], "safe": False},
        "ActionForm.setBean":            {"passthrough": [0], "safe": False},
        "ActionMapping.getInput":        {"passthrough": [], "safe": True},
        "ActionMapping.findForward":     {"passthrough": [0], "safe": False},
        "ActionMapping.getPath":         {"passthrough": [], "safe": True},
        "Action.execute":                {"passthrough": [0], "safe": False},
        "HttpServletRequest.getParameter": {"passthrough": [0], "safe": False},
        "ServletActionContext.getRequest":  {"passthrough": [], "safe": True},
        "ServletActionContext.getResponse": {"passthrough": [], "safe": True},
        "ActionContext.getContext":         {"passthrough": [], "safe": True},
        "ActionContext.getParameters":      {"passthrough": [0], "safe": False},
        "ValueStack.findValue":             {"passthrough": [0], "safe": False},
        "ValueStack.setValue":              {"passthrough": [0], "safe": False},
        "ValueStack.peek":                  {"passthrough": [0], "safe": False},
        "ValueStack.pop":                   {"passthrough": [0], "safe": False},
        "ValueStack.push":                  {"passthrough": [0], "safe": False},
        "TextProvider.getText":             {"passthrough": [0], "safe": False},
        "ActionSupport.execute":            {"passthrough": [0], "safe": False},
        "ActionSupport.validate":           {"passthrough": [], "safe": True},
        "ActionSupport.addActionError":     {"passthrough": [0], "safe": False},
        "ActionSupport.addActionMessage":   {"passthrough": [0], "safe": False},
        "ActionSupport.addFieldError":      {"passthrough": [0], "safe": False},

        # ===== Apache HttpClient =====
        "HttpClient.execute":             {"passthrough": [0], "safe": False},
        "HttpClient.executeMethod":       {"passthrough": [0], "safe": False},
        "HttpGet":                        {"passthrough": [0], "safe": False},
        "HttpPost":                       {"passthrough": [0], "safe": False},
        "HttpPut":                        {"passthrough": [0], "safe": False},
        "HttpDelete":                     {"passthrough": [0], "safe": False},
        "HttpPatch":                      {"passthrough": [0], "safe": False},
        "HttpHead":                       {"passthrough": [0], "safe": False},
        "HttpOptions":                    {"passthrough": [0], "safe": False},
        "HttpGet.getURI":                 {"passthrough": [0], "safe": False},
        "HttpPost.getEntity":             {"passthrough": [0], "safe": False},
        "HttpPost.setEntity":             {"passthrough": [0], "safe": False},
        "HttpResponse.getEntity":         {"passthrough": [0], "safe": False},
        "HttpResponse.getStatusLine":     {"passthrough": [], "safe": True},
        "HttpResponse.getAllHeaders":     {"passthrough": [0], "safe": False},
        "HttpResponse.getFirstHeader":    {"passthrough": [0], "safe": False},
        "HttpEntity.getContent":          {"passthrough": [0], "safe": False},
        "EntityUtils.toString":           {"passthrough": [0], "safe": False},
        "EntityUtils.toByteArray":        {"passthrough": [0], "safe": False},
        "URIBuilder":                     {"passthrough": [0], "safe": False},
        "URIBuilder.addParameter":        {"passthrough": [0], "safe": False},
        "URIBuilder.setParameters":       {"passthrough": [0], "safe": False},
        "URIBuilder.build":               {"passthrough": [0], "safe": False},
        "StringEntity":                   {"passthrough": [0], "safe": False},
        "UrlEncodedFormEntity":           {"passthrough": [0], "safe": False},
        "NameValuePair":                  {"passthrough": [0], "safe": False},
        "HttpClientBuilder.build":        {"passthrough": [], "safe": True},
        "HttpClientBuilder.create":       {"passthrough": [], "safe": True},
}


def lookup(func_name: str) -> Optional[Dict[str, Union[List[int], bool]]]:
    """
    查询该语言的内置函数知识库

    :param func_name: 函数/方法名
    :return: {"passthrough": [...], "safe": bool, "param_flow": dict} 或 None
    """
    # 精确匹配
    if func_name in KNOWLEDGE:
        return KNOWLEDGE[func_name]

    # 短名匹配（方法名不带类/模块前缀）
    # 如 "html.escape" -> 尝试 "escape"
    if "." in func_name:
        short_name = func_name.split(".")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]

    return None