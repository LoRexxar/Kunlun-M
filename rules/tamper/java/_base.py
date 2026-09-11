# -*- coding: utf-8 -*-
"""
    Java base config (standard library)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Java 修复函数和可控输入源配置（基础配置，非框架配置）

    CVI 编号分类：
    - 6001/6021/6039/6043/6048: SQL注入
    - 6002/6022: XSS
    - 6003/6023: 命令注入
    - 6004/6025: 路径穿越
    - 6005: 反序列化
    - 6006/6024: SSRF
    - 6007: XXE
    - 6008: 不安全加密
    - 6009: 硬编码密码
    - 6010: 日志注入 (已移除)
    - 6011: 不安全文件上传
    - 6012: SpEL/OGNL 注入
    - 6013: LDAP 注入
    - 6014: 不安全 Cookie
    - 6015: 开放重定向
    - 6016: 不安全随机数
    - 6017: Log4Shell
    - 6018: 不安全反射
    - 6019: 不安全 CORS
    - 6020: 不安全 JWT
    - 6031: MyBatis SQL 注入
    - 6032: ProcessBuilder 命令注入
    - 6033: 路径穿越
    - 6034: SSRF
    - 6035: 反序列化
    - 6036: JNDI 注入
    - 6037/6045/6061/6062/6063: Fastjson 反序列化
    - 6038: ProcessBuilder 命令注入
    - 6039: MyBatis ${} 注入
    - 6040/6047/6066: Jackson 反序列化
    - 6041: SSTI
    - 6044/6065: XStream 反序列化
    - 6046/6060: Log4j JNDI
    - 6048: Hibernate HQL 注入
    - 6050-6053: Shiro
    - 6054-6057: Struts2
    - 6064: Commons Collections 反序列化
    - 6067: Spring Boot Actuator
    - 6068: Commons FileUpload 反序列化

    :author:    KunLun-M
    :license:   MIT, see LICENSE for more details.
"""

# 修复函数 → 可防御的 CVI 编号
IS_REPAIR = {
    # ---- SQL 注入防御 ----
    "prepareStatement": [6001, 6021, 6031, 6039, 6043, 6048],
    "PreparedStatement": [6001, 6021, 6031, 6039, 6043, 6048],
    "setString": [6001, 6021, 6031, 6039, 6043, 6048],
    "setInt": [6001, 6021, 6031, 6039, 6043, 6048],
    "setLong": [6001, 6021, 6031, 6039, 6043, 6048],
    "setObject": [6001, 6021, 6031, 6039, 6043, 6048],
    "setNull": [6001, 6021, 6031, 6039, 6043, 6048],
    "jdbcTemplate.query": [6043],
    "jdbcTemplate.update": [6043],
    "JdbcTemplate.query": [6043],
    "JdbcTemplate.update": [6043],
    "createQuery": [6048],
    "setParameter": [6048],
    "Integer.parseInt": [6001, 6021, 6031, 6039, 6043, 6048],
    "Long.parseLong": [6001, 6021, 6031, 6039, 6043, 6048],
    "Integer.valueOf": [6001, 6021, 6031, 6039, 6043, 6048],

    # ---- XSS 防御 ----
    "encodeForHTML": [6002, 6022],
    "escapeHtml": [6002, 6022],
    "escapeHtml4": [6002, 6022],
    "encodeForJavaScript": [6002, 6022],
    "encodeForURL": [6002, 6022],
    "encodeForCSS": [6002, 6022],
    "HtmlUtils.htmlEscape": [6002, 6022],
    "ESAPI.encoder().encodeForHTML": [6002, 6022],

    # ---- 命令注入防御 ----
    "escapeShellArg": [6003, 6023, 6032, 6038],

    # ---- 路径穿越防御 ----
    "normalize": [6004, 6025, 6033],
    "getCanonicalPath": [6004, 6025, 6033],
    "getAbsoluteFile": [6004, 6025, 6033],
    "toAbsolutePath": [6004, 6025, 6033],
    "getFileName": [6004, 6025, 6033, 6011],

    # ---- SSRF 防御 ----
    "isUrlAllowed": [6006, 6024, 6034],
    "validateUrl": [6006, 6024, 6034],
    "URI.create": [6006, 6024, 6034],
    "URL.getHost": [6006, 6024, 6034],
    "InetAddress.getByName": [6006, 6024, 6034],
    "Integer.parseInt": [6006, 6024, 6034],

    # ---- XXE 防御 ----
    "XMLInputFactory.setProperty": [6007],
    "setFeature": [6007],
    "disallowDoctypeDecl": [6007],
    "SAXParserFactory.newInstance": [6007],
    "DocumentBuilderFactory.newInstance": [6007],
    "TransformerFactory.newInstance": [6007],

    # ---- LDAP 注入防御 ----
    "escapeLDAPSearchFilter": [6013],

    # ---- 反序列化防御 ----
    "ObjectInputFilter": [6005, 6035],
    "resolveClass": [6005, 6035],
    "ObjectInputStream": [6005, 6035],
    "ObjectMapper": [6005, 6035, 6037, 6040, 6045, 6047, 6061, 6062, 6063, 6066],
    "JSONObject": [6005, 6035],
    "JSON.parseObject": [6005, 6035, 6037, 6040, 6045, 6061, 6062, 6063],
    "Gson": [6005, 6035, 6040, 6047, 6066],
    "fromJson": [6005, 6035, 6040, 6047, 6066],

    # ---- 开放重定向防御 ----
    "URI.create": [6015],
    "URL": [6015],
    "getHost": [6015],
    "startsWith": [6015],

    # ---- SSTI 防御 ----
    "HtmlUtils.htmlEscape": [6041],
    "StringEscapeUtils.escapeHtml4": [6041],
    "escapeHtml4": [6041],

    # ---- Cookie 安全 ----
    "setHttpOnly": [6014],
    "setSecure": [6014],
    "setPath": [6014],

    # ---- CORS 防御 ----
    "setAllowedOrigins": [6019],
    "allowedOrigins": [6019],
}

# 可控输入源
IS_CONTROLLED = [
    # Servlet API
    "request",
    "request.getParameter",
    "request.getParameterValues",
    "request.getParameterMap",
    "request.getHeader",
    "request.getHeaders",
    "request.getInputStream",
    "request.getReader",
    "request.getCookies",
    "request.getQueryString",
    "request.getRequestURI",
    "request.getRequestURL",
    "request.getRemoteAddr",
    "request.getRemoteHost",
    "request.getMethod",
    "request.getContentType",
    "request.getServerName",
    # Spring
    "@RequestParam",
    "@PathVariable",
    "@RequestBody",
    "@RequestHeader",
    "@CookieValue",
    # 环境变量
    "System.getenv",
    "System.getProperty",
    # 标准输入
    "System.in",
    "Scanner",
    "BufferedReader",
]
