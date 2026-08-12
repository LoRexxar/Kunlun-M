# -*- coding: utf-8 -*-
"""
    PHP base config (standard library)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    PHP 标准库修复函数和可控输入源配置（基础配置，非框架配置）

    CVI 编号对照：
    - 1000: SQL注入 (PDO/mysqli)
    - 1001: SSRF (cURL)
    - 1002: SSRF (file_get_contents)
    - 1003: SSRF (get_headers)
    - 1004: SQL注入 (mysql)
    - 1005: SQL注入 (mysql_old)
    - 1006: SQL注入 (mysqli)
    - 1007: RFI (文件包含)
    - 1008: XXE/XML注入
    - 1009: 命令注入 (exec/passthru)
    - 1010: LDAP注入
    - 1011: 代码执行 (eval/assert)
    - 1012: 信息泄露 (var_dump)
    - 1013: URL重定向
    - 1014: 变量覆盖
    - 1015: 反序列化
    - 10001: SSTI (Twig/Smarty)
    - 10002: SSTI (Blade/Other)

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

IS_REPAIR = {
    # ---- XSS / SSTI 防御 ----
    # HTML 实体转义
    "htmlspecialchars": [1000, 10001, 10002, 1012],
    "htmlentities": [1000, 10001, 10002, 1012],
    # URL 编码
    "urlencode": [1000, 10001, 10002],
    "rawurlencode": [1000, 10001, 10002],
    # 哈希（不可逆，消除原始值）
    "md5": [1000, 10001, 10002, 1012],
    "sha1": [1000, 10001, 10002, 1012],

    # ---- SQL 注入防御 ----
    # 参数化查询相关
    "intval": [1000, 1004, 1005, 1006, 1001, 1002, 1003, 1007, 1009, 1011, 1013],
    "floatval": [1000, 1004, 1005, 1006, 1001, 1002, 1003],
    "mysql_real_escape_string": [1004, 1005, 1006],
    "mysqli_real_escape_string": [1004, 1005, 1006],
    "mysqli_escape_string": [1004, 1005, 1006],
    "addslashes": [1004, 1005, 1006],
    "pg_escape_string": [1000],
    "PDO::quote": [1000],

    # ---- 命令注入防御 (1009) ----
    "escapeshellcmd": [1009, 1011],
    "escapeshellarg": [1009, 1011],

    # ---- SSRF 防御 (1001, 1002, 1003) ----
    # URL 解析验证
    "parse_url": [1001, 1002, 1003],
    "filter_var": [1001, 1002, 1003, 1013],  # FILTER_VALIDATE_URL/FILTER_VALIDATE_IP
    "gethostbyname": [1001, 1002, 1003],  # DNS 解析（可用于验证 IP）
    "dns_get_record": [1001, 1002, 1003],

    # ---- XXE/XML 注入防御 (1008) ----
    "libxml_disable_entity_loader": [1008],
    "libxml_use_internal_errors": [1008],

    # ---- LDAP 注入防御 (1010) ----
    "ldap_escape": [1010],

    # ---- 信息泄露防御 (1012) ----
    # 主要是代码审计问题，没有运行时修复函数

    # ---- URL 重定向防御 (1013) ----
    "parse_url": [1013],
    "filter_var": [1013],

    # ---- 反序列化防御 (1015) ----
    # 没有安全的 unserialize 替代，json_decode 是替代方案
    "json_decode": [1015],
    "json_encode": [1015],

    # ---- 文件包含防御 (1007) ----
    # basename 限制路径范围
    "basename": [1007, 1004],
    "realpath": [1007],

    # ---- 变量覆盖防御 (1014) ----
    # 主要靠代码规范，没有运行时修复函数
}

IS_CONTROLLED = [
    # Superglobals
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_FILES",
    "$_COOKIE",
    "$_SERVER",
    "$_ENV",
    "$_SESSION",
    # 常见框架输入
    "file_get_contents(\"php://input\")",
    "php://input",
    # 环境变量
    "getenv",
    "$argv",
    "$argc",
    # HTTP 头
    "getallheaders",
    "apache_request_headers",
    # CGI
    "$HTTP_GET_VARS",
    "$HTTP_POST_VARS",
    "$HTTP_COOKIE_VARS",
    "$HTTP_SERVER_VARS",
]
