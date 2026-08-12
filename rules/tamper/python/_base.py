# -*- coding: utf-8 -*-
"""
    Python base config (standard library)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Python 标准库修复函数和可控输入源配置（基础配置，非框架配置）

    修复函数绑定说明：
    - 键：精确函数名（用于 is_repair 精确匹配）
    - 值：CVI 编号列表（svid），表示该函数能防御哪些漏洞类型
    - 编号对应 rules/python/CVI_XXXX.py 中的 svid

    :author:    LoRexxar <LoRexxar@gmail.com>
    :homepage:  https://github.com/LoRexxar/Kunlun-M
    :license:   MIT, see LICENSE for more details.
    :copyright: Copyright (c) 2017 LoRexxar. All rights reserved.
"""

# 修复函数 → 可防御的 CVI 编号
IS_REPAIR = {
    # ---- XSS 防御 (7008) ----
    # HTML 转义，防止 XSS
    "html.escape": [7008],
    "markupsafe.escape": [7008],
    "markupsafe.Markup.escape": [7008],
    # JSON 序列化输出（不会执行 HTML/JS）
    "json.dumps": [7008],
    "json.dumps.html_safe_dumps": [7008],

    # ---- 命令注入防御 (7000) ----
    # Shell 参数转义
    "shlex.quote": [7000],

    # ---- SQL 注入防御 (7002) ----
    # 参数化查询 / ORM 方法（不直接拼接 SQL）
    "execute": [7002],
    "executemany": [7002],
    # SQLAlchemy text().bindparams
    "text": [7002],

    # ---- 反序列化防御 (7003) ----
    # 安全 YAML 加载
    "safe_load": [7003],
    "yaml.safe_load": [7003],
    "yaml.safe_load_all": [7003],
    # JSON 反序列化（本身安全）
    "json.loads": [7003],
    "json.load": [7003],

    # ---- 代码执行防御 (7001) ----
    # 安全表达式求值（不执行任意代码）
    "ast.literal_eval": [7001, 7014],

    # ---- SSRF 防御 (7004) ----
    # URL 解析验证
    "urllib.parse.urlparse": [7004],
    "urlparse": [7004],
    "urlparse.urlparse": [7004],

    # ---- SSTI 防御 (7006) ----
    # 模板引擎的自动转义 / 手动转义
    "markupsafe.escape": [7006],
    "jinja2.Markup.escape": [7006],
    "jinja2.escape": [7006],
    # 类型转换（确保不会注入模板表达式）
    "str": [7006],
    # string.Template.substitute only does $variable replacement,
    # NOT Python expression evaluation. Safe for SSTI/expr injection.
    "substitute": [7006, 7014],
    "safe_substitute": [7006, 7014],

    # ---- XXE 防御 (7011) ----
    # 安全 XML 解析库
    "defusedxml.parse": [7011],
    "defusedxml.ElementTree.parse": [7011],
    "defusedxml.minidom.parseString": [7011],
    "defusedxml.expatparser.parse": [7011],

    # ---- XPath 注入防御 (7012) ----
    # lxml 参数化 XPath
    "lxml.etree.XPath": [7012],

    # ---- 文件操作防御 (7005) / 路径穿越防御 (7009) ----
    # 路径规范化（限制在预期目录内）
    "os.path.basename": [7005, 7009],
    "os.path.normpath": [7005, 7009],
    "pathlib.Path.resolve": [7005, 7009],
    "posixpath.basename": [7005, 7009],

    # ---- 通用类型转换（多漏洞防御） ----
    # int/float 将输入转为数字，消除注入向量
    "int": [7000, 7001, 7002, 7004, 7010],
    "float": [7000, 7001, 7002, 7004, 7010],
    "bool": [7000, 7001, 7002, 7004, 7010],
}

# 可控输入源
IS_CONTROLLED = [
    # Flask / Django / Tornado
    "request.args",
    "request.form",
    "request.data",
    "request.json",
    "request.files",
    "request.values",
    "request.headers",
    "request.GET",
    "request.POST",
    "request.FILES",
    "request.body",
    "request.META",
    "request.COOKIES",
    "request.method",
    # Flask
    "flask.request",
    # Tornado
    "self.request.get_argument",
    # Django
    "GET",
    "POST",
    # 标准输入
    "input()",
    "sys.argv",
    # 环境变量
    "os.environ",
    "environ.get",
    "environ",
    # CGI
    "cgi.FieldStorage",
    "cgi.parse_qs",
]
