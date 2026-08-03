"""
PYTHON 内置函数/方法可控性知识库

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
        # ===== 字符串方法（透传 self） =====
        "str.upper":        {"passthrough": [0], "safe": False},
        "str.lower":        {"passthrough": [0], "safe": False},
        "str.strip":        {"passthrough": [0], "safe": False},
        "str.lstrip":       {"passthrough": [0], "safe": False},
        "str.rstrip":       {"passthrough": [0], "safe": False},
        "str.capitalize":   {"passthrough": [0], "safe": False},
        "str.title":        {"passthrough": [0], "safe": False},
        "str.swapcase":     {"passthrough": [0], "safe": False},
        "str.replace":      {"passthrough": [0], "safe": False},
        "str.split":        {"passthrough": [0], "safe": False},
        "str.rsplit":       {"passthrough": [0], "safe": False},
        "str.splitlines":   {"passthrough": [0], "safe": False},
        "str.encode":       {"passthrough": [0], "safe": False},
        "str.decode":       {"passthrough": [0], "safe": False},
        "str.format":       {"passthrough": [0], "safe": False},
        "str.join":         {"passthrough": [1], "safe": False},
        "str.center":       {"passthrough": [0], "safe": False},
        "str.ljust":        {"passthrough": [0], "safe": False},
        "str.rjust":        {"passthrough": [0], "safe": False},
        "str.zfill":        {"passthrough": [0], "safe": False},
        "str.expandtabs":   {"passthrough": [0], "safe": False},
        "str.removeprefix": {"passthrough": [0], "safe": False},
        "str.removesuffix": {"passthrough": [0], "safe": False},
        "str.casefold":     {"passthrough": [0], "safe": False},
        "str.translate":    {"passthrough": [0], "safe": False},

        # ===== 内置类型转换（透传参数） =====
        "str":              {"passthrough": [0], "safe": False},
        "int":              {"passthrough": [], "safe": True},   # 返回整数
        "float":            {"passthrough": [], "safe": True},   # 返回浮点数
        "bool":             {"passthrough": [], "safe": True},   # 返回布尔值
        "bytes":            {"passthrough": [0], "safe": False},
        "bytearray":        {"passthrough": [0], "safe": False},
        "list":             {"passthrough": [0], "safe": False},
        "dict":             {"passthrough": [0], "safe": False},
        "tuple":            {"passthrough": [0], "safe": False},
        "set":              {"passthrough": [0], "safe": False},
        "frozenset":        {"passthrough": [0], "safe": False},
        "repr":             {"passthrough": [0], "safe": False},
        "format":           {"passthrough": [0], "safe": False},
        "sorted":           {"passthrough": [0], "safe": False},
        "reversed":         {"passthrough": [0], "safe": False},
        "enumerate":        {"passthrough": [0], "safe": False},
        "zip":              {"passthrough": [0, 1], "safe": False},
        "map":              {"passthrough": [1], "safe": False},
        "filter":           {"passthrough": [1], "safe": False},
        "slice":            {"passthrough": [0], "safe": False},
        "ord":              {"passthrough": [], "safe": True},   # 返回整数
        "chr":              {"passthrough": [], "safe": True},   # 返回单字符
        "hex":              {"passthrough": [], "safe": True},
        "oct":              {"passthrough": [], "safe": True},
        "bin":              {"passthrough": [], "safe": True},

        # ===== 不透传（返回值与输入无关） =====
        "len":              {"passthrough": [], "safe": True},
        "type":             {"passthrough": [], "safe": True},
        "isinstance":       {"passthrough": [], "safe": True},
        "issubclass":       {"passthrough": [], "safe": True},
        "id":               {"passthrough": [], "safe": True},
        "hash":             {"passthrough": [], "safe": True},
        "dir":              {"passthrough": [], "safe": True},
        "vars":             {"passthrough": [], "safe": True},
        "callable":         {"passthrough": [], "safe": True},
        "hasattr":          {"passthrough": [], "safe": True},
        "getattr":          {"passthrough": [0], "safe": False},
        "setattr":          {"passthrough": [], "safe": True, "param_flow": {0: 2}},
        "abs":              {"passthrough": [], "safe": True},
        "round":            {"passthrough": [], "safe": True},
        "min":              {"passthrough": [0], "safe": False},
        "max":              {"passthrough": [0], "safe": False},
        "sum":              {"passthrough": [], "safe": True},
        "any":              {"passthrough": [], "safe": True},
        "all":              {"passthrough": [], "safe": True},
        "range":            {"passthrough": [], "safe": True},
        "print":            {"passthrough": [], "safe": True},

        # ===== 编解码（透传但不安全） =====
        "base64.b64encode":     {"passthrough": [0], "safe": False},
        "base64.b64decode":     {"passthrough": [0], "safe": False},
        "base64.urlsafe_b64encode": {"passthrough": [0], "safe": False},
        "base64.urlsafe_b64decode": {"passthrough": [0], "safe": False},
        "json.dumps":           {"passthrough": [0], "safe": False},
        "json.loads":           {"passthrough": [0], "safe": False},
        "pickle.dumps":         {"passthrough": [0], "safe": False},
        "pickle.loads":         {"passthrough": [0], "safe": False},  # 不安全但透传
        "urllib.parse.quote":   {"passthrough": [0], "safe": False},
        "urllib.parse.unquote": {"passthrough": [0], "safe": False},
        "urllib.parse.urlencode": {"passthrough": [0], "safe": False},
        "urllib.parse.urlparse":  {"passthrough": [0], "safe": False},
        "yaml.dump":            {"passthrough": [0], "safe": False},
        "yaml.load":            {"passthrough": [0], "safe": False},

        # ===== 代码执行/命令执行（危险 sink） =====
        "eval":               {"passthrough": [0], "safe": False},
        "exec":               {"passthrough": [], "safe": False},
        "os.system":          {"passthrough": [0], "safe": False},
        "os.popen":           {"passthrough": [0], "safe": False},
        "subprocess.Popen":   {"passthrough": [0], "safe": False},
        "subprocess.call":    {"passthrough": [0], "safe": False},
        "subprocess.run":     {"passthrough": [0], "safe": False},
        "subprocess.check_output": {"passthrough": [0], "safe": False},
        "os.execv":            {"passthrough": [0], "safe": False},
        "os.execvp":           {"passthrough": [0], "safe": False},

        # ===== 输入源（source） =====
        "input":              {"passthrough": [], "safe": False},  # Python 3 input
        "open":               {"passthrough": [0], "safe": False},  # 文件内容透传
        "urllib.request.urlopen": {"passthrough": [0], "safe": False},

        # ===== 安全过滤函数 =====
        "html.escape":              {"passthrough": [0], "safe": True},
        "markupsafe.escape":        {"passthrough": [0], "safe": True},
        "markupsafe.Markup":        {"passthrough": [0], "safe": True},
        "bleach.clean":             {"passthrough": [0], "safe": True},
        "bleach.linkify":           {"passthrough": [0], "safe": True},
        "cgi.escape":               {"passthrough": [0], "safe": True},
        "xml.sax.saxutils.escape":  {"passthrough": [0], "safe": True},
        "re.escape":                {"passthrough": [0], "safe": True},
        "shlex.quote":              {"passthrough": [0], "safe": True},
        "werkzeug.utils.escape":    {"passthrough": [0], "safe": True},
        "django.utils.html.escape": {"passthrough": [0], "safe": True},
        "django.utils.http.urlquote": {"passthrough": [0], "safe": True},

        # ===== 文件/IO（透传路径参数） =====
        "os.path.join":         {"passthrough": [0, 1], "safe": False},
        "os.path.normpath":     {"passthrough": [0], "safe": False},
        "os.path.abspath":      {"passthrough": [0], "safe": False},
        "os.path.realpath":     {"passthrough": [0], "safe": False},
        "os.path.basename":     {"passthrough": [0], "safe": False},
        "os.path.dirname":      {"passthrough": [0], "safe": False},
        "os.path.expanduser":   {"passthrough": [0], "safe": False},

        # ===== 正则匹配 =====
        "re.sub":       {"passthrough": [2], "safe": False},  # 透传 subject(第3个参数)
        "re.match":     {"passthrough": [1], "safe": False},
        "re.search":    {"passthrough": [1], "safe": False},
        "re.findall":   {"passthrough": [1], "safe": False},
        "re.split":     {"passthrough": [1], "safe": False},

        # ===== Django =====
        "django.utils.safestring.mark_safe":  {"passthrough": [0], "safe": False},  # 标记安全但不实际过滤
        "django.utils.safestring.SafeString": {"passthrough": [0], "safe": False},
        "django.template.loader.render_to_string": {"passthrough": [0], "safe": False},

        # ===== Flask =====
        "flask.escape":            {"passthrough": [0], "safe": True},  # 同 markupsafe.escape
        "flask.render_template":   {"passthrough": [0], "safe": False},
        "flask.render_template_string": {"passthrough": [0], "safe": False},
        "flask.redirect":          {"passthrough": [0], "safe": False},
        "flask.url_for":           {"passthrough": [], "safe": True},
        "flask.jsonify":           {"passthrough": [0], "safe": False},
        "flask.send_file":         {"passthrough": [0], "safe": False},

        # ===== FastAPI/Starlette =====
        "fastapi.Query":    {"passthrough": [0], "safe": False},
        "fastapi.Path":     {"passthrough": [0], "safe": False},
        "fastapi.Body":     {"passthrough": [0], "safe": False},
        "fastapi.Form":     {"passthrough": [0], "safe": False},
        "fastapi.File":     {"passthrough": [0], "safe": False},
        "fastapi.Depends":  {"passthrough": [0], "safe": False},
        "starlette.responses.HTMLResponse": {"passthrough": [0], "safe": False},
        "starlette.responses.JSONResponse": {"passthrough": [0], "safe": False},

        # ===== Tornado =====
        "tornado.escape.xhtml_escape":  {"passthrough": [0], "safe": True},
        "tornado.escape.url_escape":    {"passthrough": [0], "safe": False},
        "tornado.escape.json_encode":   {"passthrough": [0], "safe": False},
        "tornado.escape.squeeze":       {"passthrough": [0], "safe": False},

        # ===== Jinja2 =====
        "jinja2.escape":     {"passthrough": [0], "safe": True},
        "jinja2.Markup":     {"passthrough": [0], "safe": False},  # 标记安全但不过滤

        # ===== Celery =====
        "celery.utils.serialization.unpickle": {"passthrough": [0], "safe": False},

        # ===== SQLAlchemy =====
        "sqlalchemy.orm.Query.filter":            {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.filter_by":         {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.query":             {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.all":               {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.first":             {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.get":               {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.one":               {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.one_or_none":       {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.scalar":            {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.count":             {"passthrough": [], "safe": True},
        "sqlalchemy.orm.Query.order_by":          {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.group_by":          {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.having":            {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.join":              {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.outerjoin":         {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.limit":             {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.offset":            {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.from_self":         {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.subquery":          {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.union":             {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.Query.with_entities":     {"passthrough": [0], "safe": False},
        "sqlalchemy.orm.session.make_transient":  {"passthrough": [0], "safe": False},
        "sqlalchemy.sql.text":                    {"passthrough": [0], "safe": False},

        # ===== Django REST framework =====
        "rest_framework.serializers.Serializer.to_representation":  {"passthrough": [0], "safe": False},
        "rest_framework.serializers.Serializer.data":              {"passthrough": [0], "safe": False},
        "rest_framework.serializers.Serializer.is_valid":          {"passthrough": [], "safe": True},
        "rest_framework.serializers.Serializer.save":              {"passthrough": [0], "safe": False},
        "rest_framework.serializers.Serializer.create":            {"passthrough": [0], "safe": False},
        "rest_framework.serializers.Serializer.update":            {"passthrough": [0], "safe": False},
        "rest_framework.serializers.ModelSerializer.to_representation": {"passthrough": [0], "safe": False},
        "rest_framework.serializers.ModelSerializer.data":         {"passthrough": [0], "safe": False},
        "rest_framework.response.Response":                       {"passthrough": [0], "safe": False},
        "rest_framework.views.APIView":                            {"passthrough": [0], "safe": False},
        "rest_framework.generics.ListAPIView":                     {"passthrough": [0], "safe": False},
        "rest_framework.generics.RetrieveAPIView":                 {"passthrough": [0], "safe": False},
        "rest_framework.generics.CreateAPIView":                   {"passthrough": [0], "safe": False},
        "rest_framework.generics.UpdateAPIView":                   {"passthrough": [0], "safe": False},
        "rest_framework.generics.DestroyAPIView":                  {"passthrough": [0], "safe": False},
        "rest_framework.decorators.api_view":                      {"passthrough": [0], "safe": False},
        "rest_framework.parsers.JSONParser.parse":                 {"passthrough": [0], "safe": False},
        "rest_framework.parsers.FormParser.parse":                 {"passthrough": [0], "safe": False},
        "rest_framework.parsers.MultiPartParser.parse":            {"passthrough": [0], "safe": False},

        # ===== Pandas =====
        "pandas.read_csv":            {"passthrough": [0], "safe": False},
        "pandas.read_excel":          {"passthrough": [0], "safe": False},
        "pandas.read_json":           {"passthrough": [0], "safe": False},
        "pandas.read_sql":            {"passthrough": [0], "safe": False},
        "pandas.read_html":           {"passthrough": [0], "safe": False},
        "pandas.read_pickle":         {"passthrough": [0], "safe": False},
        "pandas.read_parquet":        {"passthrough": [0], "safe": False},
        "pandas.read_feather":        {"passthrough": [0], "safe": False},
        "pandas.read_hdf":            {"passthrough": [0], "safe": False},
        "pandas.read_clipboard":      {"passthrough": [], "safe": False},
        "pandas.DataFrame":           {"passthrough": [0], "safe": False},
        "pandas.Series":              {"passthrough": [0], "safe": False},
        "pandas.concat":              {"passthrough": [0], "safe": False},
        "pandas.merge":               {"passthrough": [0, 1], "safe": False},
        "pandas.merge_ordered":       {"passthrough": [0, 1], "safe": False},
        "pandas.merge_asof":          {"passthrough": [0, 1], "safe": False},
        "pandas.DataFrame.to_csv":    {"passthrough": [0], "safe": False},
        "pandas.DataFrame.to_excel":  {"passthrough": [0], "safe": False},
        "pandas.DataFrame.to_json":   {"passthrough": [0], "safe": False},
        "pandas.DataFrame.to_html":   {"passthrough": [0], "safe": False},
        "pandas.DataFrame.to_dict":   {"passthrough": [0], "safe": False},
        "pandas.DataFrame.query":     {"passthrough": [0], "safe": False},
        "pandas.DataFrame.eval":      {"passthrough": [0], "safe": False},
        "pandas.DataFrame.apply":     {"passthrough": [0], "safe": False},
        "pandas.DataFrame.applymap":  {"passthrough": [0], "safe": False},
        "pandas.DataFrame.groupby":   {"passthrough": [0], "safe": False},
        "pandas.DataFrame.sort_values": {"passthrough": [0], "safe": False},
        "pandas.DataFrame.filter":    {"passthrough": [0], "safe": False},
        "pandas.DataFrame.drop":      {"passthrough": [0], "safe": False},
        "pandas.DataFrame.fillna":    {"passthrough": [0], "safe": False},
        "pandas.DataFrame.replace":   {"passthrough": [0], "safe": False},
        "pandas.DataFrame.astype":    {"passthrough": [0], "safe": False},
        "pandas.eval":                {"passthrough": [0], "safe": False},

        # ===== Requests =====
        "requests.get":               {"passthrough": [0], "safe": False},
        "requests.post":              {"passthrough": [0], "safe": False},
        "requests.put":               {"passthrough": [0], "safe": False},
        "requests.delete":            {"passthrough": [0], "safe": False},
        "requests.patch":             {"passthrough": [0], "safe": False},
        "requests.head":              {"passthrough": [0], "safe": False},
        "requests.options":           {"passthrough": [0], "safe": False},
        "requests.request":           {"passthrough": [0], "safe": False},
        "requests.Session":           {"passthrough": [], "safe": True},
        "requests.Session.get":       {"passthrough": [0], "safe": False},
        "requests.Session.post":      {"passthrough": [0], "safe": False},
        "requests.Session.put":       {"passthrough": [0], "safe": False},
        "requests.Session.delete":    {"passthrough": [0], "safe": False},
        "requests.Session.send":      {"passthrough": [0], "safe": False},
        "requests.Session.request":   {"passthrough": [0], "safe": False},
        "requests.Response.text":     {"passthrough": [0], "safe": False},
        "requests.Response.json":     {"passthrough": [0], "safe": False},
        "requests.Response.content":  {"passthrough": [0], "safe": False},

        # ===== BeautifulSoup =====
        "bs4.BeautifulSoup":                   {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.find":              {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.find_all":          {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.select":            {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.select_one":        {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.get_text":          {"passthrough": [0], "safe": True},
        "bs4.BeautifulSoup.strings":           {"passthrough": [0], "safe": False},
        "bs4.BeautifulSoup.stripped_strings":  {"passthrough": [0], "safe": False},
        "bs4.element.Tag.find":                {"passthrough": [0], "safe": False},
        "bs4.element.Tag.find_all":            {"passthrough": [0], "safe": False},
        "bs4.element.Tag.select":              {"passthrough": [0], "safe": False},
        "bs4.element.Tag.select_one":          {"passthrough": [0], "safe": False},
        "bs4.element.Tag.get_text":            {"passthrough": [0], "safe": True},
        "bs4.element.Tag.get":                 {"passthrough": [0], "safe": False},
        "bs4.element.Tag.text":                {"passthrough": [0], "safe": True},
        "bs4.element.Tag.string":              {"passthrough": [0], "safe": True},
        "bs4.element.Tag.decode":              {"passthrough": [0], "safe": False},
        "bs4.element.Tag.encode":              {"passthrough": [0], "safe": False},
        "bs4.element.Tag.prettify":            {"passthrough": [0], "safe": False},
        "bs4.element.Tag.contents":            {"passthrough": [0], "safe": False},
        "bs4.element.Tag.children":            {"passthrough": [0], "safe": False},
        "bs4.element.Tag.parent":              {"passthrough": [0], "safe": False},

        # ===== lxml =====
        "lxml.etree.fromstring":        {"passthrough": [0], "safe": False},
        "lxml.etree.parse":             {"passthrough": [0], "safe": False},
        "lxml.etree.XML":               {"passthrough": [0], "safe": False},
        "lxml.etree.HTML":              {"passthrough": [0], "safe": False},
        "lxml.etree.tostring":          {"passthrough": [0], "safe": False},
        "lxml.etree.tounicode":         {"passthrough": [0], "safe": False},
        "lxml.etree.SubElement":        {"passthrough": [0], "safe": False},
        "lxml.etree.Element":           {"passthrough": [0], "safe": False},
        "lxml.etree.xpath":             {"passthrough": [0], "safe": False},
        "lxml.etree.xpathevaluate":     {"passthrough": [0], "safe": False},
        "lxml.etree.CleanupNamespaces": {"passthrough": [0], "safe": False},
        "lxml.etree.strip_tags":        {"passthrough": [0], "safe": False},
        "lxml.etree.strip_elements":    {"passthrough": [0], "safe": False},
        "lxml.html.fromstring":         {"passthrough": [0], "safe": False},
        "lxml.html.parse":              {"passthrough": [0], "safe": False},
        "lxml.html.tostring":           {"passthrough": [0], "safe": False},
        "lxml.html.clean.clean_html":   {"passthrough": [0], "safe": True},
        "lxml.html.soupparser.fromstring": {"passthrough": [0], "safe": False},

        # ===== OS temp file/dir generators (return framework-controlled paths) =====
        "os.mkstemp":                     {"passthrough": [], "safe": True},
        "os.mkdtemp":                     {"passthrough": [], "safe": True},
        "mkstemp":                        {"passthrough": [], "safe": True},
        "mkdtemp":                        {"passthrough": [], "safe": True},

        # ===== Django URL builders (return internal URLs, not user input) =====
        "reverse":                        {"passthrough": [], "safe": True},
        "get_redirect_url":               {"passthrough": [], "safe": True},
        "get_success_url":                {"passthrough": [], "safe": True},
        "get_absolute_url":               {"passthrough": [], "safe": True},

        # ===== Path sanitization =====
        "canonicalize":                   {"passthrough": [], "safe": True},
        "normalize":                      {"passthrough": [], "safe": True},
        "sanitize":                       {"passthrough": [], "safe": True},
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