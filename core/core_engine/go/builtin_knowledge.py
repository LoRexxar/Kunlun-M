"""
GOLANG 内置函数/方法可控性知识库

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

        # ================================================================
        #  SOURCES — 用户可控输入（返回值不安全，透传参数）
        # ================================================================

        # ===== net/http 请求 Sources =====
        "http.Request.URL.Query.Get":    {"passthrough": [0], "safe": False},
        "Request.URL.Query.Get":         {"passthrough": [0], "safe": False},
        "r.URL.Query().Get":             {"passthrough": [0], "safe": False},
        "URL.Query.Get":                 {"passthrough": [0], "safe": False},

        "http.Request.FormValue":        {"passthrough": [0], "safe": False},
        "Request.FormValue":             {"passthrough": [0], "safe": False},
        "r.FormValue":                   {"passthrough": [0], "safe": False},
        "FormValue":                     {"passthrough": [0], "safe": False},

        "http.Request.PostFormValue":    {"passthrough": [0], "safe": False},
        "Request.PostFormValue":         {"passthrough": [0], "safe": False},
        "r.PostFormValue":               {"passthrough": [0], "safe": False},
        "PostFormValue":                 {"passthrough": [0], "safe": False},

        "http.Request.Header.Get":       {"passthrough": [0], "safe": False},
        "Request.Header.Get":            {"passthrough": [0], "safe": False},
        "r.Header.Get":                  {"passthrough": [0], "safe": False},
        "Header.Get":                    {"passthrough": [0], "safe": False},

        "http.Request.URL.Query":        {"passthrough": [0], "safe": False},
        "Request.URL.Query":             {"passthrough": [0], "safe": False},
        "r.URL.Query":                   {"passthrough": [0], "safe": False},

        "http.Request.URL.Path":         {"passthrough": [0], "safe": False},
        "Request.URL.Path":              {"passthrough": [0], "safe": False},
        "r.URL.Path":                    {"passthrough": [0], "safe": False},

        "http.Request.URL.RawPath":      {"passthrough": [0], "safe": False},
        "Request.URL.RawPath":           {"passthrough": [0], "safe": False},

        "http.Request.URL.String":       {"passthrough": [0], "safe": False},
        "Request.URL.String":            {"passthrough": [0], "safe": False},

        "http.Request.URL.Host":         {"passthrough": [0], "safe": False},
        "Request.URL.Host":              {"passthrough": [0], "safe": False},

        "http.Request.Host":             {"passthrough": [0], "safe": False},
        "Request.Host":                  {"passthrough": [0], "safe": False},

        "http.Request.Referer":          {"passthrough": [0], "safe": False},
        "Request.Referer":               {"passthrough": [0], "safe": False},

        "http.Request.UserAgent":        {"passthrough": [0], "safe": False},
        "Request.UserAgent":             {"passthrough": [0], "safe": False},

        "http.Request.Cookie":           {"passthrough": [0], "safe": False},
        "Request.Cookie":                {"passthrough": [0], "safe": False},

        "http.Request.FormValue":        {"passthrough": [0], "safe": False},
        "http.Request.MultipartForm":    {"passthrough": [0], "safe": False},
        "Request.MultipartForm":         {"passthrough": [0], "safe": False},

        "http.Request.ParseForm":        {"passthrough": [0], "safe": False},
        "Request.ParseForm":             {"passthrough": [0], "safe": False},

        "http.Request.ParseMultipartForm": {"passthrough": [0], "safe": False},
        "Request.ParseMultipartForm":    {"passthrough": [0], "safe": False},

        # ===== os 环境变量/命令行 Sources =====
        "os.Getenv":     {"passthrough": [0], "safe": False},
        "os.LookupEnv":  {"passthrough": [0], "safe": False},
        "os.Args":       {"passthrough": [], "safe": False},  # source (CLI args)

        # ===== io/ioutil / os 文件读取 Sources =====
        "ioutil.ReadFile":  {"passthrough": [0], "safe": False},
        "os.ReadFile":      {"passthrough": [0], "safe": False},
        "ioutil.ReadAll":   {"passthrough": [0], "safe": False},
        "io.ReadAll":       {"passthrough": [0], "safe": False},

        # ===== bufio Sources =====
        "bufio.Scanner.Text":     {"passthrough": [0], "safe": False},
        "bufio.Scanner.Bytes":    {"passthrough": [0], "safe": False},
        "bufio.Reader.ReadString": {"passthrough": [0], "safe": False},
        "bufio.Reader.ReadLine":  {"passthrough": [0], "safe": False},

        # ===== net/url 解析 =====
        "url.Parse":          {"passthrough": [0], "safe": False},
        "url.ParseRequestURI": {"passthrough": [0], "safe": False},
        "url.QueryUnescape":  {"passthrough": [0], "safe": False},

        # ===== encoding/json 解码 =====
        "json.Unmarshal":     {"passthrough": [1], "safe": False, "param_flow": {1: 0}},
        "json.NewDecoder":    {"passthrough": [0], "safe": False},
        "json.Decoder.Decode": {"passthrough": [0], "safe": False},

        # ===== encoding/xml 解码 =====
        "xml.Unmarshal":      {"passthrough": [1], "safe": False, "param_flow": {1: 0}},
        "xml.NewDecoder":     {"passthrough": [0], "safe": False},

        # ===== reflect =====
        "reflect.ValueOf":        {"passthrough": [0], "safe": False},
        "reflect.Value.Interface": {"passthrough": [0], "safe": False},
        "reflect.Value.String":   {"passthrough": [0], "safe": False},

        # ================================================================
        #  Gin 框架 Sources
        # ================================================================
        "gin.Context.Query":           {"passthrough": [0], "safe": False},
        "Context.Query":               {"passthrough": [0], "safe": False},
        "c.Query":                     {"passthrough": [0], "safe": False},

        "gin.Context.Param":           {"passthrough": [0], "safe": False},
        "Context.Param":               {"passthrough": [0], "safe": False},
        "c.Param":                     {"passthrough": [0], "safe": False},

        "gin.Context.PostForm":        {"passthrough": [0], "safe": False},
        "Context.PostForm":            {"passthrough": [0], "safe": False},
        "c.PostForm":                  {"passthrough": [0], "safe": False},

        "gin.Context.DefaultQuery":    {"passthrough": [0], "safe": False},
        "Context.DefaultQuery":        {"passthrough": [0], "safe": False},
        "c.DefaultQuery":              {"passthrough": [0], "safe": False},

        "gin.Context.DefaultPostForm": {"passthrough": [0], "safe": False},
        "Context.DefaultPostForm":     {"passthrough": [0], "safe": False},
        "c.DefaultPostForm":           {"passthrough": [0], "safe": False},

        "gin.Context.GetHeader":       {"passthrough": [0], "safe": False},
        "Context.GetHeader":           {"passthrough": [0], "safe": False},
        "c.GetHeader":                 {"passthrough": [0], "safe": False},

        "gin.Context.GetQuery":        {"passthrough": [0], "safe": False},
        "Context.GetQuery":            {"passthrough": [0], "safe": False},
        "c.GetQuery":                  {"passthrough": [0], "safe": False},

        "gin.Context.GetPostForm":     {"passthrough": [0], "safe": False},
        "Context.GetPostForm":         {"passthrough": [0], "safe": False},
        "c.GetPostForm":               {"passthrough": [0], "safe": False},

        "gin.Context.ShouldBindJSON":  {"passthrough": [0], "safe": False},
        "Context.ShouldBindJSON":      {"passthrough": [0], "safe": False},
        "c.ShouldBindJSON":            {"passthrough": [0], "safe": False},

        "gin.Context.ShouldBind":      {"passthrough": [0], "safe": False},
        "Context.ShouldBind":          {"passthrough": [0], "safe": False},
        "c.ShouldBind":                {"passthrough": [0], "safe": False},

        "gin.Context.Bind":            {"passthrough": [0], "safe": False},
        "Context.Bind":                {"passthrough": [0], "safe": False},
        "c.Bind":                      {"passthrough": [0], "safe": False},

        "gin.Context.BindJSON":        {"passthrough": [0], "safe": False},
        "Context.BindJSON":            {"passthrough": [0], "safe": False},
        "c.BindJSON":                  {"passthrough": [0], "safe": False},

        "gin.Context.Cookie":          {"passthrough": [0], "safe": False},
        "Context.Cookie":              {"passthrough": [0], "safe": False},
        "c.Cookie":                    {"passthrough": [0], "safe": False},

        # ================================================================
        #  Echo 框架 Sources
        # ================================================================
        "echo.Context.QueryParam":     {"passthrough": [0], "safe": False},
        "echo.Context.Param":          {"passthrough": [0], "safe": False},
        "echo.Context.FormValue":      {"passthrough": [0], "safe": False},
        "echo.Context.QueryParams":    {"passthrough": [0], "safe": False},
        "echo.Context.Path":           {"passthrough": [0], "safe": False},
        "echo.Context.Get":            {"passthrough": [0], "safe": False},
        "echo.Context.Set":            {"passthrough": [0], "safe": False},
        "echo.Context.Bind":           {"passthrough": [0], "safe": False},

        # ================================================================
        #  Beego 框架 Sources
        # ================================================================
        "beego.Controller.GetString":       {"passthrough": [0], "safe": False},
        "Controller.GetString":             {"passthrough": [0], "safe": False},
        "this.GetString":                   {"passthrough": [0], "safe": False},

        "beego.Controller.GetStrings":      {"passthrough": [0], "safe": False},
        "Controller.GetStrings":            {"passthrough": [0], "safe": False},
        "this.GetStrings":                  {"passthrough": [0], "safe": False},

        "beego.Controller.GetInt":          {"passthrough": [0], "safe": False},
        "Controller.GetInt":                {"passthrough": [0], "safe": False},
        "this.GetInt":                      {"passthrough": [0], "safe": False},

        "beego.Controller.GetFloat":        {"passthrough": [0], "safe": False},
        "Controller.GetFloat":              {"passthrough": [0], "safe": False},
        "this.GetFloat":                    {"passthrough": [0], "safe": False},

        "beego.Controller.GetBool":         {"passthrough": [0], "safe": False},
        "Controller.GetBool":               {"passthrough": [0], "safe": False},
        "this.GetBool":                     {"passthrough": [0], "safe": False},

        "beego.Controller.Input":           {"passthrough": [0], "safe": False},
        "Controller.Input":                 {"passthrough": [0], "safe": False},
        "this.Input":                       {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.Query": {"passthrough": [0], "safe": False},
        "Ctx.Input.Query":                  {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.Param": {"passthrough": [0], "safe": False},
        "Ctx.Input.Param":                  {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.Header": {"passthrough": [0], "safe": False},
        "Ctx.Input.Header":                 {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.Cookie": {"passthrough": [0], "safe": False},
        "Ctx.Input.Cookie":                 {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.URI":   {"passthrough": [0], "safe": False},
        "Ctx.Input.URI":                    {"passthrough": [0], "safe": False},

        "beego.Controller.Ctx.Input.URL":   {"passthrough": [0], "safe": False},
        "Ctx.Input.URL":                    {"passthrough": [0], "safe": False},

        # ================================================================
        #  SINKS — 危险操作（标记为不安全）
        # ================================================================

        # ===== os/exec — 命令注入 =====
        "exec.Command":         {"passthrough": [0], "safe": False},
        "exec.CommandContext":   {"passthrough": [1], "safe": False},  # ctx, name, args...

        # ===== database/sql — SQL 注入 =====
        "db.Query":             {"passthrough": [0], "safe": False},
        "db.Exec":              {"passthrough": [0], "safe": False},
        "db.QueryRow":          {"passthrough": [0], "safe": False},
        "db.Prepare":           {"passthrough": [0], "safe": False},
        "sql.Open":             {"passthrough": [0], "safe": False},
        "sql.DB.Query":         {"passthrough": [0], "safe": False},
        "sql.DB.QueryRow":      {"passthrough": [0], "safe": False},
        "sql.DB.Exec":          {"passthrough": [0], "safe": False},
        "sql.DB.Prepare":       {"passthrough": [0], "safe": False},
        "sql.Tx.Query":         {"passthrough": [0], "safe": False},
        "sql.Tx.Exec":          {"passthrough": [0], "safe": False},
        "sql.Tx.QueryRow":      {"passthrough": [0], "safe": False},
        "sql.Stmt.Query":       {"passthrough": [0], "safe": False},
        "sql.Stmt.Exec":        {"passthrough": [0], "safe": False},

        # ===== html/template — XSS (类型转换绕过自动转义) =====
        "template.HTML":        {"passthrough": [0], "safe": False},  # 标记为安全HTML但不实际过滤
        "template.JS":          {"passthrough": [0], "safe": False},  # 标记为安全JS但不实际过滤
        "template.URL":         {"passthrough": [0], "safe": False},  # 标记为安全URL但不实际过滤
        "template.HTMLAttr":    {"passthrough": [0], "safe": False},
        "template.JSStr":       {"passthrough": [0], "safe": False},
        "template.Srcset":      {"passthrough": [0], "safe": False},

        # ===== text/template — 注入（无自动转义） =====
        "text/template.New":    {"passthrough": [0], "safe": False},
        "template.Must":        {"passthrough": [0], "safe": False},
        "template.ParseFiles":  {"passthrough": [0], "safe": False},
        "template.ParseGlob":   {"passthrough": [0], "safe": False},
        "template.ParseFS":     {"passthrough": [0], "safe": False},
        "template.Execute":     {"passthrough": [0], "safe": False, "param_flow": {"self": 0}},
        "template.ExecuteTemplate": {"passthrough": [0], "safe": False, "param_flow": {"self": 0}},

        # ===== os 文件操作 — 路径遍历 =====
        "os.Open":              {"passthrough": [0], "safe": False},
        "os.Create":            {"passthrough": [0], "safe": False},
        "os.OpenFile":          {"passthrough": [0], "safe": False},
        "os.Remove":            {"passthrough": [0], "safe": False},
        "os.RemoveAll":         {"passthrough": [0], "safe": False},
        "os.Mkdir":             {"passthrough": [0], "safe": False},
        "os.MkdirAll":          {"passthrough": [0], "safe": False},
        "os.Stat":              {"passthrough": [0], "safe": False},
        "os.Readlink":          {"passthrough": [0], "safe": False},
        "os.Symlink":           {"passthrough": [0, 1], "safe": False},
        "os.Rename":            {"passthrough": [0, 1], "safe": False},

        # ===== io/ioutil 文件操作 =====
        "ioutil.WriteFile":     {"passthrough": [0], "safe": False},
        "ioutil.TempDir":       {"passthrough": [0], "safe": False},
        "ioutil.TempFile":      {"passthrough": [0], "safe": False},

        # ===== os.WriteFile =====
        "os.WriteFile":         {"passthrough": [0], "safe": False},

        # ===== net/http — SSRF =====
        "http.Get":             {"passthrough": [0], "safe": False},
        "http.Post":            {"passthrough": [0], "safe": False},
        "http.PostForm":        {"passthrough": [0], "safe": False},
        "http.Head":            {"passthrough": [0], "safe": False},
        "http.NewRequest":      {"passthrough": [1], "safe": False},  # method, url
        "http.NewRequestWithContext": {"passthrough": [2], "safe": False},  # ctx, method, url
        "http.Client.Get":      {"passthrough": [0], "safe": False},
        "http.Client.Post":     {"passthrough": [0], "safe": False},
        "http.Client.Do":       {"passthrough": [0], "safe": False},
        "http.Client.Head":     {"passthrough": [0], "safe": False},

        # ===== fmt — 输出（可能 XSS） =====
        "fmt.Fprintf":          {"passthrough": [1, 2], "safe": False},  # w, format, args (variadic)
        "fmt.Sprintf":          {"passthrough": [0, 1], "safe": False},  # format, variadic args
        "fmt.Errorf":           {"passthrough": [0, 1], "safe": False},  # format, variadic args

        # ===== unsafe =====
        "unsafe.Pointer":       {"passthrough": [0], "safe": False},
        "unsafe.Sizeof":        {"passthrough": [], "safe": True},
        "unsafe.Alignof":       {"passthrough": [], "safe": True},
        "unsafe.Offsetof":      {"passthrough": [], "safe": True},

        # ===== net/http ResponseWriter 写入 =====
        "http.ResponseWriter.Write":           {"passthrough": [0], "safe": False},
        "ResponseWriter.Write":                {"passthrough": [0], "safe": False},
        "w.Write":                             {"passthrough": [0], "safe": False},

        "http.ResponseWriter.WriteHeader":     {"passthrough": [], "safe": True},
        "ResponseWriter.WriteHeader":          {"passthrough": [], "safe": True},
        "w.WriteHeader":                       {"passthrough": [], "safe": True},

        "http.ResponseWriter.Header":          {"passthrough": [0], "safe": False},
        "ResponseWriter.Header":               {"passthrough": [0], "safe": False},
        "w.Header":                            {"passthrough": [0], "safe": False},

        # ===== net/http ServeMux =====
        "http.ServeMux.HandleFunc": {"passthrough": [0], "safe": False},
        "http.HandleFunc":          {"passthrough": [0], "safe": False},
        "http.Handle":              {"passthrough": [0], "safe": False},
        "mux.HandleFunc":           {"passthrough": [0], "safe": False},
        "mux.Handle":               {"passthrough": [0], "safe": False},

        # ===== Gin 框架 Sink =====
        "gin.Context.JSON":            {"passthrough": [1], "safe": False},
        "Context.JSON":                {"passthrough": [1], "safe": False},
        "c.JSON":                      {"passthrough": [1], "safe": False},

        "gin.Context.String":          {"passthrough": [1], "safe": False},
        "Context.String":              {"passthrough": [1], "safe": False},
        "c.String":                    {"passthrough": [1], "safe": False},

        "gin.Context.HTML":            {"passthrough": [1], "safe": False},
        "Context.HTML":                {"passthrough": [1], "safe": False},
        "c.HTML":                      {"passthrough": [1], "safe": False},

        "gin.Context.Redirect":        {"passthrough": [1], "safe": False},
        "Context.Redirect":            {"passthrough": [1], "safe": False},
        "c.Redirect":                  {"passthrough": [1], "safe": False},

        "gin.Context.Data":            {"passthrough": [1], "safe": False},
        "Context.Data":                {"passthrough": [1], "safe": False},
        "c.Data":                      {"passthrough": [1], "safe": False},

        "gin.Context.SetCookie":       {"passthrough": [0], "safe": False},
        "Context.SetCookie":           {"passthrough": [0], "safe": False},
        "c.SetCookie":                 {"passthrough": [0], "safe": False},

        # ===== Echo 框架 Sink =====
        "echo.Context.JSON":           {"passthrough": [1], "safe": False},
        "echo.Context.String":         {"passthrough": [1], "safe": False},
        "echo.Context.HTML":           {"passthrough": [1], "safe": False},
        "echo.Context.Redirect":       {"passthrough": [1], "safe": False},
        "echo.Context.File":           {"passthrough": [0], "safe": False},
        "echo.Context.Inline":         {"passthrough": [0], "safe": False},

        # ===== Beego 框架 Sink =====
        "beego.Controller.Data":       {"passthrough": [0], "safe": False},
        "Controller.Data":             {"passthrough": [0], "safe": False},
        "this.Data":                   {"passthrough": [0], "safe": False},

        "beego.Controller.Redirect":   {"passthrough": [0], "safe": False},
        "Controller.Redirect":         {"passthrough": [0], "safe": False},
        "this.Redirect":               {"passthrough": [0], "safe": False},

        "beego.Controller.ServeJSON":  {"passthrough": [0], "safe": False},
        "Controller.ServeJSON":        {"passthrough": [0], "safe": False},
        "this.ServeJSON":              {"passthrough": [0], "safe": False},

        "beego.Controller.ServeXML":   {"passthrough": [0], "safe": False},
        "Controller.ServeXML":         {"passthrough": [0], "safe": False},
        "this.ServeXML":               {"passthrough": [0], "safe": False},

        "beego.Controller.Servejsonp": {"passthrough": [0], "safe": False},
        "Controller.Servejsonp":       {"passthrough": [0], "safe": False},
        "this.Servejsonp":             {"passthrough": [0], "safe": False},

        "beego.Controller.TplName":    {"passthrough": [0], "safe": False},
        "Controller.TplName":          {"passthrough": [0], "safe": False},
        "this.TplName":                {"passthrough": [0], "safe": False},

        "beego.Controller.SetCookie":  {"passthrough": [0], "safe": False},
        "Controller.SetCookie":        {"passthrough": [0], "safe": False},
        "this.SetCookie":              {"passthrough": [0], "safe": False},

        # ================================================================
        #  字符串操作（透传 receiver，不安全）
        # ================================================================

        # ===== strings 包 =====
        "strings.ToUpper":         {"passthrough": [0], "safe": False},
        "strings.ToLower":         {"passthrough": [0], "safe": False},
        "strings.Trim":            {"passthrough": [0], "safe": False},
        "strings.TrimLeft":        {"passthrough": [0], "safe": False},
        "strings.TrimRight":       {"passthrough": [0], "safe": False},
        "strings.TrimSpace":       {"passthrough": [0], "safe": False},
        "strings.TrimPrefix":      {"passthrough": [0], "safe": False},
        "strings.TrimSuffix":      {"passthrough": [0], "safe": False},
        "strings.Replace":         {"passthrough": [0], "safe": False},
        "strings.ReplaceAll":      {"passthrough": [0], "safe": False},
        "strings.Split":           {"passthrough": [0], "safe": False},
        "strings.SplitN":          {"passthrough": [0], "safe": False},
        "strings.SplitAfter":      {"passthrough": [0], "safe": False},
        "strings.Join":            {"passthrough": [0], "safe": False},
        "strings.Contains":        {"passthrough": [], "safe": True},
        "strings.HasPrefix":       {"passthrough": [], "safe": True},
        "strings.HasSuffix":       {"passthrough": [], "safe": True},
        "strings.Index":           {"passthrough": [], "safe": True},
        "strings.LastIndex":       {"passthrough": [], "safe": True},
        "strings.Count":           {"passthrough": [], "safe": True},
        "strings.Repeat":          {"passthrough": [0], "safe": False},
        "strings.Title":           {"passthrough": [0], "safe": False},
        "strings.Map":             {"passthrough": [1], "safe": False},
        "strings.NewReplacer":     {"passthrough": [0], "safe": False},
        "strings.Reader":          {"passthrough": [0], "safe": False},
        "strings.Builder.String":  {"passthrough": [0], "safe": False},
        "strings.Builder.Write":   {"passthrough": [0], "safe": False},
        "strings.Builder.WriteString": {"passthrough": [0], "safe": False},

        # ===== strconv 包 =====
        "strconv.Itoa":           {"passthrough": [], "safe": True},
        "strconv.Atoi":           {"passthrough": [], "safe": True},
        "strconv.FormatInt":      {"passthrough": [], "safe": True},
        "strconv.ParseInt":       {"passthrough": [], "safe": True},
        "strconv.ParseFloat":     {"passthrough": [], "safe": True},
        "strconv.ParseBool":      {"passthrough": [], "safe": True},
        "strconv.FormatBool":     {"passthrough": [], "safe": True},
        "strconv.FormatFloat":    {"passthrough": [], "safe": True},
        "strconv.Quote":          {"passthrough": [0], "safe": True},
        "strconv.Unquote":        {"passthrough": [0], "safe": False},

        # ===== bytes 包 =====
        "bytes.ToUpper":          {"passthrough": [0], "safe": False},
        "bytes.ToLower":          {"passthrough": [0], "safe": False},
        "bytes.Trim":             {"passthrough": [0], "safe": False},
        "bytes.TrimSpace":        {"passthrough": [0], "safe": False},
        "bytes.TrimPrefix":       {"passthrough": [0], "safe": False},
        "bytes.TrimSuffix":       {"passthrough": [0], "safe": False},
        "bytes.Replace":          {"passthrough": [0], "safe": False},
        "bytes.Split":            {"passthrough": [0], "safe": False},
        "bytes.Join":             {"passthrough": [0], "safe": False},
        "bytes.Contains":         {"passthrough": [], "safe": True},
        "bytes.HasPrefix":        {"passthrough": [], "safe": True},
        "bytes.HasSuffix":        {"passthrough": [], "safe": True},
        "bytes.Index":            {"passthrough": [], "safe": True},
        "bytes.NewBuffer":        {"passthrough": [0], "safe": False},
        "bytes.Buffer.String":    {"passthrough": [0], "safe": False},
        "bytes.Buffer.Bytes":     {"passthrough": [0], "safe": False},
        "bytes.Buffer.Write":     {"passthrough": [0], "safe": False},
        "bytes.Buffer.WriteString": {"passthrough": [0], "safe": False},

        # ===== path / path/filepath 包 =====
        "path.Join":             {"passthrough": [0, 1], "safe": False},
        "path.Base":             {"passthrough": [0], "safe": False},
        "path.Dir":              {"passthrough": [0], "safe": False},
        "path.Ext":              {"passthrough": [0], "safe": False},
        "path.Clean":            {"passthrough": [0], "safe": False},
        "filepath.Join":         {"passthrough": [0, 1], "safe": False},
        "filepath.Base":         {"passthrough": [0], "safe": False},
        "filepath.Dir":          {"passthrough": [0], "safe": False},
        "filepath.Ext":          {"passthrough": [0], "safe": False},
        "filepath.Clean":        {"passthrough": [0], "safe": False},
        "filepath.Abs":          {"passthrough": [0], "safe": False},
        "filepath.Rel":          {"passthrough": [0, 1], "safe": False},
        "filepath.Match":        {"passthrough": [0, 1], "safe": False},
        "filepath.Walk":         {"passthrough": [0], "safe": False},
        "filepath.WalkDir":      {"passthrough": [0], "safe": False},
        "filepath.Glob":         {"passthrough": [0], "safe": False},
        "filepath.EvalSymlinks": {"passthrough": [0], "safe": False},

        # ================================================================
        #  编解码（透传但不安全）
        # ================================================================

        # ===== encoding/json 编码 =====
        "json.Marshal":          {"passthrough": [0], "safe": False},
        "json.MarshalIndent":    {"passthrough": [0], "safe": False},
        "json.NewEncoder":       {"passthrough": [0], "safe": False},
        "json.Encoder.Encode":   {"passthrough": [0], "safe": False},

        # ===== encoding/xml =====
        "xml.Marshal":           {"passthrough": [0], "safe": False},
        "xml.MarshalIndent":     {"passthrough": [0], "safe": False},

        # ===== encoding/base64 =====
        "base64.StdEncoding.Encode":    {"passthrough": [0], "safe": False},
        "base64.StdEncoding.Decode":    {"passthrough": [0], "safe": False},
        "base64.URLEncoding.Encode":    {"passthrough": [0], "safe": False},
        "base64.URLEncoding.Decode":    {"passthrough": [0], "safe": False},
        "base64.RawStdEncoding.Encode": {"passthrough": [0], "safe": False},
        "base64.RawStdEncoding.Decode": {"passthrough": [0], "safe": False},

        # ===== net/url 编码 =====
        "url.QueryEscape":      {"passthrough": [0], "safe": True},
        "url.PathEscape":       {"passthrough": [0], "safe": True},
        "url.QueryUnescape":    {"passthrough": [0], "safe": False},
        "url.PathUnescape":     {"passthrough": [0], "safe": False},
        "url.Values.Encode":    {"passthrough": [0], "safe": False},
        "url.Values.Get":       {"passthrough": [0], "safe": False},

        # ===== net/url URL 结构体 =====
        "url.URL.String":       {"passthrough": [0], "safe": False},
        "url.URL.RequestURI":   {"passthrough": [0], "safe": False},

        # ===== crypto (hash 函数) =====
        "crypto/md5.Sum":         {"passthrough": [0], "safe": True},
        "crypto/sha1.Sum":        {"passthrough": [0], "safe": True},
        "crypto/sha256.Sum256":   {"passthrough": [0], "safe": True},
        "crypto/sha512.Sum512":   {"passthrough": [0], "safe": True},
        "md5.Sum":                {"passthrough": [0], "safe": True},
        "sha1.Sum":               {"passthrough": [0], "safe": True},
        "sha256.Sum256":          {"passthrough": [0], "safe": True},
        "sha512.Sum512":          {"passthrough": [0], "safe": True},

        # ===== crypto/hmac =====
        "hmac.New":               {"passthrough": [0], "safe": True},
        "hmac.Equal":             {"passthrough": [], "safe": True},

        # ===== hex =====
        "hex.EncodeToString":    {"passthrough": [0], "safe": True},
        "hex.DecodeString":      {"passthrough": [0], "safe": False},

        # ================================================================
        #  不透传（返回值与输入无关或为安全类型）
        # ================================================================

        # ===== 内置函数（Go 不可覆盖的 builtins） =====
        "len":              {"passthrough": [], "safe": True},
        "cap":              {"passthrough": [], "safe": True},
        "make":             {"passthrough": [], "safe": True},
        "new":              {"passthrough": [], "safe": True},
        "append":           {"passthrough": [0], "safe": False},
        "copy":             {"passthrough": [0], "safe": False},
        "delete":           {"passthrough": [], "safe": True},
        "close":            {"passthrough": [], "safe": True},
        "panic":            {"passthrough": [], "safe": True},
        "recover":          {"passthrough": [], "safe": True},
        "print":            {"passthrough": [], "safe": True},
        "println":          {"passthrough": [], "safe": True},
        "complex":          {"passthrough": [], "safe": True},
        "real":             {"passthrough": [], "safe": True},
        "imag":             {"passthrough": [], "safe": True},

        # ===== 类型转换（返回安全类型） =====
        "string":           {"passthrough": [0], "safe": False},
        "int":              {"passthrough": [], "safe": True},
        "int8":             {"passthrough": [], "safe": True},
        "int16":            {"passthrough": [], "safe": True},
        "int32":            {"passthrough": [], "safe": True},
        "int64":            {"passthrough": [], "safe": True},
        "uint":             {"passthrough": [], "safe": True},
        "uint8":            {"passthrough": [], "safe": True},
        "uint16":           {"passthrough": [], "safe": True},
        "uint32":           {"passthrough": [], "safe": True},
        "uint64":           {"passthrough": [], "safe": True},
        "float32":          {"passthrough": [], "safe": True},
        "float64":          {"passthrough": [], "safe": True},
        "bool":             {"passthrough": [], "safe": True},
        "byte":             {"passthrough": [], "safe": True},
        "rune":             {"passthrough": [], "safe": True},
        "[]byte":           {"passthrough": [0], "safe": False},
        "[]rune":           {"passthrough": [0], "safe": False},

        # ===== fmt 不透传 =====
        "fmt.Println":       {"passthrough": [], "safe": True},
        "fmt.Printf":        {"passthrough": [], "safe": True},
        "fmt.Sprint":        {"passthrough": [0], "safe": False},
        "fmt.Sprintln":      {"passthrough": [0], "safe": False},

        # ===== sort =====
        "sort.Strings":      {"passthrough": [], "safe": True},
        "sort.Ints":         {"passthrough": [], "safe": True},
        "sort.Float64s":     {"passthrough": [], "safe": True},
        "sort.Slice":        {"passthrough": [], "safe": True},

        # ===== errors =====
        "errors.New":        {"passthrough": [0], "safe": False},
        "fmt.Errorf":         {"passthrough": [0], "safe": False},

        # ===== regexp =====
        "regexp.Compile":        {"passthrough": [0], "safe": False},
        "regexp.MustCompile":    {"passthrough": [0], "safe": False},
        "regexp.Match":          {"passthrough": [0], "safe": False},
        "regexp.MatchString":    {"passthrough": [0], "safe": False},
        "regexp.Regexp.Match":   {"passthrough": [0], "safe": False},
        "regexp.Regexp.Find":    {"passthrough": [0], "safe": False},
        "regexp.Regexp.FindString": {"passthrough": [0], "safe": False},
        "regexp.Regexp.FindAll": {"passthrough": [0], "safe": False},
        "regexp.Regexp.FindAllString": {"passthrough": [0], "safe": False},
        "regexp.Regexp.ReplaceAll": {"passthrough": [1], "safe": False},
        "regexp.Regexp.ReplaceAllString": {"passthrough": [1], "safe": False},
        "regexp.Regexp.Split":   {"passthrough": [0], "safe": False},
        "regexp.Regexp.SubexpNames": {"passthrough": [], "safe": True},

        # ===== context =====
        "context.Background": {"passthrough": [], "safe": True},
        "context.TODO":      {"passthrough": [], "safe": True},
        "context.WithCancel": {"passthrough": [0], "safe": True},
        "context.WithValue":  {"passthrough": [0], "safe": False},

        # ===== sync =====
        "sync.Mutex.Lock":    {"passthrough": [], "safe": True},
        "sync.Mutex.Unlock":  {"passthrough": [], "safe": True},
        "sync.RWMutex.Lock":  {"passthrough": [], "safe": True},
        "sync.RWMutex.RLock": {"passthrough": [], "safe": True},

        # ===== time =====
        "time.Now":           {"passthrough": [], "safe": True},
        "time.Parse":         {"passthrough": [1], "safe": False},
        "time.Date":          {"passthrough": [], "safe": True},
        "time.Since":         {"passthrough": [], "safe": True},
        "time.Until":         {"passthrough": [], "safe": True},
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
    # 如 "http.Get" -> 尝试 "Get"
    if "." in func_name:
        short_name = func_name.split(".")[-1]
        if short_name in KNOWLEDGE:
            return KNOWLEDGE[short_name]

    return None
