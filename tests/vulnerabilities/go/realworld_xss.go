package main

// Real-world XSS test cases for Kunlun-M scanner
// Simulates a Go web application with user profile and comment features
// Expected detections: 3 TRUE POSITIVE (XSS), 1 SAFE

import (
	"fmt"
	"html/template"
	"net/http"
)

// BlogServer simulates a blog platform with user-generated content
type BlogServer struct {
	tmpl *template.Template
}

// VULN-1: XSS via template.HTML wrapping user input
// User-controlled "comment" param is wrapped in template.HTML, bypassing auto-escaping
func (s *BlogServer) CommentHandler(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	author := r.FormValue("author")
	// VULN: template.HTML explicitly marks string as safe HTML, disabling auto-escaping
	// Attacker can inject <script>alert('xss')</script> via comment field
	tmpl := template.Must(template.New("comment").Parse(`
		<div class="comment">
			<span class="author">{{.Author}}</span>
			<div class="body">{{.Body}}</div>
		</div>
	`))
	tmpl.Execute(w, struct {
		Author string
		Body   template.HTML
	}{
		Author: author,
		Body:   template.HTML(comment),
	})
}

// VULN-2: XSS via template.HTML with user-controlled "bio" param
// User profile bio is rendered as raw HTML without sanitization
func (s *BlogServer) ProfileBioHandler(w http.ResponseWriter, r *http.Request) {
	bio := r.URL.Query().Get("bio")
	// VULN: bio is rendered as raw HTML, allowing script injection
	html := fmt.Sprintf(`<div class="profile-bio">%s</div>`, bio)
	tmpl := template.Must(template.New("bio").Parse(`{{.Content}}`))
	tmpl.Execute(w, struct {
		Content template.HTML
	}{
		Content: template.HTML(html),
	})
}

// VULN-3: XSS via template.HTML with user-controlled "page" param
// Custom page content rendered as raw HTML
func (s *BlogServer) CustomPageHandler(w http.ResponseWriter, r *http.Request) {
	pageContent := r.FormValue("content")
	// VULN: entire page content is user-controlled and rendered as safe HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html><head><title>User Page</title></head>
<body>{{.Content}}</body></html>`))
	tmpl.Execute(w, struct {
		Content template.HTML
	}{
		Content: template.HTML(pageContent),
	})
}

// SAFE: User input rendered via template auto-escaping (no template.HTML)
// Go's html/template automatically escapes all content unless wrapped in template.HTML
func (s *BlogServer) SafeSearchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	// SAFE: using html/template's default auto-escaping (no template.HTML wrapper)
	tmpl := template.Must(template.New("search").Parse(`
		<div class="search">
			<p>You searched for: <strong>{{.Query}}</strong></p>
		</div>
	`))
	tmpl.Execute(w, struct {
		Query string
	}{
		Query: query,
	})
}

// SAFE: User input explicitly escaped using html/template.HTMLEscaper
// Manual escaping applied before rendering
func (s *BlogServer) SafePreviewHandler(w http.ResponseWriter, r *http.Request) {
	text := r.FormValue("text")
	// SAFE: explicit escaping via template.HTMLEscaper
	safeText := template.HTMLEscaper(text)
	tmpl := template.Must(template.New("preview").Parse(`
		<div class="preview">
			<pre>{{.Text}}</pre>
		</div>
	`))
	tmpl.Execute(w, struct {
		Text string
	}{
		Text: safeText,
	})
}

func main() {
	srv := &BlogServer{
		tmpl: template.Must(template.New("base").Parse("")),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/comment", srv.CommentHandler)
	mux.HandleFunc("/profile/bio", srv.ProfileBioHandler)
	mux.HandleFunc("/page/custom", srv.CustomPageHandler)
	mux.HandleFunc("/search", srv.SafeSearchHandler)
	mux.HandleFunc("/preview", srv.SafePreviewHandler)
	fmt.Println("Blog server running on :8082")
	http.ListenAndServe(":8082", mux)
}
