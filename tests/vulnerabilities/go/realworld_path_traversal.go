package main

// Real-world path traversal test cases for Kunlun-M scanner
// Simulates a Go web application with file browsing and template rendering features
// Expected detections: 3 TRUE POSITIVE (path traversal), 1 SAFE

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ContentServer simulates a CMS with file browsing and template loading
type ContentServer struct {
	contentDir  string
	templateDir string
}

// VULN-1: Path traversal via filepath.Join with user-controlled directory component
// User can traverse using "../" in the "folder" parameter
func (cs *ContentServer) BrowseFilesHandler(w http.ResponseWriter, r *http.Request) {
	folder := r.URL.Query().Get("folder")
	filename := r.URL.Query().Get("file")
	// VULN: filepath.Join with user-controlled folder allows directory traversal
	// e.g., folder=../../../../etc&file=passwd reads /etc/passwd
	fullPath := filepath.Join(cs.contentDir, folder, filename)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

// VULN-2: Path traversal via direct concatenation with user path
// User-controlled "resource" param concatenated directly to base directory
func (cs *ContentServer) GetResourceHandler(w http.ResponseWriter, r *http.Request) {
	resource := r.FormValue("resource")
	// VULN: direct string concatenation with user input, no sanitization
	// e.g., resource=../../../etc/shadow reads /etc/shadow
	fullPath := cs.templateDir + "/" + resource
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "resource not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// VULN-3: Path traversal via filepath.Join with user-controlled subpath
// User can escape the intended directory via encoded traversal sequences
func (cs *ContentServer) LoadThemeHandler(w http.ResponseWriter, r *http.Request) {
	theme := r.URL.Query().Get("theme")
	asset := r.URL.Query().Get("asset")
	// VULN: user controls theme path component, can use ../ to escape
	// e.g., theme=../../../tmp&asset=malicious.exe
	fullPath := filepath.Join("/opt/app/themes", theme, "assets", asset)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "asset not found", 404)
		return
	}
	w.Write(data)
}

// SAFE: Path traversal protected by path.Clean + prefix validation
// Canonicalizes the path and ensures it stays within baseDir
func (cs *ContentServer) SafeViewPostHandler(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	// SAFE: path.Clean resolves all traversal sequences (.., ., //)
	// Then prefix check ensures the result is within the content directory
	cleanSlug := path.Clean(slug)
	if strings.Contains(cleanSlug, "..") {
		http.Error(w, "invalid slug", 400)
		return
	}
	fullPath := filepath.Join(cs.contentDir, cleanSlug+".md")
	// Double-check: resolve to absolute and verify prefix
	absPath, _ := filepath.Abs(fullPath)
	absBase, _ := filepath.Abs(cs.contentDir)
	if !strings.HasPrefix(absPath, absBase) {
		http.Error(w, "access denied", 403)
		return
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		http.Error(w, "post not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/markdown")
	w.Write(data)
}

// SAFE: Path traversal protected by base filename extraction
// Uses only the basename, stripping all directory components
func (cs *ContentServer) SafeDownloadAttachmentHandler(w http.ResponseWriter, r *http.Request) {
	attachmentName := r.FormValue("attachment")
	// SAFE: filepath.Base strips all directory/path components
	// Even if user sends "attachment=../../../../etc/passwd", only "passwd" is used
	safeName := filepath.Base(attachmentName)
	fullPath := filepath.Join(cs.contentDir, "uploads", safeName)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "attachment not found", 404)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", safeName))
	w.Write(data)
}

func main() {
	cs := &ContentServer{
		contentDir:  "/opt/app/content",
		templateDir: "/opt/app/templates",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/files/browse", cs.BrowseFilesHandler)
	mux.HandleFunc("/resources/get", cs.GetResourceHandler)
	mux.HandleFunc("/themes/load", cs.LoadThemeHandler)
	mux.HandleFunc("/posts/view", cs.SafeViewPostHandler)
	mux.HandleFunc("/attachments/download", cs.SafeDownloadAttachmentHandler)
	fmt.Println("Content server running on :8085")
	http.ListenAndServe(":8085", mux)
}
