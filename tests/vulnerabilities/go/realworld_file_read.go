package main

// Real-world file read test cases for Kunlun-M scanner
// Simulates a Go web application with file viewing and report download features
// Expected detections: 3 TRUE POSITIVE (file read), 1 SAFE

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// FileServer simulates a document management system
type FileServer struct {
	baseDir string
}

// VULN-1: Arbitrary file read via os.Open with user-controlled path
// User can read any file on the system by providing absolute path or traversal
func (s *FileServer) ViewDocHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// VULN: no path validation, user can read /etc/passwd, ~/.ssh/id_rsa, etc.
	f, err := os.Open(filename)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		http.Error(w, "read error", 500)
		return
	}
	w.Write(data)
}

// VULN-2: Arbitrary file read via os.ReadFile with user-controlled path
// User can read any file through the report download endpoint
func (s *FileServer) DownloadReportHandler(w http.ResponseWriter, r *http.Request) {
	reportName := r.URL.Query().Get("report")
	// VULN: user-controlled reportName concatenated with directory, no sanitization
	filePath := "/var/reports/" + reportName
	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "report not found", 404)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", reportName))
	w.Write(data)
}

// VULN-3: Arbitrary file read via ioutil.ReadFile with user-controlled relative path
// User can traverse directories using ../ sequences
func (s *FileServer) ReadConfigHandler(w http.ResponseWriter, r *http.Request) {
	configFile := r.FormValue("config")
	// VULN: relative path from user input allows directory traversal
	data, err := ioutil.ReadFile(filepath.Join(s.baseDir, configFile))
	if err != nil {
		http.Error(w, "config not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
}

// SAFE: File read with path.Clean + prefix check (canonicalized path validation)
// Ensures resolved path stays within allowed directory
func (s *FileServer) SafeReadStaticHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("asset")
	// SAFE: path.Clean resolves traversal sequences, prefix check confines access
	cleanPath := filepath.Clean(filename)
	if !strings.HasPrefix(cleanPath, "static/") && cleanPath != "static" {
		http.Error(w, "access denied", 403)
		return
	}
	data, err := os.ReadFile(filepath.Join(s.baseDir, cleanPath))
	if err != nil {
		http.Error(w, "asset not found", 404)
		return
	}
	w.Write(data)
}

// SAFE: File read with strict allowlist validation
// Only predefined filenames are allowed
func (s *FileServer) SafeReadTemplateHandler(w http.ResponseWriter, r *http.Request) {
	tmplName := r.URL.Query().Get("template")
	// SAFE: allowlist restricts access to pre-approved template files
	allowed := map[string]bool{
		"invoice.html":    true,
		"receipt.html":     true,
		"shipping.html":   true,
		"newsletter.html": true,
	}
	if !allowed[tmplName] {
		http.Error(w, "template not found", 404)
		return
	}
	data, err := os.ReadFile(filepath.Join(s.baseDir, "templates", tmplName))
	if err != nil {
		http.Error(w, "template not found", 404)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	w.Write(data)
}

func main() {
	srv := &FileServer{
		baseDir: "/opt/app/data",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/docs/view", srv.ViewDocHandler)
	mux.HandleFunc("/reports/download", srv.DownloadReportHandler)
	mux.HandleFunc("/config/read", srv.ReadConfigHandler)
	mux.HandleFunc("/static/asset", srv.SafeReadStaticHandler)
	mux.HandleFunc("/templates/read", srv.SafeReadTemplateHandler)
	fmt.Println("File server running on :8083")
	http.ListenAndServe(":8083", mux)
}
