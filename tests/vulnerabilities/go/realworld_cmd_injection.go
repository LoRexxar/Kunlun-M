package main

// Real-world command injection test cases for Kunlun-M scanner
// Simulates a Go web application with admin diagnostic tools
// Expected detections: 3 TRUE POSITIVE (command injection), 1 SAFE

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// DiagnosticServer simulates an admin tool that runs system commands
type DiagnosticServer struct{}

// VULN-1: Command injection via fmt.Sprintf into exec.Command name
// User-controlled "tool" param is concatenated directly into the command string
func (s *DiagnosticServer) RunToolHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	// VULN: user input controls which binary is executed
	cmdStr := fmt.Sprintf("/usr/local/bin/%s --version", tool)
	out, err := exec.Command("sh", "-c", cmdStr).Output()
	if err != nil {
		http.Error(w, "command failed", 500)
		return
	}
	w.Write(out)
}

// VULN-2: Command injection via argument concatenation
// User-controlled "host" param injected into ping command argument
func (s *DiagnosticServer) PingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// VULN: user can inject additional shell commands via semicolons or backticks
	cmd := exec.Command("ping", "-c", "4", host)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "ping failed", 500)
		return
	}
	w.Write(out)
}

// VULN-3: Command injection via exec.Command with sh -c and fmt.Sprintf
// User-controlled "logfile" param is concatenated into a grep command
func (s *DiagnosticServer) LogSearchHandler(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.FormValue("search")
	logFile := r.URL.Query().Get("logfile")
	// VULN: both searchTerm and logFile are user-controlled, no sanitization
	cmdStr := fmt.Sprintf("grep '%s' /var/log/app/%s", searchTerm, logFile)
	out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
	if err != nil {
		http.Error(w, "search failed", 500)
		return
	}
	w.Write(out)
}

// SAFE: Command execution with validated allowlist and separate args
// Only executes pre-approved binaries, user input passed as isolated argument
func (s *DiagnosticServer) SafeDnsLookupHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	// SAFE: using allowlist check and separate args (no shell wrapping)
	allowed := []string{"example.com", "test.local", "internal.corp"}
	isValid := false
	for _, a := range allowed {
		if domain == a {
			isValid = true
			break
		}
	}
	if !isValid {
		http.Error(w, "domain not allowed", 403)
		return
	}
	// SAFE: separate args, no shell, no string concatenation in command
	out, err := exec.Command("dig", "+short", domain).Output()
	if err != nil {
		http.Error(w, "dns lookup failed", 500)
		return
	}
	w.Write(out)
}

// SAFE: Command execution with strict input validation (alphanumeric only)
func (s *DiagnosticServer) SafeProcessInfoHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.URL.Query().Get("pid")
	// SAFE: strict validation ensures only numeric input
	for _, c := range pid {
		if c < '0' || c > '9' {
			http.Error(w, "invalid pid", 400)
			return
		}
	}
	// SAFE: separate args, no shell concatenation
	out, err := exec.Command("ps", "-p", pid, "-o", "pid,comm,args").Output()
	if err != nil {
		http.Error(w, "process not found", 404)
		return
	}
	w.Write(out)
}

func main() {
	srv := &DiagnosticServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/run-tool", srv.RunToolHandler)
	mux.HandleFunc("/admin/ping", srv.PingHandler)
	mux.HandleFunc("/admin/log-search", srv.LogSearchHandler)
	mux.HandleFunc("/admin/dns", srv.SafeDnsLookupHandler)
	mux.HandleFunc("/admin/process", srv.SafeProcessInfoHandler)
	fmt.Println("Diagnostic server running on :8080")
	_ = strings.TrimSpace("") // unused import suppression
	http.ListenAndServe(":8080", mux)
}
