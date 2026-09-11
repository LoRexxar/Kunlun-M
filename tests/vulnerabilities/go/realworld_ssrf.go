package main

// Real-world SSRF test cases for Kunlun-M scanner
// Simulates a Go web application with URL preview, webhook, and proxy features
// Expected detections: 3 TRUE POSITIVE (SSRF), 1 SAFE

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WebhookService simulates a service that makes outgoing HTTP requests
type WebhookService struct {
	client *http.Client
}

// VULN-1: SSRF via http.Get with user-controlled URL
// User can make the server fetch any internal or external resource
func (ws *WebhookService) URLPreviewHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	// VULN: user-controlled URL passed directly to http.Get
	// Attacker can probe internal services (e.g., http://169.254.169.254/metadata)
	resp, err := ws.client.Get(targetURL)
	if err != nil {
		http.Error(w, "failed to fetch URL", 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	io.Copy(w, resp.Body)
}

// VULN-2: SSRF via http.Post with user-controlled URL and body
// User can POST arbitrary data to any internal or external endpoint
func (ws *WebhookService) SendNotificationHandler(w http.ResponseWriter, r *http.Request) {
	webhookURL := r.FormValue("webhook_url")
	message := r.FormValue("message")
	contentType := r.FormValue("content_type")
	// VULN: user controls the destination URL, body, and content type
	resp, err := ws.client.Post(webhookURL, contentType, strings.NewReader(message))
	if err != nil {
		http.Error(w, "notification failed", 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintf(w, "Notification sent, status: %d", resp.StatusCode)
}

// VULN-3: SSRF via http.NewRequest with user-controlled URL and method
// User can craft arbitrary HTTP requests to internal services
func (ws *WebhookService) ProxyRequestHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("target")
	method := r.FormValue("method")
	// VULN: user controls both the method and the target URL
	req, err := http.NewRequest(method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	// Forward headers from the original request (dangerous)
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := ws.client.Do(req)
	if err != nil {
		http.Error(w, "proxy failed", 502)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// SAFE: HTTP request with URL whitelist validation
// Only pre-approved external API endpoints are allowed
func (ws *WebhookService) SafeFetchAPIHandler(w http.ResponseWriter, r *http.Request) {
	apiName := r.URL.Query().Get("api")
	// SAFE: whitelist restricts destinations to known safe endpoints
	allowedURLs := map[string]string{
		"weather":    "https://api.weather.example.com/current",
		"geocode":     "https://api.maps.example.com/geocode",
		"translate":   "https://api.translate.example.com/translate",
		"stock_price": "https://api.finance.example.com/price",
	}
	baseURL, ok := allowedURLs[apiName]
	if !ok {
		http.Error(w, "unknown API", 400)
		return
	}
	// SAFE: URL is constructed from whitelist, not user input
	resp, err := ws.client.Get(baseURL + "?key=apikey123")
	if err != nil {
		http.Error(w, "API request failed", 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

// SAFE: HTTP request with scheme and host validation
// Ensures only HTTPS to approved domains is allowed
func (ws *WebhookService) SafeAvatarFetchHandler(w http.ResponseWriter, r *http.Request) {
	avatarURL := r.URL.Query().Get("avatar_url")
	// SAFE: validate scheme and host before making request
	if !strings.HasPrefix(avatarURL, "https://cdn.example.com/avatars/") {
		http.Error(w, "invalid avatar URL", 400)
		return
	}
	resp, err := ws.client.Get(avatarURL)
	if err != nil {
		http.Error(w, "failed to fetch avatar", 500)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "image/png")
	io.Copy(w, resp.Body)
}

func main() {
	ws := &WebhookService{
		client: &http.Client{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/preview", ws.URLPreviewHandler)
	mux.HandleFunc("/notify", ws.SendNotificationHandler)
	mux.HandleFunc("/proxy", ws.ProxyRequestHandler)
	mux.HandleFunc("/api/fetch", ws.SafeFetchAPIHandler)
	mux.HandleFunc("/avatar/fetch", ws.SafeAvatarFetchHandler)
	fmt.Println("Webhook service running on :8084")
	http.ListenAndServe(":8084", mux)
}
