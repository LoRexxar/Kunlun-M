package main

// Real-world open redirect test cases for Kunlun-M scanner
// Simulates a Go web application with login redirect and OAuth callback features
// Expected detections: 3 TRUE POSITIVE (open redirect), 1 SAFE

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// AuthServer simulates an authentication service with redirect flows
type AuthServer struct{}

// VULN-1: Open redirect via http.Redirect with user-controlled "next" param
// User can redirect to any external URL after login
func (as *AuthServer) LoginRedirectHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	nextURL := r.URL.Query().Get("next")
	// VULN: user-controlled nextURL used directly in redirect
	// Attacker can set next=http://evil.com to phish credentials
	if username == "admin" && password == "admin123" {
		if nextURL != "" {
			http.Redirect(w, r, nextURL, http.StatusFound)
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		}
	} else {
		http.Error(w, "invalid credentials", 401)
	}
}

// VULN-2: Open redirect via http.Redirect with user-controlled "return_to" param
// OAuth-style callback redirect without validation
func (as *AuthServer) OAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	returnTo := r.URL.Query().Get("return_to")
	// VULN: return_to is user-controlled and used in redirect without validation
	// Attacker crafts link: /oauth/callback?code=xxx&return_to=https://evil.com
	if code != "" {
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusFound)
		} else {
			http.Redirect(w, r, "/settings", http.StatusFound)
		}
	} else {
		http.Error(w, "missing code", 400)
	}
}

// VULN-3: Open redirect via http.Redirect with user-controlled "redirect" param
// Language switching endpoint used as open redirect vector
func (as *AuthServer) SetLanguageHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	redirect := r.URL.Query().Get("redirect")
	// VULN: redirect param is user-controlled and used directly
	// e.g., /set-lang?lang=en&redirect=http://evil.com
	http.SetCookie(w, &http.Cookie{
		Name:  "lang",
		Value: lang,
		Path:  "/",
	})
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
	} else {
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// SAFE: Open redirect protected by relative-path-only validation
// Only allows redirects to paths starting with "/" (no scheme/host)
func (as *AuthServer) SafePostLoginRedirectHandler(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.FormValue("redirect")
	// SAFE: only allow relative redirects (path must start with / and not contain ://)
	if redirectURL != "" {
		parsed, err := url.Parse(redirectURL)
		if err != nil || parsed.IsAbs() || strings.HasPrefix(redirectURL, "//") {
			redirectURL = "/dashboard"
		}
		// Additional check: ensure it's a relative path
		if !strings.HasPrefix(redirectURL, "/") {
			redirectURL = "/dashboard"
		}
	} else {
		redirectURL = "/dashboard"
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// SAFE: Open redirect protected by URL whitelist
// Only pre-approved redirect destinations are allowed
func (as *AuthServer) SafePaymentReturnHandler(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return")
	// SAFE: whitelist of allowed redirect destinations
	allowedReturns := map[string]bool{
		"/order/complete":  true,
		"/order/cancelled": true,
		"/checkout":         true,
		"/cart":             true,
	}
	if !allowedReturns[returnURL] {
		returnURL = "/order/complete"
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func main() {
	as := &AuthServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", as.LoginRedirectHandler)
	mux.HandleFunc("/auth/oauth/callback", as.OAuthCallbackHandler)
	mux.HandleFunc("/set-lang", as.SetLanguageHandler)
	mux.HandleFunc("/auth/post-login", as.SafePostLoginRedirectHandler)
	mux.HandleFunc("/payment/return", as.SafePaymentReturnHandler)
	fmt.Println("Auth server running on :8086")
	http.ListenAndServe(":8086", mux)
}
