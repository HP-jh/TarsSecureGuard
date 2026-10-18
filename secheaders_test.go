package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	cfg := &SecurityHeadersConfig{
		Enabled:                 true,
		XFrameOptions:           "DENY",
		XContentTypeOptions:     true,
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		XXSSProtection:          true,
		PermissionsPolicy:       "camera=(), microphone=()",
		StrictTransportSecurity: "max-age=63072000",
	}
	initSecurityHeaders(cfg)

	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	tests := []struct {
		header   string
		expected string
	}{
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"X-XSS-Protection", "1; mode=block"},
		{"Permissions-Policy", "camera=(), microphone=()"},
		{"Strict-Transport-Security", "max-age=63072000"},
	}

	for _, tc := range tests {
		got := rr.Header().Get(tc.header)
		if got != tc.expected {
			t.Errorf("header %s: expected %q, got %q", tc.header, tc.expected, got)
		}
	}
}

func TestSecurityHeadersDisabled(t *testing.T) {
	initSecurityHeaders(&SecurityHeadersConfig{Enabled: false})
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Frame-Options") != "" {
		t.Error("expected no X-Frame-Options when disabled")
	}
}

func TestSecurityHeadersExcludePath(t *testing.T) {
	cfg := &SecurityHeadersConfig{
		Enabled:       true,
		XFrameOptions: "DENY",
		ExcludePaths:  []string{"/api/internal/"},
	}
	initSecurityHeaders(cfg)

	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/internal/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Frame-Options") != "" {
		t.Error("expected no X-Frame-Options for excluded path")
	}
}
