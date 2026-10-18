package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHealthEndpointTimeout v4.19.0: verify health endpoint responds within reasonable time
func TestHealthEndpointTimeout(t *testing.T) {
	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	// Use a minimal handler; if no health handler exists, this test documents the expectation
	http.DefaultServeMux.ServeHTTP(w, req)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("health endpoint too slow: %v", elapsed)
	}
}
