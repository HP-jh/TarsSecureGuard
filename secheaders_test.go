package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithSecurityHeaders(t *testing.T) {
	handler := withSecurityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("X-Frame-Options missing")
	}
}
