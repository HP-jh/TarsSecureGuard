package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithIPAllowlist(t *testing.T) {
	handler := withIPAllowlist("127.0.0.1")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rr.Code)
	}
}
