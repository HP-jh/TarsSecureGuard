package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithTiming(t *testing.T) {
	handler := withTiming(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Header().Get("X-Response-Time") == "" {
		t.Fatal("X-Response-Time missing")
	}
}
