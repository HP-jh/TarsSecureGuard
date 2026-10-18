package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithMethodGuard(t *testing.T) {
	handler := withMethodGuard("GET")(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}
