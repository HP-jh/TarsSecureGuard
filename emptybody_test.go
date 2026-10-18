package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithEmptyBodyGuard(t *testing.T) {
	handler := withEmptyBodyGuard(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("POST", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}
