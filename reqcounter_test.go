package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithRequestCounter(t *testing.T) {
	handler := withRequestCounter(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	before := getRequestCount()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	after := getRequestCount()
	if after != before+1 {
		t.Fatalf("count want %d, got %d", before+1, after)
	}
}
