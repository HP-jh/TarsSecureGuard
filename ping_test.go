package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlePing(t *testing.T) {
	req := httptest.NewRequest("GET", "/ping", nil)
	rr := httptest.NewRecorder()
	handlePing(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status want 200, got %d", rr.Code)
	}
	if string(rr.Body.Bytes()) != "pong" {
		t.Fatalf("body want pong, got %s", rr.Body.Bytes())
	}
}
