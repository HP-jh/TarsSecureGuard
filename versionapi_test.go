package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleVersion(t *testing.T) {
	req := httptest.NewRequest("GET", "/version", nil)
	rr := httptest.NewRecorder()
	handleVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var body map[string]string
	json.Unmarshal(rr.Body.Bytes(), &body)
	if body["version"] != version {
		t.Fatalf("version mismatch")
	}
}
