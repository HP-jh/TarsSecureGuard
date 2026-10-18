package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGzipMiddlewareCompiles(t *testing.T) {
	_ = func() {
		handler := gzipMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		_ = handler
	}
}
