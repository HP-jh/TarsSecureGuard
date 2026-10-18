package main

import (
	"net/http"
	"time"
)

func withTiming(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		w.Header().Set("X-Response-Time", time.Since(start).String())
	}
}
