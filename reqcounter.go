package main

import (
	"net/http"
	"sync/atomic"
)

var reqCount int64

func withRequestCounter(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		next(w, r)
	}
}

func getRequestCount() int64 {
	return atomic.LoadInt64(&reqCount)
}
