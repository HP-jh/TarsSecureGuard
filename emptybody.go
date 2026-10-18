package main

import (
	"net/http"
)

func withEmptyBodyGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.ContentLength == 0 {
			http.Error(w, "Empty Body", http.StatusBadRequest)
			return
		}
		next(w, r)
	}
}
