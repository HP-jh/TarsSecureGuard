package main

import "net/http"

func withMethodGuard(allowed ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			for _, m := range allowed {
				if r.Method == m {
					next(w, r)
					return
				}
			}
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}
