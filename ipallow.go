package main

import (
	"net/http"
	"strings"
)

func withIPAllowlist(ips ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			client := strings.Split(r.RemoteAddr, ":")[0]
			for _, ip := range ips {
				if ip == client {
					next(w, r)
					return
				}
			}
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
}
