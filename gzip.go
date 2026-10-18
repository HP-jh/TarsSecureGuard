package main

import (
	"compress/gzip"
	"net/http"
	"strings"
)

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		defer gw.Close()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gw}, r)
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	*gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
