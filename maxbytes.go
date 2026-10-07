package main

import (
	"fmt"
	"io"
	"net/http"
)

// maxBytesBody v3.7.1：包装 http.MaxBytesReader，超限返回 413 而非直接关闭连接
type maxBytesBody struct {
	io.ReadCloser
	maxBytes int64
	read     int64
	w        http.ResponseWriter
	done     bool
}

func (b *maxBytesBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, fmt.Errorf("http: request body too large")
	}
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	if b.read > b.maxBytes {
		b.done = true
		b.w.WriteHeader(http.StatusRequestEntityTooLarge)
		b.w.Header().Set("Retry-After", "60")
		return n, fmt.Errorf("http: request body too large")
	}
	return n, err
}
