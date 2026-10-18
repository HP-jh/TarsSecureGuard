package main

import (
	"net/http"
	"testing"
	"time"
)

func TestShutdownGracefullyCompiles(t *testing.T) {
	_ = func() {
		srv := &http.Server{Addr: ":0"}
		shutdownGracefully(srv, 5*time.Second)
	}
}
