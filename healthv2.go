package main

import (
	"encoding/json"
	"net/http"
	"runtime"
)

type HealthV2 struct {
	Status       string `json:"status"`
	Version      string `json:"version"`
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"goroutines"`
	NumCPU       int    `json:"num_cpu"`
}

func handleHealthV2(w http.ResponseWriter, r *http.Request) {
	h := HealthV2{
		Status:       "healthy",
		Version:      version,
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h)
}
