package main

import (
	"encoding/json"
	"net/http"
)

func handleVersion(w http.ResponseWriter, r *http.Request) {
	resp := map[string]string{"version": version}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
