// server.go — HTTP API for the security evaluation system.
package security

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Server wraps the score engine and protectors as an http.Handler.
type Server struct {
	engine    *ScoreEngine
	protector *DynamicProtector
	auditor   *StaticAuditor
}

// NewServer creates an HTTP server for security endpoints.
func NewServer(engine *ScoreEngine, protector *DynamicProtector, auditor *StaticAuditor) http.Handler {
	s := &Server{engine: engine, protector: protector, auditor: auditor}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/security/report", s.handleReport)
	mux.HandleFunc("/api/security/evaluate", s.handleEvaluate)
	mux.HandleFunc("/api/security/dynamic", s.handleDynamic)
	mux.HandleFunc("/api/security/static", s.handleStatic)
	mux.HandleFunc("/api/security/events", s.handleEvents)
	mux.HandleFunc("/api/security/health", s.handleHealth)
	return mux
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	report := s.engine.LastReport()
	if report == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no report available, run /evaluate first"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	report, err := s.engine.Evaluate(ctx)
	if err != nil {
		http.Error(w, `{"error":"evaluation failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleDynamic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.protector.Snapshot())
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": s.auditor.Findings(),
		"score":    s.auditor.Score(),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.protector.Events())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
