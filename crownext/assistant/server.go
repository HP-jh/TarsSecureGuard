package assistant

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Server exposes the assistant via HTTP.
type Server struct {
	router    *ModelRouter
	registry  *ToolRegistry
	sessions  *SessionManager
	guard     *AssistantGuard
	audit     *SelectionAudit
	mux       *http.ServeMux
}

// NewServer creates an assistant HTTP server.
func NewServer(router *ModelRouter, registry *ToolRegistry, sessions *SessionManager, guard *AssistantGuard) *Server {
	s := &Server{
		router:    router,
		registry:  registry,
		sessions:  sessions,
		guard:     guard,
		audit:     NewSelectionAudit(1000),
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/assistant/chat", s.handleChat)
	s.mux.HandleFunc("/api/assistant/sessions", s.handleSessions)
	s.mux.HandleFunc("/api/assistant/sessions/", s.handleSessionDetail)
	s.mux.HandleFunc("/api/assistant/tools", s.handleTools)
	s.mux.HandleFunc("/api/assistant/providers", s.handleProviders)
	s.mux.HandleFunc("/api/assistant/confirm", s.handleConfirm)
	s.mux.HandleFunc("/api/assistant/health", s.handleHealth)
	s.mux.HandleFunc("/assistant/", s.handleStatic)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID    string `json:"session_id"`
		UserID       string `json:"user_id"`
		Role         string `json:"role"`
		Message      string `json:"message"`
		Mode         string `json:"mode"`
		Provider     string `json:"provider"`
		ConfirmToken string `json:"confirm_token,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get or create session
	var sess *Session
	if req.SessionID != "" {
		var ok bool
		sess, ok = s.sessions.Get(req.SessionID)
		if !ok {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
	} else {
		role := req.Role
		if role == "" {
			role = "user"
		}
		sess = s.sessions.NewSession(req.UserID, role)
	}

	// Update mode if provided
	if req.Mode != "" {
		s.sessions.SetMode(sess.ID, SelectionMode(req.Mode))
	}
	if req.Provider != "" {
		s.sessions.SetProvider(sess.ID, req.Provider)
	}

	// Add user message
	_ = s.sessions.AddMessage(sess.ID, Message{
		Role:      "user",
		Content:   req.Message,
		Timestamp: time.Now(),
	})

	// Select provider
	var provider *ProviderConfig
	var err error
	var score float64
	var reason string

	if sess.Mode == ModeManual && sess.Provider != "" {
		provider, err = s.router.SelectManual(sess.Provider)
		reason = "manual selection"
	} else {
		provider, err = s.router.SelectAuto(nil)
		if provider != nil {
			score = s.router.Score(provider, nil)
		}
		reason = "auto routing"
	}
	if err != nil {
		_ = s.sessions.AddMessage(sess.ID, Message{
			Role:      "assistant",
			Content:   "No available model provider. Please check configuration.",
			Timestamp: time.Now(),
		})
		respondJSON(w, map[string]interface{}{
			"session_id": sess.ID,
			"error":      err.Error(),
		})
		return
	}

	// Record selection audit
	s.audit.Record(SelectionRecord{
		Timestamp:  time.Now(),
		Mode:       sess.Mode,
		Provider:   provider.Name,
		Model:      provider.Model,
		Score:      score,
		Reason:     reason,
		SessionID:  sess.ID,
	})

	// Build system prompt with available tools
	toolsJSON, _ := json.Marshal(s.registry.ToOpenAITools())
	_ = fmt.Sprintf("You are TarsSecureGuard Assistant. You have access to tools. Respond helpfully. Available tools: %s", string(toolsJSON))

	// In a real implementation, this would call the LLM API
	// For now, simulate a response that may include tool calls
	simulatedResponse := fmt.Sprintf("Assistant response using %s/%s. Tools available: %d", provider.Name, provider.Model, len(s.registry.ListDefinitions()))

	_ = s.sessions.AddMessage(sess.ID, Message{
		Role:      "assistant",
		Content:   simulatedResponse,
		Timestamp: time.Now(),
	})

	respondJSON(w, map[string]interface{}{
		"session_id": sess.ID,
		"response":   simulatedResponse,
		"provider":   provider.Name,
		"model":      provider.Model,
		"mode":       sess.Mode,
	})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sessions := s.sessions.List()
		respondJSON(w, sessions)
		return
	}
	if r.Method == http.MethodPost {
		var req struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		role := req.Role
		if role == "" {
			role = "user"
		}
		sess := s.sessions.NewSession(req.UserID, role)
		respondJSON(w, sess)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/assistant/sessions/"), "/")
	if len(parts) < 1 {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	id := parts[0]
	sess, ok := s.sessions.Get(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	respondJSON(w, sess)
}

func (s *Server) handleTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defs := s.registry.ListDefinitions()
	respondJSON(w, defs)
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	providers := s.router.List()
	respondJSON(w, providers)
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ok := s.guard.ConfirmOperation(req.Token)
	respondJSON(w, map[string]interface{}{"confirmed": ok})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Serve embedded frontend
	path := strings.TrimPrefix(r.URL.Path, "/assistant/")
	if path == "" || path == "/" {
		path = "index.html"
	}
	content, ok := embeddedFrontend[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	} else if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else {
		w.Header().Set("Content-Type", "text/html")
	}
	w.Write([]byte(content))
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// embeddedFrontend holds static files for the assistant UI.
var embeddedFrontend = map[string]string{
	"index.html": assistantUIHTML,
}
