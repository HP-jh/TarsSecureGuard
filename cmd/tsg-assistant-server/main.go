// tsg-assistant-server is a standalone assistant server for smoke testing.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"tarssecureguard-v41/crownext/assistant"
)

func resolveServerSettings() (addr string, ttl time.Duration) {
	addr = ":18080"
	if a := os.Getenv("ASSISTANT_ADDR"); a != "" {
		addr = a
	}

	ttl = time.Hour
	if v := os.Getenv("ASSISTANT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			ttl = d
		}
	}
	return addr, ttl
}

func buildDemoRouter(ttl time.Duration) *assistant.ModelRouter {
	router := assistant.NewModelRouter(ttl)
	router.Register(&assistant.ProviderConfig{
		Name:        "openai-gpt4",
		BaseURL:     "https://api.openai.com/v1",
		APIKey:      "sk-test",
		Model:       "gpt-4o",
		Weight:      1.0,
		MaxRPM:      100,
		Capabilities: []string{"chat", "vision", "tools"},
		Healthy:     true,
		LastCheck:   time.Now(),
	})
	router.Register(&assistant.ProviderConfig{
		Name:        "anthropic-claude",
		BaseURL:     "https://api.anthropic.com/v1",
		APIKey:      "sk-test2",
		Model:       "claude-3-sonnet",
		Weight:      0.8,
		MaxRPM:      80,
		Capabilities: []string{"chat", "tools"},
		Healthy:     true,
		LastCheck:   time.Now(),
	})
	return router
}

func buildDemoTools() *assistant.ToolRegistry {
	registry := assistant.NewToolRegistry(10, 1000)
	registry.Register(&assistant.ToolDefinition{
		Name:        "default_model",
		Description: "Get default model",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"default": "gpt-4o"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name:        "user_profile",
		Description: "Get user profile",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"user_id":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"user_id": "test", "role": "user"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name:           "rotate_key",
		Description:    "Rotate API key",
		Dangerous:      true,
		RequiredRBAC:   "admin",
		Parameters:     json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "rotated"}, nil
	})
	return registry
}

func buildGuard() assistant.Guard {
	sessions := assistant.NewSessionManager(20, "/tmp/tsg-assistant")
	pathChecker := func(path string) bool {
		return len(path) > 0 && (path == "/tmp/tsg-safe" || len(path) > len("/tmp/tsg-safe/") && path[:len("/tmp/tsg-safe/")] == "/tmp/tsg-safe/")
	}
	return assistant.NewAssistantGuard(pathChecker)
}

func main() {
	addr, ttl := resolveServerSettings()
	router := buildDemoRouter(ttl)
	registry := buildDemoTools()
	guard := buildGuard()
	server := assistant.NewServer(router, registry, assistant.NewSessionManager(20, "/tmp/tsg-assistant"), guard)

	if v := os.Getenv("ASSISTANT_MAX_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			server = assistant.NewServer(router, registry, assistant.NewSessionManager(n, "/tmp/tsg-assistant"), guard)
		}
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("Assistant server listening on %s (ttl=%s)", addr, ttl)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown error: %v", err)
	}
	log.Println("Done.")
}

func init() {
	if os.Getenv("ASSISTANT_LOG_FORMAT") == "json" {
		log.SetFlags(0)
		log.SetOutput(os.Stdout)
	}
	_ = fmt.Sprintf("")
}
