// tsg-assistant-server is a standalone assistant server for smoke testing.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tarssecureguard-v41/crownext/assistant"
)

func main() {
	router := assistant.NewModelRouter(time.Hour)
	router.Register(&assistant.ProviderConfig{
		Name: "openai-gpt4", BaseURL: "https://api.openai.com/v1", APIKey: "sk-test",
		Model: "gpt-4o", Weight: 1.0, MaxRPM: 100, Capabilities: []string{"chat", "vision", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})
	router.Register(&assistant.ProviderConfig{
		Name: "anthropic-claude", BaseURL: "https://api.anthropic.com/v1", APIKey: "sk-test2",
		Model: "claude-3-sonnet", Weight: 0.8, MaxRPM: 80, Capabilities: []string{"chat", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})

	registry := assistant.NewToolRegistry(10, 1000)
	registry.Register(&assistant.ToolDefinition{
		Name: "default_model", Description: "Get default model",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"default": "gpt-4o"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "user_profile", Description: "Get user profile",
		Parameters: json.RawMessage(`{"type":"object","properties":{"user_id":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"user_id": "test", "role": "user"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "rotate_key", Description: "Rotate API key", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "rotated"}, nil
	})

	sessions := assistant.NewSessionManager(20, "/tmp/tsg-assistant")
	pathChecker := func(path string) bool {
		return len(path) > 0 && (path == "/tmp/tsg-safe" || len(path) > len("/tmp/tsg-safe/") && path[:len("/tmp/tsg-safe/")] == "/tmp/tsg-safe/")
	}
	guard := assistant.NewAssistantGuard(pathChecker)

	server := assistant.NewServer(router, registry, sessions, guard)

	addr := ":18080"
	if a := os.Getenv("ASSISTANT_ADDR"); a != "" {
		addr = a
	}

	srv := &http.Server{Addr: addr, Handler: server}
	go func() {
		log.Printf("Assistant server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Println("Done.")
}
