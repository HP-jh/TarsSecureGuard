// Package mcpserver exposes TSG capabilities as an MCP server.
package mcpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// ToolHandler is the function signature for handling MCP tool calls.
type ToolHandler func(args map[string]any) (any, error)

// Server is a lightweight MCP server exposing TSG tools.
type Server struct {
	mu       sync.RWMutex
	tools    map[string]*ToolDef
	handlers map[string]ToolHandler
}

// ToolDef defines an MCP tool.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// NewServer creates an empty MCP server.
func NewServer() *Server {
	return &Server{
		tools:    make(map[string]*ToolDef),
		handlers: make(map[string]ToolHandler),
	}
}

// RegisterTool adds a tool and its handler.
func (s *Server) RegisterTool(def *ToolDef, handler ToolHandler) error {
	if def == nil || def.Name == "" {
		return fmt.Errorf("mcpserver: tool name required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[def.Name] = def
	s.handlers[def.Name] = handler
	return nil
}

// HandleHTTP serves MCP JSON-RPC requests over HTTP.
func (s *Server) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"}}`, http.StatusMethodNotAllowed)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPCError(w, req.ID, -32700, "Parse error")
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, req)
	case "tools/list":
		s.handleToolList(w, req)
	case "tools/call":
		s.handleToolCall(w, req)
	default:
		writeJSONRPCError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *Server) handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	writeJSONRPCResult(w, req.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "tars-secure-guard-mcp", "version": "4.4.0"},
	})
}

func (s *Server) handleToolList(w http.ResponseWriter, req jsonRPCRequest) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*ToolDef, 0, len(s.tools))
	for _, t := range s.tools {
		list = append(list, t)
	}
	writeJSONRPCResult(w, req.ID, map[string]any{"tools": list})
}

func (s *Server) handleToolCall(w http.ResponseWriter, req jsonRPCRequest) {
	params, ok := req.Params.(map[string]any)
	if !ok {
		writeJSONRPCError(w, req.ID, -32602, "Invalid params")
		return
	}
	name, _ := params["name"].(string)
	if name == "" {
		writeJSONRPCError(w, req.ID, -32602, "Tool name required")
		return
	}

	s.mu.RLock()
	handler, ok := s.handlers[name]
	s.mu.RUnlock()
	if !ok {
		writeJSONRPCError(w, req.ID, -32602, fmt.Sprintf("Tool %s not found", name))
		return
	}

	args, _ := params["arguments"].(map[string]any)
	result, err := handler(args)
	if err != nil {
		writeJSONRPCResult(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		})
		return
	}

	writeJSONRPCResult(w, req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("%v", result)}},
	})
}

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

func writeJSONRPCResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
}
