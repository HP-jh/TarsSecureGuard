// tsg-v41-demo is a standalone binary demonstrating v4.1.0 features:
// multi-agent collaboration, MCP tool invocation, distributed device connectivity,
// and gateway smart assistant.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"tarssecureguard-v41/crownext/agentmesh"
	"tarssecureguard-v41/crownext/assistant"
	"tarssecureguard-v41/crownext/mcpclient"
	"tarssecureguard-v41/crownext/skylink"
	"tarssecureguard-v41/crownext/threatmodel"
)

func main() {
	fmt.Println("=== TarsSecureGuard v4.1.0 Demo ===")
	fmt.Println("Features: Multi-Agent Collaboration | MCP Integration | Distributed Device Mesh | Gateway Smart Assistant")
	fmt.Println()

	ctx := context.Background()

	// 1. Agent Mesh
	fmt.Println("[1] Agent Mesh Setup")
	reg := agentmesh.NewRegistry()
	disp := agentmesh.NewDispatcher(reg)
	reg.RegisterLocal(&agentmesh.AgentCard{AgentID: "alpha", Version: "4.5.0", RBACRole: "admin", Accepts: []agentmesh.TaskType{agentmesh.TaskChat}})
	reg.RegisterLocal(&agentmesh.AgentCard{AgentID: "beta", Version: "4.5.0", RBACRole: "user", Accepts: []agentmesh.TaskType{agentmesh.TaskChat}, Capabilities: []string{"summarize"}})
	fmt.Printf("    Registered %d agents\n", reg.Count())

	// 2. MCP Guard
	fmt.Println("[2] MCP Tool Registry & Guard")
	mcpReg := mcpclient.NewRegistry()
	mcpReg.RegisterTool(
		&mcpclient.MCPToolDef{Name: "summarize", Description: "Summarize text"},
		&mcpclient.ToolPolicy{AllowedRoles: []string{"admin", "user"}, MaxCallsPerMin: 10},
	)
	guard := mcpclient.NewGuard(mcpReg)
	res := guard.Check(ctx, "user", "beta", "summarize")
	fmt.Printf("    MCP invoke allowed=%v reason=%s\n", res.Allowed, res.Reason)

	// 3. Task Dispatch (P2P)
	fmt.Println("[3] Task Dispatch (P2P)")
	disp.RegisterHandler("beta", func(ctx context.Context, task *agentmesh.TaskEnvelope) ([]byte, error) {
		return []byte(`{"result":"summarized"}`), nil
	})
	task := &agentmesh.TaskEnvelope{
		TaskID: "demo-1", TaskType: agentmesh.TaskChat, FromAgent: "alpha", ToAgent: "beta",
		Payload: []byte(`{"text":"hello world"}`),
	}
	if err := disp.Dispatch(ctx, task); err != nil {
		log.Fatalf("dispatch failed: %v", err)
	}
	fmt.Printf("    Task %s state=%s\n", task.TaskID, task.State)

	// 4. SkyLink Discovery
	fmt.Println("[4] Device Discovery")
	discovery := skylink.NewDiscovery()
	discovery.Register(&skylink.DeviceProfile{PeerID: "phone-1", DeviceType: skylink.DevicePhone, Capabilities: []string{"camera"}})
	discovery.Register(&skylink.DeviceProfile{PeerID: "server-1", DeviceType: skylink.DeviceServer, Capabilities: []string{"gpu", "storage"}})
	discovery.MarkTrusted("server-1")
	fmt.Printf("    Devices: %d (trusted: %d)\n", discovery.Count(), discovery.CountTrusted())

	// 5. Content Addressable Storage
	fmt.Println("[5] Content Addressable Storage")
	store := skylink.NewContentStore()
	cid, _ := store.Put([]byte("demo-content"))
	store.Pin(cid)
	fmt.Printf("    CID=%s size=%d\n", cid.Hash, cid.Size)

	// 6. Encrypted Messaging
	fmt.Println("[6] Encrypted Cross-Device Messaging")
	messenger := skylink.NewMessenger(10)
	key := skylink.DeriveSharedKey([]byte("demo-secret"))
	messenger.RegisterKey("phone-1", key)
	msgPayload := &skylink.MessagePayload{Type: "heartbeat", Body: json.RawMessage(`{"status":"ok"}`)}
	msg, _ := messenger.Send("server-1", "phone-1", msgPayload)
	fmt.Printf("    Message ID=%s encrypted=%d bytes\n", msg.ID, len(msg.Payload))

	// 7. Distributed Coordination
	fmt.Println("[7] Distributed Coordination")
	coord := skylink.NewCoordClient()
	coord.Put(ctx, "/mesh/agents/alpha", `{"status":"online"}`)
	v, _ := coord.Get(ctx, "/mesh/agents/alpha")
	fmt.Printf("    Coord value=%s\n", v)

	// 8. Threat Model
	fmt.Println("[8] Threat Model (Auth + Isolation)")
	auth, _ := threatmodel.NewDeviceAuthManager()
	id, _, _ := auth.IssueDeviceCert("server-1", time.Hour)
	if err := auth.VerifyPeer("server-1", id.CertPEM); err != nil {
		log.Fatalf("auth verify failed: %v", err)
	}
	fmt.Printf("    Device cert issued and verified for server-1\n")

	isolator := threatmodel.NewIsolator(time.Hour, 5)
	isolator.Quarantine("rogue-1", "bad cert", threatmodel.IsolationBlock, nil)
	if err := isolator.Check("rogue-1"); err != nil {
		fmt.Printf("    Isolation: rogue-1 blocked (%s)\n", err)
	}

	// 9. Gateway Smart Assistant
	fmt.Println()
	fmt.Println("[9] Gateway Smart Assistant")
	runAssistantDemo()

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
	fmt.Println("v4.1.0 modules: agentmesh | mcpclient | mcpserver | skylink | threatmodel | assistant")
	os.Exit(0)
}

func runAssistantDemo() {
	// 9a. Model Router with health checks and scoring
	router := assistant.NewModelRouter(time.Hour)
	router.Register(&assistant.ProviderConfig{
		Name: "openai-gpt4", BaseURL: "https://api.openai.com/v1", APIKey: "sk-test-1",
		Model: "gpt-4o", Weight: 1.0, MaxRPM: 100, Capabilities: []string{"chat", "vision", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})
	router.Register(&assistant.ProviderConfig{
		Name: "anthropic-claude", BaseURL: "https://api.anthropic.com/v1", APIKey: "sk-test-2",
		Model: "claude-3-sonnet", Weight: 0.8, MaxRPM: 80, Capabilities: []string{"chat", "tools"},
		Healthy: true, LastCheck: time.Now(),
	})
	router.Register(&assistant.ProviderConfig{
		Name: "local-llama", BaseURL: "http://localhost:11434/v1", APIKey: "",
		Model: "llama3.1", Weight: 0.5, MaxRPM: 20, Capabilities: []string{"chat"},
		Healthy: true, LastCheck: time.Now(),
	})
	fmt.Printf("    Registered %d model providers\n", len(router.List()))

	// 9b. Tool Registry with RBAC + quota + audit
	registry := assistant.NewToolRegistry(10, 1000)
	registry.Register(&assistant.ToolDefinition{
		Name: "default_model", Description: "Get or set the default model for the gateway",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"},"model":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"default": "gpt-4o"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "add_key", Description: "Add a new API key", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"},"key":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "key_added"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "rotate_key", Description: "Rotate an existing API key", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "key_rotated"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "revoke_key", Description: "Revoke an API key", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "key_revoked"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "file_ops", Description: "Read/write/list files with path validation",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"},"path":{"type":"string"},"content":{"type":"string"}}}`),
	}, assistant.WrapFileOps(func(path string) bool {
		// Anti-symlink escape: only allow paths under /tmp/tsg-safe
		return len(path) > 0 && (path == "/tmp/tsg-safe" || len(path) > len("/tmp/tsg-safe/") && path[:len("/tmp/tsg-safe/")] == "/tmp/tsg-safe/")
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "file_op_ok"}, nil
	}))
	registry.Register(&assistant.ToolDefinition{
		Name: "user_profile", Description: "Get or update user profile",
		Parameters: json.RawMessage(`{"type":"object","properties":{"user_id":{"type":"string"},"action":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"user_id": "demo-user", "role": "user"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "persona_ops", Description: "Manage assistant persona", Dangerous: true, RequiredRBAC: "admin",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"},"name":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "persona_updated"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "mcp_invoke", Description: "Invoke an MCP tool",
		Parameters: json.RawMessage(`{"type":"object","properties":{"server":{"type":"string"},"tool":{"type":"string"},"args":{"type":"object"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "mcp_invoked"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "agent_dispatch", Description: "Dispatch a task to another agent",
		Parameters: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"task":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "dispatched"}, nil
	})
	registry.Register(&assistant.ToolDefinition{
		Name: "memory_ops", Description: "Read or write assistant memory",
		Parameters: json.RawMessage(`{"type":"object","properties":{"action":{"type":"string"},"key":{"type":"string"},"value":{"type":"string"}}}`),
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]string{"status": "memory_ok"}, nil
	})
	fmt.Printf("    Registered %d tools (dangerous=%d)\n", len(registry.ListDefinitions()), 4)

	// 9c. Session Manager with context window management
	sessions := assistant.NewSessionManager(10, "/tmp/tsg-assistant")
	sess := sessions.NewSession("demo-user", "user")
	fmt.Printf("    Session created: %s (max_ctx=%d)\n", sess.ID, 10)

	// Fill session to trigger context window trimming
	for i := 0; i < 15; i++ {
		_ = sessions.AddMessage(sess.ID, assistant.Message{
			Role:      "user",
			Content:   fmt.Sprintf("Message %d", i),
			Timestamp: time.Now(),
		})
	}
	sess, _ = sessions.Get(sess.ID)
	fmt.Printf("    Context window: added 15 msgs, retained %d (system msg preserved, oldest trimmed)\n", len(sess.Messages))

	// 9d. Security Guard with confirmation gate
	pathChecker := func(path string) bool {
		return len(path) > 0 && (path == "/tmp/tsg-safe" || len(path) > len("/tmp/tsg-safe/") && path[:len("/tmp/tsg-safe/")] == "/tmp/tsg-safe/")
	}
	aguard := assistant.NewAssistantGuard(pathChecker)

	// Test RBAC
	canInvoke := registry.CheckRBAC("user", "add_key")
	fmt.Printf("    RBAC: user can invoke add_key=%v (requires admin)\n", canInvoke)
	canInvoke = registry.CheckRBAC("admin", "add_key")
	fmt.Printf("    RBAC: admin can invoke add_key=%v\n", canInvoke)

	// Test quota
	for i := 0; i < 12; i++ {
		registry.CheckQuota("user", "user_profile")
	}
	quotaOk := registry.CheckQuota("user", "user_profile")
	fmt.Printf("    Quota: user_profile called 12 times (quota=10), last allowed=%v\n", quotaOk)

	// Test confirmation gate for dangerous ops
	token := aguard.RequestConfirmation(sess.ID, "rotate_key", "Rotate production API key", time.Minute)
	fmt.Printf("    Confirm gate: rotate_key token=%s\n", token)
	confirmed := aguard.ConfirmOperation(token)
	fmt.Printf("    Confirm gate: token confirmed=%v\n", confirmed)

	// 9e. HTTP Server end-to-end
	server := assistant.NewServer(router, registry, sessions, aguard)
	ts := httptest.NewServer(server)
	defer ts.Close()

	// Create session via API
	resp, _ := http.Post(ts.URL+"/api/assistant/sessions", "application/json", bytes.NewBufferString(`{"user_id":"demo-api-user","role":"user"}`))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var sessResp map[string]interface{}
	_ = json.Unmarshal(body, &sessResp)
	fmt.Printf("    API POST /sessions: created session id=%s\n", sessResp["id"])

	// Chat via API (auto mode)
	chatReq := fmt.Sprintf(`{"session_id":"%s","message":"Hello assistant","mode":"auto"}`, sessResp["id"])
	resp, _ = http.Post(ts.URL+"/api/assistant/chat", "application/json", bytes.NewBufferString(chatReq))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var chatResp map[string]interface{}
	_ = json.Unmarshal(body, &chatResp)
	prov, _ := chatResp["provider"].(string)
	mode, _ := chatResp["mode"].(string)
	fmt.Printf("    API POST /chat: provider=%s mode=%s\n", prov, mode)

	// Switch to manual mode
	chatReq2 := fmt.Sprintf(`{"session_id":"%s","message":"Use Claude","mode":"manual","provider":"anthropic-claude"}`, sessResp["id"])
	resp, _ = http.Post(ts.URL+"/api/assistant/chat", "application/json", bytes.NewBufferString(chatReq2))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = json.Unmarshal(body, &chatResp)
	prov2, _ := chatResp["provider"].(string)
	mod2, _ := chatResp["model"].(string)
	fmt.Printf("    API POST /chat: switched to manual provider=%s model=%s\n", prov2, mod2)

	// List tools
	resp, _ = http.Get(ts.URL + "/api/assistant/tools")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var toolsResp []map[string]interface{}
	_ = json.Unmarshal(body, &toolsResp)
	fmt.Printf("    API GET /tools: returned %d tool definitions\n", len(toolsResp))

	// List providers
	resp, _ = http.Get(ts.URL + "/api/assistant/providers")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var provResp []map[string]interface{}
	_ = json.Unmarshal(body, &provResp)
	fmt.Printf("    API GET /providers: returned %d providers\n", len(provResp))

	// Health check
	resp, _ = http.Get(ts.URL + "/api/assistant/health")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var healthResp map[string]interface{}
	_ = json.Unmarshal(body, &healthResp)
	fmt.Printf("    API GET /health: status=%v\n", healthResp["status"])

	// UI static endpoint
	resp, _ = http.Get(ts.URL + "/assistant/")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("    UI GET /assistant/: HTML size=%d bytes\n", len(body))
}
