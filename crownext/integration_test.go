// Package crownext provides end-to-end integration tests for v4.1.0 features.
package crownext

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"tarssecureguard-v41/crownext/agentmesh"
	"tarssecureguard-v41/crownext/mcpclient"
	"tarssecureguard-v41/crownext/skylink"
	"tarssecureguard-v41/crownext/threatmodel"
)

// TestMultiAgentMCPAndCrossDevice runs the full v4.1.0 integration scenario:
// 1. Two agents register in the mesh
// 2. One agent dispatches a task to another via supervisor pattern
// 3. The worker agent invokes an MCP tool guarded by RBAC+quota+audit
// 4. Cross-device content addressing and messaging
// 5. Device authentication and isolation checks
func TestMultiAgentMCPAndCrossDevice(t *testing.T) {
	ctx := context.Background()

	// --- Setup Agent Mesh ---
	reg := agentmesh.NewRegistry()
	disp := agentmesh.NewDispatcher(reg)

	// Register supervisor agent
	super := &agentmesh.AgentCard{
		AgentID: "supervisor", Version: "1.0", RBACRole: "admin",
		Accepts: []agentmesh.TaskType{agentmesh.TaskChat},
	}
	reg.RegisterLocal(super)

	// Register worker agent
	worker := &agentmesh.AgentCard{
		AgentID: "worker", Version: "1.0", RBACRole: "user",
		Accepts:      []agentmesh.TaskType{agentmesh.TaskChat},
		Capabilities: []string{"mcp_invoke"},
	}
	reg.RegisterLocal(worker)

	// --- Setup MCP Registry + Guard ---
	mcpReg := mcpclient.NewRegistry()
	mcpReg.RegisterTool(
		&mcpclient.MCPToolDef{Name: "summarize", Description: "summarize text"},
		&mcpclient.ToolPolicy{AllowedRoles: []string{"admin", "user"}, MaxCallsPerMin: 5},
	)
	guard := mcpclient.NewGuard(mcpReg)

	// Bind worker handler: receives task, invokes MCP tool via guard
	disp.RegisterHandler("worker", func(ctx context.Context, task *agentmesh.TaskEnvelope) ([]byte, error) {
		res := guard.Check(ctx, "user", "worker", "summarize")
		if !res.Allowed {
			return nil, fmt.Errorf("mcp guard denied: %s", res.Reason)
		}
		guard.PostInvoke("user", "summarize")
		return []byte(`{"summary":"ok"}`), nil
	})

	// --- Setup SkyLink (cross-device) ---
	discovery := skylink.NewDiscovery()
	discovery.Register(&skylink.DeviceProfile{PeerID: "deviceA", DeviceType: skylink.DeviceServer, Capabilities: []string{"agent_host"}})
	discovery.Register(&skylink.DeviceProfile{PeerID: "deviceB", DeviceType: skylink.DeviceEdge, Capabilities: []string{"agent_host"}})
	discovery.MarkTrusted("deviceA")

	contentStore := skylink.NewContentStore()
	cid, _ := contentStore.Put([]byte("shared-config"))
	contentStore.Pin(cid)

	// Cross-device encrypted messaging
	messenger := skylink.NewMessenger(10)
	key := skylink.DeriveSharedKey([]byte("shared-secret"))
	messenger.RegisterKey("deviceA", key)
	messenger.RegisterKey("deviceB", key)

	// --- Setup Threat Model ---
	authMgr, _ := threatmodel.NewDeviceAuthManager()
	idA, _, _ := authMgr.IssueDeviceCert("deviceA", time.Hour)
	if err := authMgr.VerifyPeer("deviceA", idA.CertPEM); err != nil {
		t.Fatalf("deviceA auth failed: %v", err)
	}

	verifier := threatmodel.NewContentVerifier()
	if err := verifier.Verify([]byte("shared-config"), cid.Hash); err != nil {
		t.Fatalf("content verify failed: %v", err)
	}

	isolator := threatmodel.NewIsolator(time.Hour, 10)
	isolator.Quarantine("deviceC", "untrusted cert", threatmodel.IsolationBlock, nil)
	if err := isolator.Check("deviceC"); err == nil {
		t.Fatal("expected deviceC to be blocked")
	}

	// --- Execute Supervisor Pattern ---
	ps := &agentmesh.PatternSupervisor{}
	task := &agentmesh.TaskEnvelope{
		TaskID:    "integration-1",
		TaskType:  agentmesh.TaskChat,
		FromAgent: "supervisor",
		Payload:   []byte(`{"text":"long text to summarize"}`),
		Metadata:  map[string]string{"worker_count": "1"},
	}
	res, err := ps.Execute(ctx, task, reg, disp)
	if err != nil {
		t.Fatalf("supervisor execute failed: %v", err)
	}
	if res.State != agentmesh.TaskCompleted {
		t.Fatalf("expected completed, got %v", res.State)
	}

	// --- Verify MCP Audit Trail ---
	auditLogs := mcpReg.AuditLog()
	if len(auditLogs) == 0 {
		t.Fatal("expected audit logs from MCP guard")
	}
	found := false
	for _, log := range auditLogs {
		if log.ToolName == "summarize" && log.Allowed {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected allowed summarize audit record")
	}

	// --- Cross-device Messaging ---
	msgPayload := &skylink.MessagePayload{Type: "task", Body: json.RawMessage(`{"done":true}`)}
	msg, err := messenger.Send("deviceA", "deviceB", msgPayload)
	if err != nil {
		t.Fatalf("messenger send failed: %v", err)
	}
	recv, ok := messenger.Receive()
	if !ok || recv.ID != msg.ID {
		t.Fatal("expected message in outbox")
	}

	// --- Discovery Assertions ---
	if discovery.Count() != 2 {
		t.Fatalf("expected 2 devices, got %d", discovery.Count())
	}
	if discovery.CountTrusted() != 1 {
		t.Fatalf("expected 1 trusted device, got %d", discovery.CountTrusted())
	}
	devs := discovery.FindByCapability("agent_host")
	if len(devs) != 2 {
		t.Fatalf("expected 2 agent_host devices, got %d", len(devs))
	}

	// --- Content Store Assertions ---
	if !contentStore.Has(cid) {
		t.Fatal("expected CID to exist in store")
	}
	blocks, pinned, bytes := contentStore.Stats()
	if blocks != 1 || pinned != 1 || bytes != 13 {
		t.Fatalf("unexpected stats: blocks=%d pinned=%d bytes=%d", blocks, pinned, bytes)
	}
}

// TestCoordDeviceSync tests distributed coordination for device state sync.
func TestCoordDeviceSync(t *testing.T) {
	coord := skylink.NewCoordClient()
	ctx := context.Background()

	// Simulate deviceA publishing its agents
	agents := []agentmesh.AgentCard{
		{AgentID: "agentA1", Version: "1.0", RBACRole: "user", DeviceID: "deviceA"},
	}
	data, _ := json.Marshal(agents)
	coord.Put(ctx, "/devices/deviceA/agents", string(data))

	v, err := coord.Get(ctx, "/devices/deviceA/agents")
	if err != nil {
		t.Fatal(err)
	}
	var retrieved []agentmesh.AgentCard
	if err := json.Unmarshal([]byte(v), &retrieved); err != nil {
		t.Fatal(err)
	}
	if len(retrieved) != 1 || retrieved[0].AgentID != "agentA1" {
		t.Fatalf("unexpected retrieved agents: %v", retrieved)
	}
}
