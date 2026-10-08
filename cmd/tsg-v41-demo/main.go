// tsg-v41-demo is a standalone binary demonstrating v4.1.0 features:
// multi-agent collaboration, MCP tool invocation, and distributed device connectivity.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"tarssecureguard-v41/crownext/agentmesh"
	"tarssecureguard-v41/crownext/mcpclient"
	"tarssecureguard-v41/crownext/skylink"
	"tarssecureguard-v41/crownext/threatmodel"
)

func main() {
	fmt.Println("=== TarsSecureGuard v4.1.0 Demo ===")
	fmt.Println("Features: Multi-Agent Collaboration | MCP Integration | Distributed Device Mesh")
	fmt.Println()

	ctx := context.Background()

	// 1. Agent Mesh
	fmt.Println("[1] Agent Mesh Setup")
	reg := agentmesh.NewRegistry()
	disp := agentmesh.NewDispatcher(reg)
	reg.RegisterLocal(&agentmesh.AgentCard{AgentID: "alpha", Version: "4.1.0", RBACRole: "admin", Accepts: []agentmesh.TaskType{agentmesh.TaskChat}})
	reg.RegisterLocal(&agentmesh.AgentCard{AgentID: "beta", Version: "4.1.0", RBACRole: "user", Accepts: []agentmesh.TaskType{agentmesh.TaskChat}, Capabilities: []string{"summarize"}})
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

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
	fmt.Println("v4.1.0 modules: agentmesh | mcpclient | mcpserver | skylink | threatmodel")
	os.Exit(0)
}
