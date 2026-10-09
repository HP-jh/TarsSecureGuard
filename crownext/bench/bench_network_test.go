package bench

import (
	"testing"

	"tarssecureguard-v41/crownext/agentmesh"
	"tarssecureguard-v41/crownext/skylink"
)

// BenchmarkSkylinkEncrypt 网络维度：消息加密（AES-GCM + JSON）
func BenchmarkSkylinkEncrypt(b *testing.B) {
	m := skylink.NewMessenger(100)
	m.RegisterKey("peer-a", skylink.DeriveSharedKey([]byte("test-secret-key-123")))
	payload := &skylink.MessagePayload{Type: "ping", Body: []byte(`{"ts":1234567890}`)}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.Encrypt("peer-a", payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSkylinkDecrypt 网络维度：消息解密
func BenchmarkSkylinkDecrypt(b *testing.B) {
	m := skylink.NewMessenger(100)
	m.RegisterKey("peer-a", skylink.DeriveSharedKey([]byte("test-secret-key-123")))
	payload := &skylink.MessagePayload{Type: "ping", Body: []byte(`{"ts":1234567890}`)}
	msg, err := m.Encrypt("peer-a", payload)
	if err != nil {
		b.Fatal(err)
	}
	msg.FromPeer = "peer-a"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := m.Decrypt(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAgentMeshRegisterLookup 网络维度：Agent 注册与查找
func BenchmarkAgentMeshRegisterLookup(b *testing.B) {
	reg := agentmesh.NewRegistry()
	cards := make([]*agentmesh.AgentCard, 100)
	for i := 0; i < 100; i++ {
		cards[i] = &agentmesh.AgentCard{
			AgentID:  "agent-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			Version:  "4.5.0",
			RBACRole: "user",
			Accepts:  []agentmesh.TaskType{agentmesh.TaskChat},
		}
	}
	for _, c := range cards {
		reg.RegisterLocal(c)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		card, ok := reg.Get(cards[i%100].AgentID)
		if !ok {
			b.Fatal("agent not found")
		}
		_ = card
	}
}

// BenchmarkHarnessNetwork 用 Harness 汇总网络维度
func BenchmarkHarnessNetwork(b *testing.B) {
	h := NewHarness()

	h.Run("Network/SkylinkEncrypt", func(b *testing.B) {
		m := skylink.NewMessenger(100)
		m.RegisterKey("p", skylink.DeriveSharedKey([]byte("secret")))
		pl := &skylink.MessagePayload{Type: "ping", Body: []byte(`{"a":"b"}`)}
		for i := 0; i < b.N; i++ {
			m.Encrypt("p", pl)
		}
	})

	h.Run("Network/SkylinkDecrypt", func(b *testing.B) {
		m := skylink.NewMessenger(100)
		m.RegisterKey("p", skylink.DeriveSharedKey([]byte("secret")))
		pl := &skylink.MessagePayload{Type: "ping", Body: []byte(`{"a":"b"}`)}
		msg, _ := m.Encrypt("p", pl)
		msg.FromPeer = "p"
		for i := 0; i < b.N; i++ {
			m.Decrypt(msg)
		}
	})

	h.Run("Network/AgentMeshLookup", func(b *testing.B) {
		reg := agentmesh.NewRegistry()
		for j := 0; j < 100; j++ {
			reg.RegisterLocal(&agentmesh.AgentCard{AgentID: "a" + string(rune('0'+j)), Version: "4.5.0", RBACRole: "user", Accepts: []agentmesh.TaskType{agentmesh.TaskChat}})
		}
		for i := 0; i < b.N; i++ {
			reg.Get("a0")
		}
	})

	b.Log("\n" + h.Report())
}
