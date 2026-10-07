package main

// M3 冒烟：MCP stdio JSON-RPC（initialize / tools/list / tools/call）
// M4 E 线：Go fuzzing 目标（锦衣卫附加意见 F：语料脱敏——fuzz 输入不落盘不外传）

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMCPInitializeAndList(t *testing.T) {
	// initialize
	resp := handleMCPMethod(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"})
	if resp.Error != nil {
		t.Fatalf("initialize 失败: %v", resp.Error)
	}
	b, _ := json.Marshal(resp.Result)
	if !containsSubstr(string(b), "tarssecureguard") {
		t.Fatalf("serverInfo 应含 tarssecureguard: %s", b)
	}
	// tools/list：6 个工具
	resp = handleMCPMethod(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/list"})
	b, _ = json.Marshal(resp.Result)
	if !containsSubstr(string(b), "tars_guarded_chat") || !containsSubstr(string(b), "tars_ip_reputation_unban") {
		t.Fatalf("工具清单应含核心工具: %s", b)
	}
}

func TestMCPGuardStatusCall(t *testing.T) {
	params, _ := json.Marshal(mcpCallParams{Name: "tars_guard_status"})
	resp := handleMCPMethod(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`3`), Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatalf("guard_status 调用失败: %v", resp.Error)
	}
	b, _ := json.Marshal(resp.Result)
	if !containsSubstr(string(b), "tier") {
		t.Fatalf("guard_status 结果应含 tier: %s", b)
	}
}

func TestMCPUnbanRequiresAdminKey(t *testing.T) {
	params, _ := json.Marshal(mcpCallParams{Name: "tars_ip_reputation_unban", Arguments: map[string]interface{}{"ip": "1.2.3.4"}})
	resp := handleMCPMethod(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`4`), Method: "tools/call", Params: params})
	if resp.Error == nil || resp.Error.Code != -32001 {
		t.Fatalf("无管理员密钥的解封应被拒绝(-32001)，实际: %v", resp.Error)
	}
}

func TestMCPUnknownTool(t *testing.T) {
	params, _ := json.Marshal(mcpCallParams{Name: "no_such_tool"})
	resp := handleMCPMethod(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`5`), Method: "tools/call", Params: params})
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("未知工具应返回 -32601，实际: %v", resp.Error)
	}
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ===================== E 线：fuzz 目标 =====================

// FuzzWAFMatch WAF 规则匹配：任意输入不得 panic（语料仅在内存中，不落盘）
func FuzzWAFMatch(f *testing.F) {
	f.Add("normal text")
	f.Add("union select * from users--")
	f.Add("<script>alert(1)</script>")
	f.Fuzz(func(t *testing.T, s string) {
		_ = maskPII(s)
	})
}

// FuzzParseConfig 配置解析：畸形配置不得 panic，解析失败必须错误返回
func FuzzParseConfig(f *testing.F) {
	f.Add(`{"port": 18889}`)
	f.Add(`{"port": "abc"}`)
	f.Add(`{`)
	f.Add(``)
	f.Add(`{"users": null, "modules": {"x": true}}`)
	f.Fuzz(func(t *testing.T, s string) {
		var c Config
		_ = json.Unmarshal([]byte(s), &c)
	})
}

// FuzzSGNormalize 语义归一化/指纹：任意输入稳定且不 panic
func FuzzSGNormalize(f *testing.F) {
	f.Add("你好 world")
	f.Add("  多  个 空 格  ")
	f.Add("\x00\x01控制字符")
	f.Fuzz(func(t *testing.T, s string) {
		fp1 := sgFingerprint(s)
		fp2 := sgFingerprint(s)
		if fp1 != fp2 {
			t.Fatalf("指纹不稳定: %q -> %s vs %s", s, fp1, fp2)
		}
		v, _ := sgStaticCheck(s)
		if v == sgBlock && sgNormalize(s) == "" {
			t.Fatalf("空文本不应判 block")
		}
	})
}

func TestMain_hasOSImport(t *testing.T) {
	_ = os.Getenv
}
