package main

// v3.0.1 专项测试：Tier 1（TTL clamp / 白名单 / 缓存 HMAC 防篡改）+ sidecarHub（manifest 校验链）

import (
	"encoding/json"
	"strings"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// ---------- Tier 1：TTL clamp（[TIER1_CACHE_DEGRADE]：60-3600，默认 300） ----------

func TestTier1CacheTTLClamp(t *testing.T) {
	orig := v3Config()
	defer loadV3Config(func() []byte { b, _ := json.Marshal(orig); return b }())
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, 300 * time.Second},        // 未配置 → 默认 300
		{10, 60 * time.Second},        // 过小 → 下限 60
		{300, 300 * time.Second},      // 正常值原样
		{99999, 3600 * time.Second},   // 过大 → 上限 3600
	}
	for _, c := range cases {
		loadV3Config([]byte(fmt.Sprintf(`{"tier1":{"cacheTtlSeconds":%d}}`, c.in)))
		if got := tier1CacheTTL(); got != c.want {
			t.Errorf("cacheTtlSeconds=%d: got %v want %v", c.in, got, c.want)
		}
	}
}

// ---------- Tier 1：白名单（[TIER1_ALLOWLIST]：精确 argv，禁 shell 中介/提权/杂项工具） ----------

func TestTier1AllowListed(t *testing.T) {
	// 各平台都应拒绝的形态：v3.0.0 违规直调的工具、shell 中介、提权
	bad := [][]string{
		{"nvidia-smi"},
		{"wmic", "path", "win32_VideoController", "get", "name"},
		{"powershell.exe", "-Command", "Get-CimInstance", "Win32_VideoController"},
		{"sh", "-c", "lspci -mm -v"},
		{"sudo", "dmidecode", "-t", "1"},
		{"lspci", "-mm", "-v", "|", "grep", "VGA"},
	}
	for _, argv := range bad {
		if tier1AllowListed("test", argv) {
			t.Errorf("白名单不应放行: %v", argv)
		}
	}
	if runtime.GOOS == "linux" {
		good := [][]string{
			{"lspci", "-mm", "-v"},
			{"dmidecode", "-t", "1"},
			{"dmidecode", "-t", "17"},
			{"cat", "/proc/cpuinfo"},
			{"cat", "/proc/meminfo"},
		}
		for _, argv := range good {
			if !tier1AllowListed("test", argv) {
				t.Errorf("Linux 白名单应放行: %v", argv)
			}
		}
		more := [][]string{
			{"lspci", "-mm"},                    // 参数不全
			{"dmidecode", "-t", "5"},            // 未允许的 type
			{"cat", "/etc/passwd"},              // 白名单外文件
			{"cat", "/proc/cpuinfo", "extra"},   // 参数多出
		}
		for _, argv := range more {
			if tier1AllowListed("test", argv) {
				t.Errorf("Linux 白名单不应放行: %v", argv)
			}
		}
	}
}

// ---------- Tier 1：缓存 HMAC 防篡改（[TIER1_CACHE_DEGRADE]：0600 + HMAC-SHA256 内存密钥） ----------

func TestTier1CacheMACDetectsTamper(t *testing.T) {
	f := &tier1CacheFile{
		WrittenAt: time.Now().Unix(),
		Data:      map[string]string{"gpu": "Ada", "cpu": "Zen"},
	}
	f.HMAC = tier1CacheMAC(f)
	if tier1CacheMAC(f) != f.HMAC {
		t.Fatal("同一内容两次计算 MAC 不一致")
	}
	orig := f.Data["gpu"]
	f.Data["gpu"] = "TamperedGPU"
	if tier1CacheMAC(f) == f.HMAC {
		t.Error("数据被篡改后 MAC 未变化（HMAC 防篡改失效）")
	}
	f.Data["gpu"] = orig
	// 新增键也应改变 MAC
	f.Data["board"] = "X"
	if tier1CacheMAC(f) == f.HMAC {
		t.Error("新增字段后 MAC 未变化")
	}
}

// ---------- sidecarHub：manifest 校验链（钉扎 / 逃逸 / 摘要不符 / command 引用） ----------

func sidecarTestEnv(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	oldCfgPath := configPath
	oldV3 := v3Config()
	oldRejected := hubRejected
	oldRejectedK := hubRejectedK
	t.Cleanup(func() {
		configPath = oldCfgPath
		b, _ := json.Marshal(oldV3)
		loadV3Config(b)
		hubRejected = oldRejected
		hubRejectedK = oldRejectedK
	})
	configPath = filepath.Join(dir, "config.json")
	hubRejected = map[string]sidecarRejected{}
	hubRejectedK = map[string]string{}
	loadV3Config([]byte(`{"sidecar":{"modules":{}}}`))
	return dir
}

func sidecarWriteManifest(t *testing.T, dir, id, artifact string, command []string) {
	t.Helper()
	modDir := filepath.Join(dir, "modules.d", id)
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if artifact != "" {
		if err := os.WriteFile(filepath.Join(modDir, filepath.Base(artifact)), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	man := map[string]interface{}{"id": id, "name": id, "version": "1.0", "artifact": artifact, "command": command}
	b, _ := json.Marshal(man)
	if err := os.WriteFile(filepath.Join(dir, "modules.d", id+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sidecarRejectedReason(id string) string {
	hubMu.Lock()
	defer hubMu.Unlock()
	r, ok := hubRejected[id]
	if !ok {
		return ""
	}
	return r.Reason
}

func TestSidecarRejectUnpinned(t *testing.T) {
	dir := sidecarTestEnv(t)
	sidecarWriteManifest(t, dir, "m1", "a.sh", []string{"modules.d/m1/a.sh"})
	sidecarScan()
	reason := sidecarRejectedReason("m1")
	if reason == "" {
		t.Fatal("未钉扎的模块应被拒绝加载")
	}
	if !strings.Contains(reason, "未钉扎") {
		t.Errorf("拒绝原因应提示未钉扎，实际：%s", reason)
	}
	// 未钉扎拒绝时应给出实测 SHA-256 供管理员确认
	artRaw, _ := os.ReadFile(filepath.Join(dir, "modules.d", "m1", "a.sh"))
	wantSHA := fmt.Sprintf("%x", sha256Raw(artRaw))
	if !strings.Contains(reason, wantSHA) {
		t.Errorf("拒绝原因应包含实测摘要 %s，实际：%s", wantSHA, reason)
	}
}

func TestSidecarRejectSHA256Mismatch(t *testing.T) {
	dir := sidecarTestEnv(t)
	sidecarWriteManifest(t, dir, "m2", "a.sh", []string{"modules.d/m2/a.sh"})
	loadV3Config([]byte(`{"sidecar":{"modules":{"m2":{"sha256":"deadbeef"}}}}`))
	sidecarScan()
	reason := sidecarRejectedReason("m2")
	if !strings.Contains(reason, "摘要不符") {
		t.Fatalf("摘要不符应被拒绝，实际：%q", reason)
	}
}

func TestSidecarRejectArtifactEscape(t *testing.T) {
	dir := sidecarTestEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "modules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// artifact 指向目录外（逃逸）
	man := map[string]interface{}{"id": "m3", "artifact": "../outside.sh", "command": []string{"modules.d/m3/../outside.sh"}}
	b, _ := json.Marshal(man)
	if err := os.WriteFile(filepath.Join(dir, "modules.d", "m3.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	loadV3Config([]byte(`{"sidecar":{"modules":{"m3":{"sha256":"00"}}}}`))
	sidecarScan()
	reason := sidecarRejectedReason("m3")
	if !strings.Contains(reason, "逃逸") && !strings.Contains(reason, "不可读") {
		t.Fatalf("artifact 逃逸应被拒绝，实际：%q", reason)
	}
}

func TestSidecarRejectCommandNotReferencingArtifact(t *testing.T) {
	dir := sidecarTestEnv(t)
	sidecarWriteManifest(t, dir, "m4", "a.sh", []string{"echo", "hi"})
	artRaw, _ := os.ReadFile(filepath.Join(dir, "modules.d", "m4", "a.sh"))
	sha := fmt.Sprintf("%x", sha256Raw(artRaw))
	loadV3Config([]byte(fmt.Sprintf(`{"sidecar":{"modules":{"m4":{"sha256":%q}}}}`, sha)))
	sidecarScan()
	reason := sidecarRejectedReason("m4")
	if !strings.Contains(reason, "command 未引用") {
		t.Fatalf("command 未引用 artifact 应被拒绝，实际：%q", reason)
	}
}

func TestSidecarRejectBadManifest(t *testing.T) {
	dir := sidecarTestEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "modules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "modules.d", "m5.json"), []byte(`{"id":"m5"}`), 0o644); err != nil {
		t.Fatal(err) // 无 command 字段
	}
	sidecarScan()
	if sidecarRejectedReason("m5") == "" {
		t.Fatal("缺 command 的 manifest 应被拒绝")
	}
}

