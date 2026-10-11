package main

import (
	"encoding/json"
	"os"
	"time"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ===================== 版本号校验 =====================

func TestMain(m *testing.M) {
	// 初始化知识库（测试用临时目录）
	tmpDir, _ := os.MkdirTemp("", "tsg-kb-test-*")
	defer os.RemoveAll(tmpDir)
	loadConfig()
	initKnowledgeBase(tmpDir)
	initDynadef(DynadefConfig{
		Enabled: true,
		ShadowRules: []ShadowRule{
			{ID: "shadow-sqli", Name: "影子-SQL注入探测", Pattern: "UNION SELECT", Enabled: true},
			{ID: "shadow-xss", Name: "影子-XSS探测", Pattern: "<script", Enabled: true},
		},
		HoneyTokens: HoneyTokenCfg{Enabled: true, HTMLComment: "ht", CookieName: "__ht_session"},
		DecodePerturb: DecodePerturbCfg{Enabled: true, MaxRounds: 3, Techniques: []string{"url", "base64", "html"}},
		HoneypotRoutes: []string{"/admin.php", "/wp-login.php", "/.env"},
		HoneypotDelay:  100 * time.Millisecond,
	})
	initStability()
	code := m.Run()
	os.Exit(code)
}

func TestV390VersionBumped(t *testing.T) {
	if version != "4.6.1" {
		t.Fatalf("version = %q, want 4.6.1", version)
	}
}

// ===================== 知识库基础测试 =====================

func TestV390KnowledgeBaseInit(t *testing.T) {
	if kb == nil {
		t.Fatal("知识库未初始化")
	}
	entries := kb.List("", LevelPublic)
	if len(entries) == 0 {
		t.Fatal("知识库内置种子未注入")
	}
}

func TestV390KnowledgeBaseCRUD(t *testing.T) {
	entry := &KnowledgeEntry{
		Category: CatProtocol,
		Name:     "测试条目",
		Level:    LevelPublic,
		Content:  "测试内容",
		Tags:     []string{"test"},
	}
	if err := kb.Put(entry); err != nil {
		t.Fatalf("Put 失败: %v", err)
	}
	if entry.ID == "" {
		t.Fatal("Put 后 ID 为空")
	}

	got, err := kb.Get(entry.ID)
	if err != nil {
		t.Fatalf("Get 失败: %v", err)
	}
	if got.Content != "测试内容" {
		t.Fatalf("Content 不匹配: got %q", got.Content)
	}

	entries := kb.List(CatProtocol, LevelPublic)
	found := false
	for _, e := range entries {
		if e.ID == entry.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("List 未返回新条目")
	}

	if err := kb.Delete(entry.ID); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	_, err = kb.Get(entry.ID)
	if err == nil {
		t.Fatal("Delete 后仍能 Get")
	}
}

func TestV390KnowledgeBaseEncryption(t *testing.T) {
	// L2 敏感条目测试加密存储
	entry := &KnowledgeEntry{
		Category: CatPII,
		Name:     "加密测试",
		Level:    LevelSensitive,
		Content:  "敏感数据内容",
	}
	if err := kb.Put(entry); err != nil {
		t.Fatalf("Put L2 失败: %v", err)
	}

	// 验证磁盘文件存在且为密文
	path := kb.entryPath(entry.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取磁盘文件失败: %v", err)
	}
	var de diskEntry
	if err := json.Unmarshal(data, &de); err != nil {
		t.Fatalf("解析磁盘文件失败: %v", err)
	}
	if de.CipherText == "敏感数据内容" {
		t.Fatal("L2 条目未加密存储")
	}
	if de.EncryptedBy != "system" {
		t.Fatalf("L2 无用户密钥时应由 system 加密，got %q", de.EncryptedBy)
	}
}

func TestV390KnowledgeBaseAPI(t *testing.T) {
	// 测试 HTTP API
	req := httptest.NewRequest(http.MethodGet, "/api/kb/list?min_level=0", nil)
	rec := httptest.NewRecorder()
	handleKBList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}
	var resp struct {
		Entries []KnowledgeEntry `json:"entries"`
		Count   int              `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 list 响应失败: %v", err)
	}
	if resp.Count == 0 {
		t.Fatal("list API 返回空")
	}
}

// ===================== 动态防护测试 =====================

func TestV390DynadefInit(t *testing.T) {
	if dyna == nil {
		t.Fatal("动态防护引擎未初始化")
	}
	if !dyna.cfg.Enabled {
		t.Fatal("动态防护未启用")
	}
}

func TestV390DynadefHoneypot(t *testing.T) {
	if !dyna.isHoneypotPath("/admin.php") {
		t.Fatal("/admin.php 应被识别为蜜罐路径")
	}
	if dyna.isHoneypotPath("/api/chat/completions") {
		t.Fatal("正常 API 不应被识别为蜜罐")
	}
}

func TestV390DynadefShadowPipeline(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?q=UNION+SELECT", nil)
	hits := dyna.runShadowPipeline(req)
	found := false
	for _, h := range hits {
		if h.RuleID == "shadow-sqli" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("影子规则应命中 UNION SELECT")
	}
}

func TestV390DynadefPerturbDecode(t *testing.T) {
	results := dyna.perturbDecode("test%20value")
	if len(results) == 0 {
		t.Fatal("解码扰动应处理 URL 编码")
	}
}

// ===================== 稳定性测试 =====================

func TestV390SafeCall(t *testing.T) {
	res := SafeCall("test", func() interface{} {
		return 42
	})
	if res.Err != nil {
		t.Fatalf("SafeCall 不应报错: %v", res.Err)
	}
	if res.Result != 42 {
		t.Fatalf("Result 不匹配: got %v", res.Result)
	}
}

func TestV390SafeCallPanic(t *testing.T) {
	res := SafeCall("panic-test", func() interface{} {
		panic("intentional panic")
	})
	if res.Err == nil {
		t.Fatal("SafeCall 应捕获 panic")
	}
	if !strings.Contains(res.Err.Error(), "panic") {
		t.Fatalf("错误消息应包含 panic: %v", res.Err)
	}
}

func TestV390HotConstants(t *testing.T) {
	RefreshHotConstants()
	if hotConst.APIKeyHash == "" {
		t.Fatal("APIKeyHash 不应为空")
	}
}

func TestV390SimpleCache(t *testing.T) {
	cache := NewSimpleCache(10, 5*60*1000*1000) // 5分钟，用纳秒
	cache.Set("key1", "value1")
	v, ok := cache.Get("key1")
	if !ok || v != "value1" {
		t.Fatalf("Cache Get 失败: got %v, ok=%v", v, ok)
	}
}

// ===================== 集成测试：版本 API =====================

func TestV390StatusAPI(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	handleStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	v, ok := resp["version"].(string)
	if !ok || v != "4.6.1" {
		t.Fatalf("版本号不匹配: got %v", v)
	}
}
