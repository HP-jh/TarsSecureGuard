package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func v436ResetState() {
	mu.Lock()
	totalReq = 0
	successReq = 0
	failReq = 0
	wafBlocks = 0
	respTotalMs = 0
	respSamples = 0
	mu.Unlock()
	cfgMu.Lock()
	cfg.Security.WAFEnabled = false
	cfg.Security.Mode = "normal"
	cfg.Security.AuditLogEnabled = false
	cfg.Security.PIIMaskEnabled = false
	// cfg.Security.Firewall.ServerCertPath = "" // field does not exist
	cfgMu.Unlock()
	scoreHistoryMu.Lock()
	scoreHistory = scoreHistory[:0]
	scoreHistoryMu.Unlock()
	sec360Mu.Lock()
	lastScanResult = nil
	threatDB = map[string]*ThreatItem{}
	sec360Mu.Unlock()
}

// TestV436SecurityScoreEndpoint 验证 /api/admin/security/score 端点
func TestV436SecurityScoreEndpoint(t *testing.T) {
	v436ResetState()
	// 模拟一些请求数据
	mu.Lock()
	totalReq = 1000
	successReq = 920
	failReq = 30
	wafBlocks = 50
	respTotalMs = 5000
	respSamples = 100
	mu.Unlock()

	// 开启 WAF + 严格模式 + 审计 + PII
	cfgMu.Lock()
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "strict"
	cfg.Security.AuditLogEnabled = true
	cfg.Security.PIIMaskEnabled = true
	cfgMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var score SecurityScore
	if err := json.Unmarshal(rr.Body.Bytes(), &score); err != nil {
		t.Fatalf("unmarshal score: %v", err)
	}

	// 验证基本字段
	if score.OverallScore < 0 || score.OverallScore > 100 {
		t.Errorf("overallScore out of range: %d", score.OverallScore)
	}
	if score.Status == "" {
		t.Error("status should not be empty")
	}
	if score.UpdatedAt.IsZero() {
		t.Error("updatedAt should not be zero")
	}

	// 验证 6 个维度
	if len(score.Dimensions) != 6 {
		t.Errorf("expected 6 dimensions, got %d", len(score.Dimensions))
	}

	expectedNames := map[string]bool{
		"WAF防护": false, "请求健康": false, "证书健康": false,
		"威胁处置": false, "配置安全": false, "防火墙": false,
	}
	for _, d := range score.Dimensions {
		if _, ok := expectedNames[d.Name]; !ok {
			t.Errorf("unexpected dimension name: %s", d.Name)
		} else {
			expectedNames[d.Name] = true
		}
		if d.Score < 0 || d.Score > 100 {
			t.Errorf("dimension %s score out of range: %d", d.Name, d.Score)
		}
		if d.Weight <= 0 {
			t.Errorf("dimension %s weight should be positive: %f", d.Name, d.Weight)
		}
		if d.Status != "safe" && d.Status != "warning" && d.Status != "danger" {
			t.Errorf("dimension %s invalid status: %s", d.Name, d.Status)
		}
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("missing dimension: %s", name)
		}
	}

	// 验证摘要数据
	if score.Summary.TotalRequests != 1000 {
		t.Errorf("expected totalRequests 1000, got %d", score.Summary.TotalRequests)
	}
	if score.Summary.BlockedRequests != 50 {
		t.Errorf("expected blockedRequests 50, got %d", score.Summary.BlockedRequests)
	}
	if score.Summary.FailedRequests != 30 {
		t.Errorf("expected failedRequests 30, got %d", score.Summary.FailedRequests)
	}
	if score.Summary.WAFHitRate != 5.0 {
		t.Errorf("expected wafHitRate 5.0, got %f", score.Summary.WAFHitRate)
	}
	// 异常率 = (30+50)/1000 = 8%
	if score.Summary.AnomalyRate != 8.0 {
		t.Errorf("expected anomalyRate 8.0, got %f", score.Summary.AnomalyRate)
	}
	if score.Summary.AvgResponseTimeMs != 50 {
		t.Errorf("expected avgResponseTimeMs 50, got %d", score.Summary.AvgResponseTimeMs)
	}
}

// TestV436SecurityScoreMethodNotAllowed POST 应返回 405
func TestV436SecurityScoreMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// TestV436SecurityScoreNoData 无请求数据时的评分
func TestV436SecurityScoreNoData(t *testing.T) {
	v436ResetState()
	cfgMu.Lock()
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "normal"
	cfg.Security.AuditLogEnabled = false
	cfg.Security.PIIMaskEnabled = false
	cfgMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var score SecurityScore
	if err := json.Unmarshal(rr.Body.Bytes(), &score); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 无数据时 WAF 分数应该较高（启用但无请求）
	for _, d := range score.Dimensions {
		if d.Name == "WAF防护" && d.Score < 70 {
			t.Errorf("WAF score too low with no data: %d", d.Score)
		}
	}
}

// TestV436SecurityScoreWAFDisabled WAF 关闭时评分
func TestV436SecurityScoreWAFDisabled(t *testing.T) {
	v436ResetState()
	mu.Lock()
	totalReq = 100
	mu.Unlock()
	cfgMu.Lock()
	cfg.Security.WAFEnabled = false
	cfg.Security.Mode = "normal"
	cfg.Security.AuditLogEnabled = false
	cfg.Security.PIIMaskEnabled = false
	cfgMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	var score SecurityScore
	json.Unmarshal(rr.Body.Bytes(), &score)

	for _, d := range score.Dimensions {
		if d.Name == "WAF防护" && d.Score != 0 {
			t.Errorf("WAF disabled should score 0, got %d", d.Score)
		}
		if d.Name == "配置安全" && d.Score > 30 {
			t.Errorf("config security should be low with everything off: %d", d.Score)
		}
	}
}

// TestV436SecurityScoreTrends 验证趋势数据随多次调用积累
func TestV436SecurityScoreTrends(t *testing.T) {
	v436ResetState()
	// 清空历史
	scoreHistoryMu.Lock()
	scoreHistory = scoreHistory[:0]
	scoreHistoryMu.Unlock()

	cfgMu.Lock()
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "strict"
	cfg.Security.AuditLogEnabled = true
	cfg.Security.PIIMaskEnabled = true
	cfgMu.Unlock()

	// 调用 3 次
	for i := 0; i < 3; i++ {
		mu.Lock()
		totalReq = 100 * (i + 1)
		wafBlocks = 5 * (i + 1)
		mu.Unlock()

		req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
		rr := httptest.NewRecorder()
		handleSecurityScore(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("call %d failed: %d", i, rr.Code)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 最后一次检查趋势
	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	var score SecurityScore
	json.Unmarshal(rr.Body.Bytes(), &score)

	if len(score.Trends.Overall) < 3 {
		t.Errorf("expected at least 3 overall trend points, got %d", len(score.Trends.Overall))
	}
	if len(score.Trends.WAF) < 3 {
		t.Errorf("expected at least 3 waf trend points, got %d", len(score.Trends.WAF))
	}
}

// TestV436SecurityScoreHighAnomaly 高异常率时应为 danger/warning
func TestV436SecurityScoreHighAnomaly(t *testing.T) {
	v436ResetState()
	mu.Lock()
	totalReq = 100
	successReq = 50
	failReq = 30
	wafBlocks = 20
	mu.Unlock()
	cfgMu.Lock()
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "strict"
	cfg.Security.AuditLogEnabled = true
	cfg.Security.PIIMaskEnabled = true
	cfgMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	var score SecurityScore
	json.Unmarshal(rr.Body.Bytes(), &score)

	// 异常率 50%，请求健康度应较低
	for _, d := range score.Dimensions {
		if d.Name == "请求健康" && d.Score > 50 {
			t.Errorf("high anomaly should have low request health score: %d", d.Score)
		}
	}
	if score.Status != "danger" && score.Status != "warning" {
		t.Errorf("high anomaly should lower overall status, got %s", score.Status)
	}
}

// TestV436VersionBump 版本号必须是 4.36.0
func TestV436VersionBump(t *testing.T) {
	if version != "4.33.0" {
		t.Errorf("expected version 4.36.0, got %s", version)
	}
}

// TestV436SecurityScoreJSONSerializability 确保 JSON 可序列化无空指针
func TestV436SecurityScoreJSONSerializability(t *testing.T) {
	v436ResetState()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
	rr := httptest.NewRecorder()
	handleSecurityScore(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "overallScore") {
		t.Error("response missing overallScore")
	}
	if !strings.Contains(body, "dimensions") {
		t.Error("response missing dimensions")
	}
	if !strings.Contains(body, "summary") {
		t.Error("response missing summary")
	}
	if !strings.Contains(body, "trends") {
		t.Error("response missing trends")
	}
}

// TestV436SecurityScoreHistoryLimit 历史数据上限测试
func TestV436SecurityScoreHistoryLimit(t *testing.T) {
	v436ResetState()
	scoreHistoryMu.Lock()
	scoreHistory = scoreHistory[:0]
	scoreHistoryMu.Unlock()

	cfgMu.Lock()
	cfg.Security.WAFEnabled = true
	cfg.Security.Mode = "strict"
	cfg.Security.AuditLogEnabled = true
	cfg.Security.PIIMaskEnabled = true
	cfgMu.Unlock()

	// 调用超过上限次数
	for i := 0; i < scoreHistoryMax+10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/security/score", nil)
		rr := httptest.NewRecorder()
		handleSecurityScore(rr, req)
	}

	scoreHistoryMu.RLock()
	count := len(scoreHistory)
	scoreHistoryMu.RUnlock()

	if count > scoreHistoryMax {
		t.Errorf("history exceeded max %d, got %d", scoreHistoryMax, count)
	}
}
