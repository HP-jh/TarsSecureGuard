// security_score.go — v4.36.0 安全评分仪表盘（实时安全态势可视化）
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// ========== 数据模型 ==========

// SecurityScore 实时安全评分总览
type SecurityScore struct {
	OverallScore    int                `json:"overallScore"`    // 0-100 综合评分
	Status          string             `json:"status"`          // safe / warning / danger
	UpdatedAt       time.Time          `json:"updatedAt"`       // 计算时间
	Dimensions      []ScoreDimension   `json:"dimensions"`      // 各维度评分
	Trends          ScoreTrends        `json:"trends"`          // 趋势数据
	Summary         ScoreSummary       `json:"summary"`         // 关键指标摘要
}

// ScoreDimension 单个安全维度评分
type ScoreDimension struct {
	Name        string  `json:"name"`        // 维度名称
	Score       int     `json:"score"`       // 0-100
	Weight      float64 `json:"weight"`      // 权重
	Status      string  `json:"status"`      // safe / warning / danger
	Details     string  `json:"details"`     // 详情说明
	RawValue    float64 `json:"rawValue"`    // 原始值（如命中率百分比）
	RawUnit     string  `json:"rawUnit"`     // 原始值单位
}

// ScoreTrends 安全评分趋势（最近 N 个采样点）
type ScoreTrends struct {
	Overall []TrendPoint `json:"overall"` // 综合评分趋势
	WAF     []TrendPoint `json:"waf"`     // WAF 维度趋势
	Anomaly []TrendPoint `json:"anomaly"` // 异常请求趋势
	Cert    []TrendPoint `json:"cert"`    // 证书健康趋势
}

// TrendPoint 趋势数据点
type TrendPoint struct {
	Timestamp int64 `json:"timestamp"` // Unix 毫秒
	Value     int   `json:"value"`     // 0-100
}

// ScoreSummary 关键指标摘要
type ScoreSummary struct {
	TotalRequests      int64 `json:"totalRequests"`      // 总请求数
	BlockedRequests    int64 `json:"blockedRequests"`    // 被拦截请求数
	FailedRequests     int64 `json:"failedRequests"`     // 失败请求数
	WAFHitRate         float64 `json:"wafHitRate"`       // WAF 命中率 %
	AnomalyRate        float64 `json:"anomalyRate"`      // 异常请求占比 %
	AvgResponseTimeMs  int64 `json:"avgResponseTimeMs"` // 平均响应时间 ms
	UptimeSec          int64 `json:"uptimeSec"`          // 运行时间秒
	ThreatCount        int   `json:"threatCount"`        // 当前威胁数
	BannedIPCount      int   `json:"bannedIPCount"`      // 被封禁 IP 数
}

// ========== 历史数据环形缓冲区 ==========

const scoreHistoryMax = 60 // 保留最近 60 个采样点（约 1 小时，每分钟 1 次）

var (
	scoreHistoryMu sync.RWMutex
	scoreHistory   = make([]SecurityScore, 0, scoreHistoryMax)
)

// recordScoreSnapshot 将当前评分存入历史（由 handleSecurityScore 每次调用时触发）
func recordScoreSnapshot(s SecurityScore) {
	scoreHistoryMu.Lock()
	defer scoreHistoryMu.Unlock()
	if len(scoreHistory) >= scoreHistoryMax {
		scoreHistory = scoreHistory[1:]
	}
	scoreHistory = append(scoreHistory, s)
}

// ========== 评分计算引擎 ==========

// computeSecurityScore 基于真实运行时数据计算安全评分
func computeSecurityScore() SecurityScore {
	now := time.Now()

	// 读取全局统计（受 mu 保护）
	mu.Lock()
	total := int64(totalReq)
	_ = int64(successReq) // succ unused
	fail := int64(failReq)
	blocks := int64(wafBlocks)
	respTotal := respTotalMs
	respSamples := respSamples
	mu.Unlock()

	// 读取防火墙状态
	fw := firewallStatusSnapshot()
	banCount := 0
	if v, ok := fw["bannedIPs"].(int); ok {
		banCount = v
	}

	// 读取安全扫描状态
	sec360Mu.RLock()
	scanResult := lastScanResult
	threatCount := len(threatDB)
	sec360Mu.RUnlock()

	// 读取配置状态
	cfgMu.RLock()
	wafOn := cfg.Security.WAFEnabled
	mode := cfg.Security.Mode
	auditOn := cfg.Security.AuditLogEnabled
	piiOn := cfg.Security.PIIMaskEnabled
	cfgMu.RUnlock()

	// 计算 WAF 命中率
	var wafHitRate float64
	if total > 0 {
		wafHitRate = float64(blocks) / float64(total) * 100
	}

	// 计算异常请求占比（失败 + WAF 拦截）
	var anomalyRate float64
	if total > 0 {
		anomalyRate = float64(fail+blocks) / float64(total) * 100
	}

	// 计算平均响应时间
	var avgRT int64
	if respSamples > 0 {
		avgRT = respTotal / respSamples
	}

	// 证书健康度检查
	certScore, certDetail, certRaw := checkCertificateHealth()

	// ====== 各维度评分 ======
	dims := make([]ScoreDimension, 0, 6)

	// 1. WAF 防护评分（权重 25%）
	// WAF 开启且有拦截记录 = 高分；未开启 = 0 分
	wafScore := 0
	wafStatus := "danger"
	wafDetail := "WAF 未启用"
	if wafOn {
		if total > 0 && blocks > 0 {
			// 有实际拦截：基于命中率调整
			// 命中率 0-1% = 优秀；1-5% = 良好；5-10% = 警告；>10% = 危险（攻击密集）
			if wafHitRate < 1 {
				wafScore = 95
				wafStatus = "safe"
				wafDetail = fmt.Sprintf("WAF 运行正常，命中率 %.2f%%", wafHitRate)
			} else if wafHitRate < 5 {
				wafScore = 85
				wafStatus = "safe"
				wafDetail = fmt.Sprintf("WAF 检测到一定攻击流量，命中率 %.2f%%", wafHitRate)
			} else if wafHitRate < 10 {
				wafScore = 70
				wafStatus = "warning"
				wafDetail = fmt.Sprintf("攻击流量偏高，命中率 %.2f%%，建议关注", wafHitRate)
			} else {
				wafScore = 50
				wafStatus = "warning"
				wafDetail = fmt.Sprintf("攻击流量密集，命中率 %.2f%%，建议升级防护", wafHitRate)
			}
		} else if total > 0 {
			// WAF 开启但无拦截（可能是正常流量或规则宽松）
			wafScore = 90
			wafStatus = "safe"
			wafDetail = "WAF 运行中，当前无恶意流量"
		} else {
			wafScore = 80
			wafStatus = "safe"
			wafDetail = "WAF 已启用（暂无请求数据）"
		}
	}
	dims = append(dims, ScoreDimension{
		Name: "WAF防护", Score: wafScore, Weight: 0.25, Status: wafStatus,
		Details: wafDetail, RawValue: wafHitRate, RawUnit: "%",
	})

	// 2. 请求健康度评分（权重 20%）
	// 异常率越低越好
	reqScore := 100
	reqStatus := "safe"
	reqDetail := "请求健康度良好"
	if total > 0 {
		if anomalyRate > 20 {
			reqScore = 40
			reqStatus = "danger"
			reqDetail = fmt.Sprintf("异常请求占比 %.2f%%，系统面临严重攻击", anomalyRate)
		} else if anomalyRate > 10 {
			reqScore = 60
			reqStatus = "warning"
			reqDetail = fmt.Sprintf("异常请求占比 %.2f%%，建议排查", anomalyRate)
		} else if anomalyRate > 5 {
			reqScore = 75
			reqStatus = "warning"
			reqDetail = fmt.Sprintf("异常请求占比 %.2f%%", anomalyRate)
		} else if anomalyRate > 1 {
			reqScore = 90
			reqStatus = "safe"
			reqDetail = fmt.Sprintf("异常请求占比 %.2f%%，处于正常范围", anomalyRate)
		} else {
			reqScore = 98
			reqStatus = "safe"
			reqDetail = fmt.Sprintf("异常请求占比 %.2f%%，非常健康", anomalyRate)
		}
	}
	dims = append(dims, ScoreDimension{
		Name: "请求健康", Score: reqScore, Weight: 0.20, Status: reqStatus,
		Details: reqDetail, RawValue: anomalyRate, RawUnit: "%",
	})

	// 3. 证书健康度（权重 15%）
	dims = append(dims, ScoreDimension{
		Name: "证书健康", Score: certScore, Weight: 0.15, Status: certStatus(certScore),
		Details: certDetail, RawValue: certRaw, RawUnit: "天",
	})

	// 4. 威胁处置评分（权重 15%）
	threatScore := 100
	threatStatus := "safe"
	threatDetail := "无活跃威胁"
	if scanResult != nil {
		if threatCount > 0 {
			// 有未解决威胁：按数量扣减
			threatScore = max(0, 100-threatCount*10)
			if threatScore < 60 {
				threatStatus = "danger"
				threatDetail = fmt.Sprintf("发现 %d 个未解决威胁，需立即处理", threatCount)
			} else if threatScore < 80 {
				threatStatus = "warning"
				threatDetail = fmt.Sprintf("发现 %d 个未解决威胁", threatCount)
			} else {
				threatStatus = "safe"
				threatDetail = fmt.Sprintf("发现 %d 个低危威胁", threatCount)
			}
		} else {
			threatScore = scanResult.Score
			threatStatus = scanResult.Status
			threatDetail = "安全扫描完成，无威胁"
		}
	} else {
		threatScore = 70
		threatStatus = "warning"
		threatDetail = "尚未执行安全扫描"
	}
	dims = append(dims, ScoreDimension{
		Name: "威胁处置", Score: threatScore, Weight: 0.15, Status: threatStatus,
		Details: threatDetail, RawValue: float64(threatCount), RawUnit: "个",
	})

	// 5. 配置安全评分（权重 15%）
	cfgScore := 0
	cfgStatus := "danger"
	cfgDetail := ""
	cfgChecks := 0
	if wafOn {
		cfgChecks++
	}
	if auditOn {
		cfgChecks++
	}
	if piiOn {
		cfgChecks++
	}
	if mode == "strict" {
		cfgChecks++
	}
	switch cfgChecks {
	case 4:
		cfgScore = 100
		cfgStatus = "safe"
		cfgDetail = "安全配置最优：WAF+审计+PII脱敏+严格模式"
	case 3:
		cfgScore = 90
		cfgStatus = "safe"
		cfgDetail = "安全配置良好"
	case 2:
		cfgScore = 75
		cfgStatus = "warning"
		cfgDetail = "安全配置尚可，建议开启更多防护"
	case 1:
		cfgScore = 50
		cfgStatus = "warning"
		cfgDetail = "安全配置薄弱，建议加强"
	default:
		cfgScore = 20
		cfgStatus = "danger"
		cfgDetail = "安全配置严重不足"
	}
	dims = append(dims, ScoreDimension{
		Name: "配置安全", Score: cfgScore, Weight: 0.15, Status: cfgStatus,
		Details: cfgDetail, RawValue: float64(cfgChecks), RawUnit: "/4",
	})

	// 6. 防火墙评分（权重 10%）
	fwScore := 80
	fwStatus := "safe"
	fwDetail := "防火墙运行中"
	if banCount > 0 {
		fwDetail = fmt.Sprintf("防火墙运行中，已封禁 %d 个 IP", banCount)
	}
	if pol, ok := fw["policy"].(string); ok && pol == "off" {
		fwScore = 30
		fwStatus = "danger"
		fwDetail = "防火墙策略为 off，系统暴露"
	}
	dims = append(dims, ScoreDimension{
		Name: "防火墙", Score: fwScore, Weight: 0.10, Status: fwStatus,
		Details: fwDetail, RawValue: float64(banCount), RawUnit: "个",
	})

	// ====== 综合评分（加权平均）======
	overall := 0.0
	for _, d := range dims {
		overall += float64(d.Score) * d.Weight
	}
	overallScore := int(overall)
	if overallScore > 100 {
		overallScore = 100
	}
	if overallScore < 0 {
		overallScore = 0
	}

	overallStatus := "safe"
	if overallScore < 60 {
		overallStatus = "danger"
	} else if overallScore < 80 {
		overallStatus = "warning"
	}

	// ====== 趋势数据 ======
	trends := buildScoreTrends(now)

	score := SecurityScore{
		OverallScore: overallScore,
		Status:       overallStatus,
		UpdatedAt:    now,
		Dimensions:   dims,
		Trends:       trends,
		Summary: ScoreSummary{
			TotalRequests:     total,
			BlockedRequests:   blocks,
			FailedRequests:    fail,
			WAFHitRate:        round2(wafHitRate),
			AnomalyRate:       round2(anomalyRate),
			AvgResponseTimeMs: avgRT,
			UptimeSec:         int64(time.Since(startTime).Seconds()),
			ThreatCount:       threatCount,
			BannedIPCount:     banCount,
		},
	}

	// 存入历史
	recordScoreSnapshot(score)
	return score
}

// checkCertificateHealth 检查证书健康度
// 返回：评分(0-100)、详情描述、剩余天数
func checkCertificateHealth() (score int, detail string, daysLeft float64) {
	cfgMu.RLock()
	certPath := "" // cfg.Security.Firewall.ServerCertPath not available
	cfgMu.RUnlock()

	if certPath == "" {
		// 无自定义证书：检查自签名临时证书
		certPath = "./certs/server.crt"
	}

	pemData, err := os.ReadFile(certPath)
	if err != nil {
		// 无证书文件：可能是未启用 TLS 或证书未配置
		return 70, "未检测到自定义证书（使用默认配置）", 0
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return 50, "证书文件解析失败", 0
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 50, "证书格式无效", 0
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return 30, "证书尚未生效", 0
	}
	if now.After(cert.NotAfter) {
		return 0, "证书已过期，请立即更换", 0
	}

	left := cert.NotAfter.Sub(now).Hours() / 24
	daysLeft = round2(left)

	if left > 60 {
		score = 100
		detail = fmt.Sprintf("证书健康，剩余 %.0f 天", daysLeft)
	} else if left > 30 {
		score = 90
		detail = fmt.Sprintf("证书即将到期，剩余 %.0f 天", daysLeft)
	} else if left > 14 {
		score = 70
		detail = fmt.Sprintf("证书即将到期，剩余 %.0f 天，建议续期", daysLeft)
	} else if left > 7 {
		score = 50
		detail = fmt.Sprintf("证书即将到期，剩余 %.0f 天，请尽快续期", daysLeft)
	} else {
		score = 20
		detail = fmt.Sprintf("证书即将到期，剩余 %.0f 天，请立即续期", daysLeft)
	}
	return score, detail, daysLeft
}

func certStatus(score int) string {
	if score >= 80 {
		return "safe"
	}
	if score >= 60 {
		return "warning"
	}
	return "danger"
}

// buildScoreTrends 从历史数据构建趋势
func buildScoreTrends(now time.Time) ScoreTrends {
	scoreHistoryMu.RLock()
	defer scoreHistoryMu.RUnlock()

	t := ScoreTrends{
		Overall: make([]TrendPoint, 0, len(scoreHistory)),
		WAF:     make([]TrendPoint, 0, len(scoreHistory)),
		Anomaly: make([]TrendPoint, 0, len(scoreHistory)),
		Cert:    make([]TrendPoint, 0, len(scoreHistory)),
	}

	for _, h := range scoreHistory {
		ms := h.UpdatedAt.UnixMilli()
		t.Overall = append(t.Overall, TrendPoint{Timestamp: ms, Value: h.OverallScore})
		for _, d := range h.Dimensions {
			switch d.Name {
			case "WAF防护":
				t.WAF = append(t.WAF, TrendPoint{Timestamp: ms, Value: d.Score})
			case "请求健康":
				t.Anomaly = append(t.Anomaly, TrendPoint{Timestamp: ms, Value: d.Score})
			case "证书健康":
				t.Cert = append(t.Cert, TrendPoint{Timestamp: ms, Value: d.Score})
			}
		}
	}
	return t
}


// ========== HTTP Handler ==========

func handleSecurityScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}

	score := computeSecurityScore()
	writeJSON(w, score)
}
