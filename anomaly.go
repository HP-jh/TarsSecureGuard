package main

// v4.35.0 异常行为检测：基于统计的异常流量告警
//
// 设计目标：
//   - 滑动窗口流量统计（QPS / 错误率 / 响应时间），10 秒一桶、默认 60 桶 = 10 分钟窗口
//   - 基于历史均值 + 标准差，3σ 原则检测异常（可配置 σ 阈值）
//   - 异常触发告警：本地日志 + 审计 v2 + SSE 实时推送
//   - 告警冷却期防止告警风暴（默认 60 秒）
//   - 零外部依赖，纯标准库

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"
)

// ===================== 配置 =====================

// AnomalyConfig 异常检测配置段（config.json 顶层键 anomaly）
type AnomalyConfig struct {
	Enabled          bool    `json:"enabled"`          // 默认 true
	WindowBuckets    int     `json:"windowBuckets"`    // 滑动窗口 bucket 数，默认 60
	BucketSeconds    int     `json:"bucketSeconds"`    // 每个 bucket 秒数，默认 10
	SigmaThreshold   float64 `json:"sigmaThreshold"`   // σ 阈值，默认 3.0
	MinSamples       int     `json:"minSamples"`       // 最小历史样本数才触发检测，默认 6
	AlertCooldownSec int     `json:"alertCooldownSec"` // 同类型告警冷却秒数，默认 60
}

// ===================== 数据结构 =====================

// TrafficBucket 单个时间桶的流量数据
type TrafficBucket struct {
	Timestamp      int64 // Unix 秒（对齐到 bucket 边界）
	RequestCount   int
	ErrorCount     int
	TotalLatencyMs int64
}

// AnomalyAlert 异常告警条目
type AnomalyAlert struct {
	ID        string  `json:"id"`
	Timestamp int64   `json:"timestamp"` // Unix 秒
	Severity  string  `json:"severity"`  // info | warn | critical
	Metric    string  `json:"metric"`    // qps | errorRate | latency
	Value     float64 `json:"value"`
	Mean      float64 `json:"mean"`
	StdDev    float64 `json:"stdDev"`
	Sigma     float64 `json:"sigma"`
	Message   string  `json:"message"`
}

// AnomalyDetector 异常检测器
type AnomalyDetector struct {
	mu         sync.RWMutex
	buckets    []TrafficBucket // 环形缓冲区
	head       int             // 最新写入位置
	filled     bool            // 是否已写满一圈
	alerts     []AnomalyAlert  // 历史告警（保留最近 100 条）
	lastAlert  time.Time       // 全局上次告警时间（用于冷却）
	lastAlerts map[string]time.Time // 按 metric 类型记录上次告警时间
	config     AnomalyConfig
}

var anomalyDetector *AnomalyDetector

// ===================== 初始化 =====================

func initAnomalyDetector() {
	anomalyDetector = &AnomalyDetector{
		buckets:    make([]TrafficBucket, 60),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:          true,
			WindowBuckets:    60,
			BucketSeconds:    10,
			SigmaThreshold:   3.0,
			MinSamples:       6,
			AlertCooldownSec: 60,
		},
	}
	logMsg("[ANOMALY] 异常行为检测器已启动（窗口=10min, bucket=10s, σ=3.0）")
}

// ===================== 核心记录 =====================

// RecordRequest 记录一次请求，自动归入当前时间桶并在条件满足时触发检测
func (ad *AnomalyDetector) RecordRequest(latencyMs int64, statusCode int) {
	if ad == nil || !ad.config.Enabled {
		return
	}
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now().Unix()
	bucketSec := int64(ad.config.BucketSeconds)
	currentBucket := (now / bucketSec) * bucketSec

	idx := ad.head
	if ad.buckets[idx].Timestamp != currentBucket {
		// 推进到新 bucket
		ad.head = (ad.head + 1) % len(ad.buckets)
		idx = ad.head
		if idx == 0 {
			ad.filled = true
		}
		ad.buckets[idx] = TrafficBucket{Timestamp: currentBucket}
	}

	ad.buckets[idx].RequestCount++
	ad.buckets[idx].TotalLatencyMs += latencyMs
	if statusCode >= 400 {
		ad.buckets[idx].ErrorCount++
	}

	// 触发检测（持有锁，但计算量极小）
	ad.detectAnomalies()
}

// ===================== 检测引擎 =====================

func (ad *AnomalyDetector) detectAnomalies() {
	valid := ad.collectValid()
	if len(valid) < ad.config.MinSamples+1 {
		return // 样本不足（+1 确保有当前 bucket 和历史基线）
	}

	current := valid[len(valid)-1]
	historical := valid[:len(valid)-1]

	// 分别计算三项指标的历史基线
	qpsVals := make([]float64, len(historical))
	errVals := make([]float64, len(historical))
	latVals := make([]float64, len(historical))

	bucketSec := float64(ad.config.BucketSeconds)
	for i, b := range historical {
		qpsVals[i] = float64(b.RequestCount) / bucketSec
		if b.RequestCount > 0 {
			errVals[i] = float64(b.ErrorCount) / float64(b.RequestCount) * 100
			latVals[i] = float64(b.TotalLatencyMs) / float64(b.RequestCount)
		}
	}

	qpsMean, qpsStd := meanStdDev(qpsVals)
	errMean, errStd := meanStdDev(errVals)
	latMean, latStd := meanStdDev(latVals)

	threshold := ad.config.SigmaThreshold

	// 当前 bucket 指标
	curQPS := float64(current.RequestCount) / bucketSec
	var curErrRate, curLatency float64
	if current.RequestCount > 0 {
		curErrRate = float64(current.ErrorCount) / float64(current.RequestCount) * 100
		curLatency = float64(current.TotalLatencyMs) / float64(current.RequestCount)
	}

	// QPS 异常
	if qpsStd > 0 && math.Abs(curQPS-qpsMean) > threshold*qpsStd {
		ad.emitAlert("qps", curQPS, qpsMean, qpsStd)
	}
	// 错误率异常
	if errStd > 0 && curErrRate > 0 && math.Abs(curErrRate-errMean) > threshold*errStd {
		ad.emitAlert("errorRate", curErrRate, errMean, errStd)
	}
	// 延迟异常（只检测上浮）
	if latStd > 0 && curLatency > latMean+threshold*latStd {
		ad.emitAlert("latency", curLatency, latMean, latStd)
	}
}

func (ad *AnomalyDetector) collectValid() []TrafficBucket {
	var out []TrafficBucket
	if ad.filled {
		for i := 0; i < len(ad.buckets); i++ {
			idx := (ad.head + 1 + i) % len(ad.buckets)
			if ad.buckets[idx].Timestamp > 0 {
				out = append(out, ad.buckets[idx])
			}
		}
	} else {
		for i := 0; i <= ad.head; i++ {
			if ad.buckets[i].Timestamp > 0 {
				out = append(out, ad.buckets[i])
			}
		}
	}
	return out
}

func meanStdDev(vals []float64) (mean, stddev float64) {
	n := len(vals)
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean = sum / float64(n)
	var sq float64
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	stddev = math.Sqrt(sq / float64(n))
	return
}

// ===================== 告警 =====================

func (ad *AnomalyDetector) emitAlert(metric string, value, mean, stddev float64) {
	// 全局冷却
	if time.Since(ad.lastAlert) < time.Duration(ad.config.AlertCooldownSec)*time.Second {
		return
	}
	// 按 metric 类型冷却（防止同一指标连续告警）
	if last, ok := ad.lastAlerts[metric]; ok && time.Since(last) < time.Duration(ad.config.AlertCooldownSec*2)*time.Second {
		return
	}

	sigma := 0.0
	if stddev > 0 {
		sigma = math.Abs(value-mean) / stddev
	}

	severity := "warn"
	if sigma > ad.config.SigmaThreshold*1.5 {
		severity = "critical"
	} else if sigma < ad.config.SigmaThreshold*1.1 {
		severity = "info"
	}

	alert := AnomalyAlert{
		ID:        fmt.Sprintf("anomaly-%d", time.Now().UnixNano()),
		Timestamp: time.Now().Unix(),
		Severity:  severity,
		Metric:    metric,
		Value:     value,
		Mean:      mean,
		StdDev:    stddev,
		Sigma:     sigma,
		Message: fmt.Sprintf("异常流量告警：%s 偏离历史基线 %.2fσ（当前 %.2f，均值 %.2f，标准差 %.2f）",
			metricLabel(metric), sigma, value, mean, stddev),
	}

	ad.alerts = append(ad.alerts, alert)
	if len(ad.alerts) > 100 {
		ad.alerts = ad.alerts[len(ad.alerts)-100:]
	}
	ad.lastAlert = time.Now()
	ad.lastAlerts[metric] = time.Now()

	// 日志 + 审计 v2 + SSE 推送
	logMsg(fmt.Sprintf("[ANOMALY] %s", alert.Message))
	auditV2Write("ANOMALY_DETECTED", "*", "", "system", "", alert.Message, "")
	sseBroadcast(sseEvent{
		Type:      "anomaly",
		Timestamp: time.Now().UnixMilli(),
		Severity:  severity,
		Title:     "异常流量告警",
		Detail:    alert.Message,
		IP:        "-",
	})
}

func metricLabel(m string) string {
	switch m {
	case "qps":
		return "每秒请求数"
	case "errorRate":
		return "错误率"
	case "latency":
		return "平均响应时间"
	}
	return m
}

// ===================== 查询接口 =====================

// Status 返回检测器当前状态与统计
func (ad *AnomalyDetector) Status() map[string]interface{} {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	valid := ad.collectValid()
	var totalReq, totalErr, totalLat int64
	for _, b := range valid {
		totalReq += int64(b.RequestCount)
		totalErr += int64(b.ErrorCount)
		totalLat += b.TotalLatencyMs
	}

	avgLat := 0.0
	if totalReq > 0 {
		avgLat = float64(totalLat) / float64(totalReq)
	}
	errRate := 0.0
	if totalReq > 0 {
		errRate = float64(totalErr) / float64(totalReq) * 100
	}

	recent := make([]AnomalyAlert, len(ad.alerts))
	copy(recent, ad.alerts)

	return map[string]interface{}{
		"enabled":       ad.config.Enabled,
		"windowBuckets": len(ad.buckets),
		"bucketSeconds": ad.config.BucketSeconds,
		"sigmaThreshold": ad.config.SigmaThreshold,
		"totalRequests": totalReq,
		"totalErrors":   totalErr,
		"avgLatencyMs":  round2(avgLat),
		"errorRatePct":  round2(errRate),
		"alertCount":    len(recent),
		"recentAlerts":  recent,
		"bucketCount":   len(valid),
	}
}

// round2 定义在 scoreboard.go（复用）

// ===================== HTTP Handlers =====================

// handleAnomalyStatus GET /api/admin/anomaly/status
func handleAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	if anomalyDetector == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	writeJSON(w, anomalyDetector.Status())
}

// handleAnomalyAlerts GET /api/admin/anomaly/alerts
func handleAnomalyAlerts(w http.ResponseWriter, r *http.Request) {
	if anomalyDetector == nil {
		writeJSON(w, map[string]interface{}{"alerts": []AnomalyAlert{}})
		return
	}
	anomalyDetector.mu.RLock()
	alerts := make([]AnomalyAlert, len(anomalyDetector.alerts))
	copy(alerts, anomalyDetector.alerts)
	anomalyDetector.mu.RUnlock()
	writeJSON(w, map[string]interface{}{"alerts": alerts})
}
