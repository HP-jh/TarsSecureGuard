package main

import (
	"math"
	"net/http"
	"testing"
	"time"
)

// ===================== 单元测试 =====================

func TestMeanStdDev(t *testing.T) {
	// 正常数据集
	mean, std := meanStdDev([]float64{10, 20, 30, 40, 50})
	if math.Abs(mean-30) > 0.001 {
		t.Fatalf("mean want 30, got %v", mean)
	}
	if math.Abs(std-14.142) > 0.01 {
		t.Fatalf("std want ~14.14, got %v", std)
	}

	// 空数据集
	mean, std = meanStdDev([]float64{})
	if mean != 0 || std != 0 {
		t.Fatalf("empty set should return 0,0, got %v,%v", mean, std)
	}

	// 单一值
	mean, std = meanStdDev([]float64{42})
	if mean != 42 || std != 0 {
		t.Fatalf("single value should return 42,0, got %v,%v", mean, std)
	}
}

func TestAnomalyDetectorRecordRequest(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 10),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:        true,
			WindowBuckets:  10,
			BucketSeconds:  1,
			SigmaThreshold: 3.0,
			MinSamples:     2,
		},
	}

	// 记录 5 条请求
	for i := 0; i < 5; i++ {
		ad.RecordRequest(100, http.StatusOK)
	}

	ad.mu.RLock()
	if ad.head != 0 {
		t.Fatalf("head should be 0 (only 1 bucket used within 1s), got %d", ad.head)
	}
	b := ad.buckets[ad.head]
	ad.mu.RUnlock()

	if b.RequestCount != 5 {
		t.Fatalf("request count want 5, got %d", b.RequestCount)
	}
	if b.TotalLatencyMs != 500 {
		t.Fatalf("latency sum want 500, got %d", b.TotalLatencyMs)
	}
	if b.ErrorCount != 0 {
		t.Fatalf("error count want 0, got %d", b.ErrorCount)
	}
}

func TestAnomalyDetectorErrorCount(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 10),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:        true,
			WindowBuckets:  10,
			BucketSeconds:  1,
			SigmaThreshold: 3.0,
			MinSamples:     2,
		},
	}

	ad.RecordRequest(50, http.StatusOK)
	ad.RecordRequest(50, http.StatusBadRequest)
	ad.RecordRequest(50, http.StatusInternalServerError)

	ad.mu.RLock()
	b := ad.buckets[ad.head]
	ad.mu.RUnlock()

	if b.ErrorCount != 2 {
		t.Fatalf("error count want 2, got %d", b.ErrorCount)
	}
}

func TestAnomalyDetectorCollectValid(t *testing.T) {
	ad := &AnomalyDetector{
		buckets: make([]TrafficBucket, 5),
		config: AnomalyConfig{
			BucketSeconds: 1,
		},
	}

	now := time.Now().Unix()
	// 填充 3 个 bucket
	ad.buckets[0] = TrafficBucket{Timestamp: now - 2, RequestCount: 1}
	ad.buckets[1] = TrafficBucket{Timestamp: now - 1, RequestCount: 2}
	ad.buckets[2] = TrafficBucket{Timestamp: now, RequestCount: 3}
	ad.head = 2
	ad.filled = false

	valid := ad.collectValid()
	if len(valid) != 3 {
		t.Fatalf("valid count want 3, got %d", len(valid))
	}
	if valid[2].RequestCount != 3 {
		t.Fatalf("last bucket request count want 3, got %d", valid[2].RequestCount)
	}
}

func TestAnomalyDetectorCollectValidFilled(t *testing.T) {
	ad := &AnomalyDetector{
		buckets: make([]TrafficBucket, 3),
		config: AnomalyConfig{
			BucketSeconds: 1,
		},
	}
	now := time.Now().Unix()
	ad.buckets[0] = TrafficBucket{Timestamp: now - 2, RequestCount: 10}
	ad.buckets[1] = TrafficBucket{Timestamp: now - 1, RequestCount: 20}
	ad.buckets[2] = TrafficBucket{Timestamp: now, RequestCount: 30}
	ad.head = 2
	ad.filled = true

	valid := ad.collectValid()
	if len(valid) != 3 {
		t.Fatalf("valid count want 3, got %d", len(valid))
	}
	// filled 时按 head+1 开始循环，顺序应为 bucket[0], bucket[1], bucket[2]
	if valid[0].RequestCount != 10 {
		t.Fatalf("first want 10, got %d", valid[0].RequestCount)
	}
	if valid[2].RequestCount != 30 {
		t.Fatalf("last want 30, got %d", valid[2].RequestCount)
	}
}

func TestAnomalyDetectorDisabled(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 10),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled: false,
		},
	}
	ad.RecordRequest(100, http.StatusOK)
	ad.mu.RLock()
	b := ad.buckets[ad.head]
	ad.mu.RUnlock()
	if b.RequestCount != 0 {
		t.Fatal("disabled detector should not record")
	}
}

func TestAnomalyDetectorNil(t *testing.T) {
	// nil detector 不应 panic
	var ad *AnomalyDetector
	ad.RecordRequest(100, http.StatusOK)
}

func TestAnomalyDetectorStatus(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 10),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:       true,
			BucketSeconds: 1,
		},
	}
	now := time.Now().Unix()
	ad.buckets[0] = TrafficBucket{Timestamp: now, RequestCount: 5, ErrorCount: 1, TotalLatencyMs: 500}
	ad.head = 0

	status := ad.Status()
	if status["enabled"] != true {
		t.Fatal("status enabled should be true")
	}
	if status["totalRequests"].(int64) != 5 {
		t.Fatalf("totalRequests want 5, got %v", status["totalRequests"])
	}
	if status["totalErrors"].(int64) != 1 {
		t.Fatalf("totalErrors want 1, got %v", status["totalErrors"])
	}
	avgLat := status["avgLatencyMs"].(float64)
	if math.Abs(avgLat-100) > 0.1 {
		t.Fatalf("avgLatency want 100, got %v", avgLat)
	}
}

func TestAnomalyDetectorAlertCooldown(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 60),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:          true,
			WindowBuckets:    60,
			BucketSeconds:    1,
			SigmaThreshold:   3.0,
			MinSamples:       2,
			AlertCooldownSec: 1,
		},
	}

	now := time.Now().Unix()
	// 建立历史基线：前 5 个 bucket 各 10 请求
	for i := 0; i < 5; i++ {
		ad.buckets[i] = TrafficBucket{
			Timestamp:    now - int64(5-i),
			RequestCount: 10,
		}
	}
	ad.head = 4
	ad.filled = false

	// 当前 bucket 突发 100 请求（远超 3σ）
	ad.buckets[5] = TrafficBucket{Timestamp: now + 1, RequestCount: 100}
	ad.head = 5

	ad.mu.Lock()
	ad.detectAnomalies()
	ad.mu.Unlock()

	if len(ad.alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(ad.alerts))
	}

	// 立即再次检测（冷却期内不应新增告警）
	ad.mu.Lock()
	ad.detectAnomalies()
	ad.mu.Unlock()
	if len(ad.alerts) != 1 {
		t.Fatalf("cooldown should prevent second alert, got %d", len(ad.alerts))
	}
}

func TestAnomalyDetectorSigmaDetection(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 20),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:          true,
			WindowBuckets:    20,
			BucketSeconds:    1,
			SigmaThreshold:   2.0,
			MinSamples:       5,
			AlertCooldownSec: 0,
		},
	}

	now := time.Now().Unix()
	// 10 个历史 bucket，每个 10 请求 → 均值=10，标准差=0
	for i := 0; i < 10; i++ {
		ad.buckets[i] = TrafficBucket{
			Timestamp:    now - int64(10-i),
			RequestCount: 10,
		}
	}
	ad.head = 9
	ad.filled = false

	// 当前 bucket 50 请求（5σ 偏离）
	ad.buckets[10] = TrafficBucket{Timestamp: now + 1, RequestCount: 50}
	ad.head = 10

	ad.mu.Lock()
	ad.detectAnomalies()
	ad.mu.Unlock()

	if len(ad.alerts) != 1 {
		t.Fatalf("expected 1 anomaly alert, got %d", len(ad.alerts))
	}
	alert := ad.alerts[0]
	if alert.Metric != "qps" {
		t.Fatalf("alert metric want qps, got %s", alert.Metric)
	}
	if alert.Severity != "critical" {
		t.Fatalf("50 req vs 10 baseline should be critical, got %s", alert.Severity)
	}
}

func TestAnomalyDetectorLatencyUpOnly(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 20),
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:          true,
			WindowBuckets:    20,
			BucketSeconds:    1,
			SigmaThreshold:   2.0,
			MinSamples:       5,
			AlertCooldownSec: 0,
		},
	}

	now := time.Now().Unix()
	// 历史基线：延迟 100ms
	for i := 0; i < 10; i++ {
		ad.buckets[i] = TrafficBucket{
			Timestamp:      now - int64(10-i),
			RequestCount:   10,
			TotalLatencyMs: 1000, // avg 100ms
		}
	}
	ad.head = 9

	// 当前延迟骤降（不应触发告警，因为只检测上浮）
	ad.buckets[10] = TrafficBucket{Timestamp: now + 1, RequestCount: 10, TotalLatencyMs: 10}
	ad.head = 10

	ad.mu.Lock()
	ad.detectAnomalies()
	ad.mu.Unlock()

	for _, a := range ad.alerts {
		if a.Metric == "latency" {
			t.Fatal("latency drop should not trigger anomaly alert")
		}
	}

	// 当前延迟暴涨
	ad.buckets[11] = TrafficBucket{Timestamp: now + 2, RequestCount: 10, TotalLatencyMs: 5000}
	ad.head = 11
	ad.lastAlerts = make(map[string]time.Time) // 重置冷却
	ad.lastAlert = time.Time{}

	ad.mu.Lock()
	ad.detectAnomalies()
	ad.mu.Unlock()

	found := false
	for _, a := range ad.alerts {
		if a.Metric == "latency" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("latency spike should trigger anomaly alert")
	}
}

func TestAnomalyDetectorBucketRotation(t *testing.T) {
	ad := &AnomalyDetector{
		buckets:    make([]TrafficBucket, 3),
		head:       2,
		lastAlerts: make(map[string]time.Time),
		config: AnomalyConfig{
			Enabled:       true,
			WindowBuckets: 3,
			BucketSeconds: 1,
		},
	}

	// 模拟跨 bucket 的记录
	base := time.Now().Unix()
	ad.RecordRequest(10, 200)
	ad.buckets[ad.head].Timestamp = base // 强制对齐

	ad.RecordRequest(20, 200)
	ad.buckets[ad.head].Timestamp = base + 1 // 下一个 bucket

	ad.RecordRequest(30, 200)
	ad.buckets[ad.head].Timestamp = base + 2

	ad.RecordRequest(40, 200)
	ad.buckets[ad.head].Timestamp = base + 3

	ad.mu.RLock()
	if !ad.filled {
		t.Fatal("should be filled after 4 writes into 3 buckets")
	}
	ad.mu.RUnlock()

	valid := ad.collectValid()
	if len(valid) != 3 {
		t.Fatalf("filled ring should have 3 valid buckets, got %d", len(valid))
	}
}

func TestRound2(t *testing.T) {
	if round2(3.14159) != 3.14 {
		t.Fatalf("round2(3.14159) want 3.14, got %v", round2(3.14159))
	}
	if round2(2.0) != 2 {
		t.Fatalf("round2(2.0) want 2, got %v", round2(2.0))
	}
}

func TestMetricLabel(t *testing.T) {
	if metricLabel("qps") != "每秒请求数" {
		t.Fatal("metricLabel qps wrong")
	}
	if metricLabel("errorRate") != "错误率" {
		t.Fatal("metricLabel errorRate wrong")
	}
	if metricLabel("latency") != "平均响应时间" {
		t.Fatal("metricLabel latency wrong")
	}
	if metricLabel("unknown") != "unknown" {
		t.Fatal("metricLabel unknown should fallback")
	}
}
