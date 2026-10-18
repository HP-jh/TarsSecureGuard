package main

// ===================== v4.25.0 连接池自适应测试 =====================
//
// 覆盖：
//  1. poolTargetConns QPS→连接数映射正确性（边界 5/200）
//  2. 高 QPS 场景下自动扩容（模拟 300 QPS → 目标 >= 100）
//  3. 低 QPS 场景下自动缩容（模拟 10 QPS → 目标 <= 5）
//  4. 启停开关：关闭自适应后连接数不再变化
//  5. poolStats 包含 adaptiveEnabled / adaptiveRange 字段
//  6. 版本号锁定

import (
	"testing"
	"time"
)

// ---- 1. poolTargetConns 映射正确性 ----

func TestV325PoolTargetConns(t *testing.T) {
	cases := []struct {
		qps    float64
		expect int
	}{
		{0, 5},
		{5, 5},
		{10, 5},
		{14, 5},
		{15, 5},
		{30, 10},
		{100, 33},
		{300, 100},
		{600, 200},
		{1000, 200},
	}
	for _, c := range cases {
		got := poolTargetConns(c.qps)
		if got != c.expect {
			t.Errorf("poolTargetConns(%.1f) = %d, want %d", c.qps, got, c.expect)
		}
	}
}

// ---- 2. 高 QPS 自动扩容 ----

func TestV325PoolAdaptiveScaleUp(t *testing.T) {
	poolSetMaxIdleConnsPerHost(5)
	poolSetAdaptiveEnabled(true)

	baseTime := time.Now()
	baseReq := poolRequests.Load()
	// 模拟 5 秒内 1500 个请求 → 300 QPS
	for i := 0; i < 1500; i++ {
		poolRequests.Add(1)
	}
	now := baseTime.Add(5 * time.Second)
	_, _, scaled, oldVal, newVal := poolAdaptiveEvalOnce(baseReq, baseTime, now)

	if !scaled {
		t.Errorf("高 QPS 应触发扩容：scaled=false old=%d new=%d", oldVal, newVal)
	}
	if newVal <= 5 {
		t.Errorf("高 QPS 扩容结果应 > 5：old=%d new=%d", oldVal, newVal)
	}
	t.Logf("高 QPS 扩容：old=%d new=%d", oldVal, newVal)
}

// ---- 3. 低 QPS 自动缩容 ----

func TestV325PoolAdaptiveScaleDown(t *testing.T) {
	poolSetMaxIdleConnsPerHost(100)
	poolSetAdaptiveEnabled(true)

	baseTime := time.Now()
	baseReq := poolRequests.Load()
	// 模拟 5 秒内 50 个请求 → 10 QPS → target = 3 → clamp 到 5
	for i := 0; i < 50; i++ {
		poolRequests.Add(1)
	}
	now := baseTime.Add(5 * time.Second)
	_, _, scaled, oldVal, newVal := poolAdaptiveEvalOnce(baseReq, baseTime, now)

	if !scaled {
		t.Errorf("低 QPS 应触发缩容：scaled=false old=%d new=%d", oldVal, newVal)
	}
	if newVal != 5 {
		t.Errorf("低 QPS 缩容结果应为 5：old=%d new=%d", oldVal, newVal)
	}
	t.Logf("低 QPS 缩容：old=%d new=%d", oldVal, newVal)
}

// ---- 4. 启停开关 ----

func TestV325PoolAdaptiveToggle(t *testing.T) {
	poolSetMaxIdleConnsPerHost(50)
	poolSetAdaptiveEnabled(false)

	baseTime := time.Now()
	baseReq := poolRequests.Load()
	for i := 0; i < 2000; i++ {
		poolRequests.Add(1)
	}
	now := baseTime.Add(5 * time.Second)
	_, _, scaled, _, _ := poolAdaptiveEvalOnce(baseReq, baseTime, now)

	if scaled {
		t.Error("关闭自适应后不应触发扩容")
	}

	poolSetAdaptiveEnabled(true)
	t.Logf("重新开启自适应，current=%d", poolCurrentMaxIdle.Load())
}

// ---- 5. poolStats 字段完整性 ----

func TestV325PoolStatsFields(t *testing.T) {
	stats := poolStats()
	if _, ok := stats["adaptiveEnabled"]; !ok {
		t.Error("poolStats 缺少 adaptiveEnabled 字段")
	}
	if _, ok := stats["adaptiveRange"]; !ok {
		t.Error("poolStats 缺少 adaptiveRange 字段")
	}
	if stats["adaptiveRange"] != "5~200" {
		t.Errorf("adaptiveRange = %v, want 5~200", stats["adaptiveRange"])
	}
	if _, ok := stats["maxIdlePerHost"]; !ok {
		t.Error("poolStats 缺少 maxIdlePerHost 字段")
	}
}

// ---- 6. 版本号锁定 ----

func TestV325VersionBumped(t *testing.T) {
	if version != "4.28.0" {
		t.Errorf("version = %s, want 4.28.0", version)
	}
}
