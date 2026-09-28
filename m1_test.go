package main

// v3.0.0 M1 单元测试：守护器状态机 / 令牌桶 / IP 信誉评分
// 覆盖锦衣卫裁定点涉及的关键纯逻辑函数。

import (
	"testing"
	"time"
)

// ===================== 守护器状态机 =====================

func resetGuard() {
	guardMu.Lock()
	guardTier = guardL0
	guardSince = map[int]time.Time{}
	modelLoadFuse = false
	memLimit = 384 << 20
	guardMu.Unlock()
}

func TestTierHoldRequiresDuration(t *testing.T) {
	resetGuard()
	now := time.Now()
	// 刚满足阈值：只记时间，不触发
	if tierHold(guardL1, 65, now) {
		t.Fatal("首次超阈值不应立即触发")
	}
	// 持续 30 秒后触发
	if !tierHold(guardL1, 65, now.Add(31*time.Second)) {
		t.Fatal("持续 30 秒后应触发 L1")
	}
	// 阈值回落后重置计时
	delete(guardSince, guardL1)
	tierHold(guardL1, 55, now)
	if tierHold(guardL1, 65, now.Add(29*time.Second)) {
		t.Fatal("阈值中断后 29 秒不应触发")
	}
}

func TestTierRecoveredNeedsSustainedDrop(t *testing.T) {
	resetGuard()
	now := time.Now()
	if tierRecovered(guardL1, 45, now) {
		t.Fatal("首次回落不应立即恢复")
	}
	if !tierRecovered(guardL1, 45, now.Add(121*time.Second)) {
		t.Fatal("回落至 50% 以下持续 2 分钟应恢复")
	}
	// 占比回升则恢复计时重置
	delete(guardSince, 201)
	tierRecovered(guardL1, 45, now)
	if tierRecovered(guardL1, 55, now.Add(121*time.Second)) {
		t.Fatal("占比回升时不应恢复")
	}
}

func TestEnterTierL2SetsFuse(t *testing.T) {
	resetGuard()
	now := time.Now()
	enterTier(guardL2, now, 400, 90)
	guardMu.Lock()
	fuse := modelLoadFuse
	tier := guardTier
	guardMu.Unlock()
	if !fuse || tier != guardL2 {
		t.Fatal("L2 应设置模型加载熔断")
	}
	exitTier(guardL2, now, 200, 50)
	guardMu.Lock()
	fuse = modelLoadFuse
	tier = guardTier
	guardMu.Unlock()
	if fuse || tier != guardL0 {
		t.Fatal("L2 恢复应解除熔断并回到 L0")
	}
}

// ===================== 令牌桶 =====================

func TestTakeTokenQuota(t *testing.T) {
	rlBuckets = map[bucketKey]*tokenBucket{}
	k := bucketKey{dim: "ip", id: "1.2.3.4", cls: "chat"}
	// 额度 3：前 3 次通过，第 4 次拒绝
	for i := 0; i < 3; i++ {
		if !takeToken(k, 3) {
			t.Fatalf("第 %d 次应通过", i+1)
		}
	}
	if takeToken(k, 3) {
		t.Fatal("超额度应拒绝")
	}
}

func TestTakeTokenRefills(t *testing.T) {
	rlBuckets = map[bucketKey]*tokenBucket{}
	k := bucketKey{dim: "ip", id: "5.6.7.8", cls: "chat"}
	takeToken(k, 60)
	// 手动回拨上次补充时间 30 秒前：应补充 30 个（60/60*30）
	rlBucketMu.Lock()
	rlBuckets[k].lastRef = time.Now().Add(-30 * time.Second)
	rlBucketMu.Unlock()
	if !takeToken(k, 60) {
		t.Fatal("时间流逝后应补充令牌")
	}
}

// ===================== 端点分类 =====================

func TestEndpointClass(t *testing.T) {
	cases := map[string]string{
		"/api/chat/completions":    "chat",
		"/api/urgent/chat":         "chat",
		"/api/admin/models":         "model",
		"/api/admin/model/download": "model",
		"/api/admin/config":         "admin",
		"/api/search":               "other",
	}
	for path, want := range cases {
		if got := endpointClass(path); got != want {
			t.Errorf("endpointClass(%s) = %s, want %s", path, got, want)
		}
	}
}

// ===================== IP 信誉评分 =====================

func TestIPRepPenaltyAndBan(t *testing.T) {
	ipRepTable = map[string]*ipRepEntry{}
	ipRepPenalty("9.9.9.9", 30, "waf")
	ipRepPenalty("9.9.9.9", 30, "waf")
	if s := ipRepScore("9.9.9.9"); s != 40 {
		t.Fatalf("两次 -30 后应为 40，实际 %f", s)
	}
	// 白名单与本地回环不扣分
	ipRepTable = map[string]*ipRepEntry{}
	ipRepPenalty("127.0.0.1", 30, "waf")
	if s := ipRepScore("127.0.0.1"); s != 100 {
		t.Fatalf("回环不应扣分，实际 %f", s)
	}
}

func TestIPRep404WindowPerMinute(t *testing.T) {
	ipRepTable = map[string]*ipRepEntry{}
	// 同一分钟内多次 404 只扣一次
	ipRepPenalty("8.8.8.8", 10, "scan404")
	ipRepPenalty("8.8.8.8", 10, "scan404")
	ipRepPenalty("8.8.8.8", 10, "scan404")
	if s := ipRepScore("8.8.8.8"); s != 90 {
		t.Fatalf("每分钟窗口内应只扣一次（期望 90，实际 %f）", s)
	}
}

func TestIPRepTickRecovery(t *testing.T) {
	ipRepTable = map[string]*ipRepEntry{}
	// 恢复场景：被封禁且 24h 无新扣分 → 恢复 60
	ipRepTable["7.7.7.7"] = &ipRepEntry{
		Score: 30, LastPenalty: time.Now().Add(-25 * time.Hour),
		BannedAt: time.Now().Add(-25 * time.Hour), distinctSrcs: map[string]bool{},
	}
	ipRepTick()
	if s := ipRepScore("7.7.7.7"); s != 60 {
		t.Fatalf("24h 无新扣分应恢复至 60，实际 %f", s)
	}
	// 每小时回升：低分条目 1 小时后 +2
	ipRepTable["6.6.6.6"] = &ipRepEntry{
		Score: 80, LastPenalty: time.Now().Add(-90 * time.Minute),
		distinctSrcs: map[string]bool{},
	}
	ipRepTick()
	if s := ipRepScore("6.6.6.6"); s != 82 {
		t.Fatalf("每小时应回升 2 分，实际 %f", s)
	}
}

func TestIPRepUnban(t *testing.T) {
	ipRepTable = map[string]*ipRepEntry{}
	ipRepPenalty("5.5.5.5", 70, "waf")
	ipRepUnban("tester", "5.5.5.5")
	if s := ipRepScore("5.5.5.5"); s != 100 {
		t.Fatalf("解封后应恢复 100，实际 %f", s)
	}
}
