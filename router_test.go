package main

import (
	"math/rand"
	"testing"
	"time"
)

// TestRtPick_EmptyCandidates tests empty candidate handling
func TestRtPick_EmptyCandidates(t *testing.T) {
	candidates := []string{}
	backend, explored := rtPick(candidates)
	if backend != "" {
		t.Errorf("rtPick() with empty candidates should return empty string, got %q", backend)
	}
	if explored {
		t.Error("rtPick() with empty candidates should not explore")
	}
}

// TestRtPick_SingleCandidate tests single candidate handling
func TestRtPick_SingleCandidate(t *testing.T) {
	candidates := []string{"ollama"}
	backend, explored := rtPick(candidates)
	if backend != "ollama" {
		t.Errorf("rtPick() with single candidate should return it, got %q", backend)
	}
	if explored {
		t.Error("rtPick() with single candidate should not explore")
	}
}

// TestRtPick_MultipleCandidates tests epsilon-greedy selection
func TestRtPick_MultipleCandidates(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	candidates := []string{"llama", "lmstudio", "ollama"}

	// Run multiple picks to test both exploration and exploitation
	exploredCount := 0
	totalPicks := 100

	for i := 0; i < totalPicks; i++ {
		backend, explored := rtPick(candidates)
		if backend == "" {
			t.Error("rtPick() should return a backend")
		}
		if explored {
			exploredCount++
		}
	}

	// With epsilon=0.1, we expect ~10% exploration (±5% variance)
	expectedExplore := int(float64(totalPicks) * 0.1)
	tolerance := int(float64(totalPicks) * 0.05)
	if exploredCount < expectedExplore-tolerance || exploredCount > expectedExplore+tolerance {
		t.Errorf("rtPick() exploration rate = %d/%d, expected ~%d±%d", exploredCount, totalPicks, expectedExplore, tolerance)
	}
}

// TestRtPick_EpsilonDecay tests epsilon decay mechanism
func TestRtPick_EpsilonDecay(t *testing.T) {
	// Reset state with high epsilon
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.5,
	}
	rtMu.Unlock()

	candidates := []string{"llama", "ollama"}

	// Initial epsilon
	initialEps := rtCurrentEpsilon()

	// Run many picks to trigger decay
	for i := 0; i < 100; i++ {
		rtPick(candidates)
	}

	// Epsilon should have decayed
	finalEps := rtCurrentEpsilon()
	if finalEps >= initialEps {
		t.Errorf("rtPick() epsilon should decay, initial=%f, final=%f", initialEps, finalEps)
	}

	// Epsilon should not go below minimum
	_, minEps := rtEpsilonBounds()
	if finalEps < minEps {
		t.Errorf("rtPick() epsilon should not go below minimum %f, got %f", minEps, finalEps)
	}
}

// TestRtPick_Exploitation tests that high-performing backends are preferred
func TestRtPick_Exploitation(t *testing.T) {
	// Reset state with low epsilon for exploitation
	rtMu.Lock()
	rtSt = rtState{
		Arms: map[string]*rtArm{
			"good": {
				Calls:     100,
				Successes: 95,
				Failures:  5,
				RewSum:    90.0, // High reward
				AvgLatMs:  50.0,
			},
			"bad": {
				Calls:     100,
				Successes: 20,
				Failures:  80,
				RewSum:    -50.0, // Low reward
				AvgLatMs:  200.0,
			},
		},
		Decisions: 100,
		Epsilon:   0.02, // Low epsilon for exploitation
	}
	rtMu.Unlock()

	candidates := []string{"good", "bad"}

	// Count picks
	goodCount := 0
	badCount := 0
	totalPicks := 100

	for i := 0; i < totalPicks; i++ {
		backend, _ := rtPick(candidates)
		if backend == "good" {
			goodCount++
		} else if backend == "bad" {
			badCount++
		}
	}

	// Good backend should be picked much more often
	if goodCount < badCount {
		t.Errorf("rtPick() should prefer good backend, good=%d, bad=%d", goodCount, badCount)
	}

	// Good backend should be picked >80% of the time (with some exploration)
	if float64(goodCount)/float64(totalPicks) < 0.8 {
		t.Errorf("rtPick() good backend pick rate = %d/%d, expected >80%%", goodCount, totalPicks)
	}
}

// TestRtRecordOutcome_Success tests successful outcome recording
func TestRtRecordOutcome_Success(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	// Record successful outcome
	latency := 100 * time.Millisecond
	rtRecordOutcome("ollama", true, latency, "admin")

	rtMu.Lock()
	arm := rtSt.Arms["ollama"]
	rtMu.Unlock()

	if arm == nil {
		t.Fatal("rtRecordOutcome() should create arm entry")
	}
	if arm.Calls != 1 {
		t.Errorf("rtRecordOutcome() Calls = %d, want 1", arm.Calls)
	}
	if arm.Successes != 1 {
		t.Errorf("rtRecordOutcome() Successes = %d, want 1", arm.Successes)
	}
	if arm.Failures != 0 {
		t.Errorf("rtRecordOutcome() Failures = %d, want 0", arm.Failures)
	}
	if arm.RewSum <= 0 {
		t.Errorf("rtRecordOutcome() RewSum = %f, should be positive for success", arm.RewSum)
	}
}

// TestRtRecordOutcome_Failure tests failed outcome recording
func TestRtRecordOutcome_Failure(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	// Record failed outcome
	latency := 100 * time.Millisecond
	rtRecordOutcome("ollama", false, latency, "admin")

	rtMu.Lock()
	arm := rtSt.Arms["ollama"]
	rtMu.Unlock()

	if arm == nil {
		t.Fatal("rtRecordOutcome() should create arm entry")
	}
	if arm.Calls != 1 {
		t.Errorf("rtRecordOutcome() Calls = %d, want 1", arm.Calls)
	}
	if arm.Successes != 0 {
		t.Errorf("rtRecordOutcome() Successes = %d, want 0", arm.Successes)
	}
	if arm.Failures != 1 {
		t.Errorf("rtRecordOutcome() Failures = %d, want 1", arm.Failures)
	}
	if arm.RewSum >= 0 {
		t.Errorf("rtRecordOutcome() RewSum = %f, should be negative for failure", arm.RewSum)
	}
}

// TestRtRecordOutcome_NonAdminWeight tests non-admin weight reduction
func TestRtRecordOutcome_NonAdminWeight(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	latency := 100 * time.Millisecond

	// Record admin outcome
	rtRecordOutcome("admin_backend", true, latency, "admin")

	// Record non-admin outcome
	rtRecordOutcome("user_backend", true, latency, "user")

	rtMu.Lock()
	adminArm := rtSt.Arms["admin_backend"]
	userArm := rtSt.Arms["user_backend"]
	rtMu.Unlock()

	// Non-admin reward should be 10% of admin reward
	if adminArm.RewSum == 0 || userArm.RewSum == 0 {
		t.Fatal("rtRecordOutcome() should record rewards")
	}

	ratio := userArm.RewSum / adminArm.RewSum
	if ratio < 0.09 || ratio > 0.11 {
		t.Errorf("rtRecordOutcome() non-admin weight ratio = %f, expected ~0.1", ratio)
	}
}

// TestRtRecordOutcome_AvgLatency tests average latency calculation
func TestRtRecordOutcome_AvgLatency(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	// Record multiple outcomes with different latencies
	rtRecordOutcome("ollama", true, 100*time.Millisecond, "admin")
	rtRecordOutcome("ollama", true, 200*time.Millisecond, "admin")
	rtRecordOutcome("ollama", true, 300*time.Millisecond, "admin")

	rtMu.Lock()
	arm := rtSt.Arms["ollama"]
	rtMu.Unlock()

	// Average should be 200ms
	expectedAvg := 200.0
	if arm.AvgLatMs < expectedAvg-1 || arm.AvgLatMs > expectedAvg+1 {
		t.Errorf("rtRecordOutcome() AvgLatMs = %f, expected ~%f", arm.AvgLatMs, expectedAvg)
	}
}

// TestRtCandidates tests candidate discovery
func TestRtCandidates(t *testing.T) {
	candidates := rtCandidates()

	// Candidates should be a subset of known backends
	validBackends := map[string]bool{
		"llama":    true,
		"lmstudio": true,
		"ollama":   true,
	}

	for _, c := range candidates {
		if !validBackends[c] {
			t.Errorf("rtCandidates() returned unknown backend %q", c)
		}
	}
}

// TestRtEnabled tests router enabled state
func TestRtEnabled(t *testing.T) {
	enabled := rtEnabled()
	// Should return a boolean without error
	_ = enabled
}

// TestRtEpsilonBounds tests epsilon bounds
func TestRtEpsilonBounds(t *testing.T) {
	start, min := rtEpsilonBounds()

	if start <= 0 {
		t.Errorf("rtEpsilonBounds() start = %f, should be positive", start)
	}
	if min <= 0 {
		t.Errorf("rtEpsilonBounds() min = %f, should be positive", min)
	}
	if min > start {
		t.Errorf("rtEpsilonBounds() min = %f should be <= start = %f", min, start)
	}
}

// TestRtCurrentEpsilon tests current epsilon retrieval
func TestRtCurrentEpsilon(t *testing.T) {
	// Set a known epsilon
	rtMu.Lock()
	rtSt.Epsilon = 0.123
	rtMu.Unlock()

	eps := rtCurrentEpsilon()
	if eps != 0.123 {
		t.Errorf("rtCurrentEpsilon() = %f, want 0.123", eps)
	}
}

// TestRtPick_Concurrent tests concurrent safety
func TestRtPick_Concurrent(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	candidates := []string{"llama", "lmstudio", "ollama"}
	done := make(chan bool, 10)

	// Launch concurrent picks
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				rtPick(candidates)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 1000 decisions
	rtMu.Lock()
	decisions := rtSt.Decisions
	rtMu.Unlock()

	if decisions != 1000 {
		t.Errorf("rtPick() concurrent decisions = %d, want 1000", decisions)
	}
}

// TestRtRecordOutcome_Concurrent tests concurrent recording
func TestRtRecordOutcome_Concurrent(t *testing.T) {
	// Reset state
	rtMu.Lock()
	rtSt = rtState{
		Arms:      make(map[string]*rtArm),
		Decisions: 0,
		Epsilon:   0.1,
	}
	rtMu.Unlock()

	done := make(chan bool, 10)

	// Launch concurrent recordings
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				latency := time.Duration(rand.Intn(200)) * time.Millisecond
				rtRecordOutcome("ollama", rand.Float64() > 0.5, latency, "admin")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 1000 calls
	rtMu.Lock()
	arm := rtSt.Arms["ollama"]
	rtMu.Unlock()

	if arm == nil {
		t.Fatal("rtRecordOutcome() should create arm entry")
	}
	if arm.Calls != 1000 {
		t.Errorf("rtRecordOutcome() concurrent Calls = %d, want 1000", arm.Calls)
	}
}

// TestRtPick_LowSuccessRatePenalty tests penalty for low success rate backends
func TestRtPick_LowSuccessRatePenalty(t *testing.T) {
	// Reset state with one good and one bad backend
	rtMu.Lock()
	rtSt = rtState{
		Arms: map[string]*rtArm{
			"good": {
				Calls:     10,
				Successes: 9,
				Failures:  1,
				RewSum:    8.0,
				AvgLatMs:  50.0,
			},
			"bad": {
				Calls:     10,
				Successes: 1, // <20% success rate
				Failures:  9,
				RewSum:    -5.0,
				AvgLatMs:  200.0,
			},
		},
		Decisions: 20,
		Epsilon:   0.01, // Very low epsilon
	}
	rtMu.Unlock()

	candidates := []string{"good", "bad"}

	// Count picks
	goodCount := 0
	badCount := 0
	totalPicks := 100

	for i := 0; i < totalPicks; i++ {
		backend, _ := rtPick(candidates)
		if backend == "good" {
			goodCount++
		} else if backend == "bad" {
			badCount++
		}
	}

	// Good backend should be picked almost exclusively
	if goodCount < 95 {
		t.Errorf("rtPick() should heavily penalize low success rate, good=%d, bad=%d", goodCount, badCount)
	}
}
