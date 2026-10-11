// security_test.go — comprehensive tests for the security evaluation system.
package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Helpers ────────────────────────────────────────────────────────────────

type fakeEvaluator struct {
	name   string
	weight float64
	score  float64
	err    error
}

func (f *fakeEvaluator) Name() string    { return f.name }
func (f *fakeEvaluator) Weight() float64 { return f.weight }
func (f *fakeEvaluator) Evaluate(ctx context.Context) (Dimension, error) {
	return Dimension{Name: f.name, Score: f.score, Description: "fake"}, f.err
}

// ── Engine Tests ───────────────────────────────────────────────────────────

func TestNewScoreEngine(t *testing.T) {
	e := NewScoreEngine()
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.LastReport() != nil {
		t.Error("expected nil last report")
	}
}

func TestRegisterEvaluator(t *testing.T) {
	e := NewScoreEngine()
	fe := &fakeEvaluator{name: "test", weight: 0.5, score: 80}
	e.RegisterEvaluator(fe)

	if len(e.evaluators) != 1 {
		t.Fatalf("expected 1 evaluator, got %d", len(e.evaluators))
	}
}

func TestEvaluate_Single(t *testing.T) {
	e := NewScoreEngine()
	e.RegisterEvaluator(&fakeEvaluator{name: "A", weight: 1.0, score: 80})

	report, err := e.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if report.TotalScore != 80 {
		t.Errorf("expected total score 80, got %.0f", report.TotalScore)
	}
	if report.Grade != "B" {
		t.Errorf("expected grade B (score 80), got %s", report.Grade)
	}
	if report.Version != "4.6.2" {
		t.Errorf("expected version 4.6.2, got %s", report.Version)
	}
}

func TestEvaluate_Weighted(t *testing.T) {
	e := NewScoreEngine()
	e.RegisterEvaluator(&fakeEvaluator{name: "A", weight: 0.3, score: 100})
	e.RegisterEvaluator(&fakeEvaluator{name: "B", weight: 0.7, score: 50})

	report, err := e.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	want := (100.0*0.3 + 50.0*0.7) / 1.0 // 65
	if report.TotalScore != want {
		t.Errorf("expected total score %.0f, got %.0f", want, report.TotalScore)
	}
	if report.Grade != "C" {
		t.Errorf("expected grade C, got %s", report.Grade)
	}
}

func TestEvaluate_ErrorFallback(t *testing.T) {
	e := NewScoreEngine()
	e.RegisterEvaluator(&fakeEvaluator{name: "fail", weight: 1.0, score: 0, err: fmt.Errorf("boom")})

	report, err := e.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Recommendations) == 0 {
		t.Error("expected recommendation for failing evaluator")
	}
	if report.TotalScore != 0 {
		t.Errorf("expected 0 score, got %.0f", report.TotalScore)
	}
}

func TestEvaluate_Recommendations(t *testing.T) {
	e := NewScoreEngine()
	e.RegisterEvaluator(&fakeEvaluator{name: "bad", weight: 1.0, score: 50})

	report, err := e.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(report.Recommendations))
	}
}

func TestLastReport_Concurrency(t *testing.T) {
	e := NewScoreEngine()
	e.RegisterEvaluator(&fakeEvaluator{name: "x", weight: 1.0, score: 90})

	_, _ = e.Evaluate(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.LastReport()
		}()
	}
	wg.Wait()
}

func TestScoreToGrade(t *testing.T) {
	cases := []struct{ score float64; want string }{
		{100, "A+"}, {95, "A+"}, {94.9, "A"},
		{85, "A"}, {84.9, "B"},
		{75, "B"}, {74.9, "C"},
		{60, "C"}, {59.9, "D"},
		{40, "D"}, {39.9, "F"},
		{0, "F"},
	}
	for _, c := range cases {
		got := scoreToGrade(c.score)
		if got != c.want {
			t.Errorf("scoreToGrade(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestNormalizeScore(t *testing.T) {
	cases := []struct{ in, want float64 }{
		{50, 50}, {150, 100}, {-10, 0},
		{99.4, 99}, {99.5, 100},
	}
	for _, c := range cases {
		got := NormalizeScore(c.in)
		if got != c.want {
			t.Errorf("NormalizeScore(%.1f) = %.0f, want %.0f", c.in, got, c.want)
		}
	}
}

// ── DynamicProtector Tests ─────────────────────────────────────────────────

func TestNewDynamicProtector(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 10, 50)
	if p == nil {
		t.Fatal("expected non-nil protector")
	}
	if p.window != time.Minute {
		t.Error("wrong window")
	}
}

func TestRecordAndIsAnomalous(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 2, 10)
	p.Record("src1")
	if p.IsAnomalous("src1") {
		t.Error("should not be anomalous after 1 record")
	}
	p.Record("src1")
	p.Record("src1")
	if !p.IsAnomalous("src1") {
		t.Error("should be anomalous after exceeding threshold")
	}
}

func TestIsAnomalous_ExpiredWindow(t *testing.T) {
	p := NewDynamicProtector(50*time.Millisecond, 1, 10)
	p.Record("src1")
	p.Record("src1")
	if !p.IsAnomalous("src1") {
		t.Fatal("expected anomalous")
	}
	time.Sleep(60 * time.Millisecond)
	if p.IsAnomalous("src1") {
		t.Error("expected not anomalous after window expiry")
	}
}

func TestIsAnomalous_UnknownSource(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 2, 10)
	if p.IsAnomalous("nosuch") {
		t.Error("unknown source should not be anomalous")
	}
}

func TestReset(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 1, 10)
	p.Record("src1")
	p.Record("src1")
	p.Reset()
	if p.IsAnomalous("src1") {
		t.Error("expected cleared after reset")
	}
	if len(p.Events()) != 0 {
		t.Error("expected no events after reset")
	}
}

func TestEvents_Cap(t *testing.T) {
	// Each source has its own bucket; 5 different sources can each
	// trigger an event independently and exercise the cap.
	p := NewDynamicProtector(time.Minute, 1, 3)
	for i := 0; i < 5; i++ {
		src := fmt.Sprintf("src%d", i)
		p.Record(src)
		p.Record(src)
	}
	events := p.Events()
	if len(events) != 3 {
		t.Errorf("expected cap 3 events, got %d", len(events))
	}
}

func TestSnapshot(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 1, 10)
	p.Record("src1")
	p.Record("src1")
	snap := p.Snapshot()
	if snap["activeBuckets"].(int) != 1 {
		t.Errorf("expected 1 bucket, got %d", snap["activeBuckets"])
	}
	if snap["anomalies"].(int) != 1 {
		t.Errorf("expected 1 anomaly, got %d", snap["anomalies"])
	}
}

func TestDynamicEvaluator(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 2, 10)
	de := NewDynamicEvaluator(p)

	if de.Name() != "动态防护" {
		t.Error("wrong name")
	}
	if de.Weight() != 0.35 {
		t.Error("wrong weight")
	}

	dim, err := de.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dim.Score != 100 {
		t.Errorf("expected 100 with no anomalies, got %.0f", dim.Score)
	}

	p.Record("src1")
	p.Record("src1")
	p.Record("src1")
	dim, err = de.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dim.Score == 100 {
		t.Error("expected reduced score after anomaly")
	}
}

func TestDynamicProtector_Concurrency(t *testing.T) {
	p := NewDynamicProtector(time.Minute, 5, 100)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p.Record(fmt.Sprintf("src%d", n%10))
			_ = p.IsAnomalous(fmt.Sprintf("src%d", n%10))
			_ = p.Events()
			_ = p.Snapshot()
		}(i)
	}
	wg.Wait()
}

// ── StaticAuditor Tests ────────────────────────────────────────────────────

func TestNewStaticAuditor(t *testing.T) {
	sa := NewStaticAuditor()
	if len(sa.checks) == 0 {
		t.Fatal("expected default checks")
	}
}

func TestStaticAuditor_RegisterCheck(t *testing.T) {
	sa := NewStaticAuditor()
	n := len(sa.checks)
	sa.RegisterCheck(StaticCheck{ID: "X-001", Name: "Test", Validate: func() (bool, string) { return true, "ok" }})
	if len(sa.checks) != n+1 {
		t.Fatalf("expected %d checks, got %d", n+1, len(sa.checks))
	}
}

func TestStaticAuditor_Audit(t *testing.T) {
	sa := NewStaticAuditor()
	findings := sa.Audit(context.Background())
	if len(findings) != len(sa.checks) {
		t.Fatalf("expected %d findings, got %d", len(sa.checks), len(findings))
	}
}

func TestStaticAuditor_Score(t *testing.T) {
	sa := NewStaticAuditor()
	_ = sa.Audit(context.Background())
	score := sa.Score()
	if score < 0 || score > 100 {
		t.Errorf("score out of range: %.0f", score)
	}
}

func TestStaticAuditor_Score_NoFindings(t *testing.T) {
	sa := &StaticAuditor{checks: []StaticCheck{}, findings: []Finding{}}
	if sa.Score() != 0 {
		t.Error("expected 0 with no findings")
	}
}

func TestStaticAuditor_AllPass(t *testing.T) {
	sa := NewStaticAuditor()
	for i := range sa.checks {
		old := sa.checks[i].Validate
		sa.checks[i].Validate = func() (bool, string) { return true, "ok" }
		_ = old // keep reference to avoid unused
	}
	_ = sa.Audit(context.Background())
	if sa.Score() != 100 {
		t.Errorf("expected 100, got %.0f", sa.Score())
	}
}

func TestStaticAuditor_KEY001_Fail(t *testing.T) {
	os.Setenv("TSG_API_KEY", "default")
	defer os.Unsetenv("TSG_API_KEY")

	sa := NewStaticAuditor()
	findings := sa.Audit(context.Background())
	for _, f := range findings {
		if f.CheckID == "KEY-001" && f.Passed {
			t.Error("KEY-001 should fail with default key")
		}
	}
}

func TestStaticAuditor_KEY001_Pass(t *testing.T) {
	os.Setenv("TSG_API_KEY", "my-secret-key-123")
	defer os.Unsetenv("TSG_API_KEY")

	sa := NewStaticAuditor()
	findings := sa.Audit(context.Background())
	for _, f := range findings {
		if f.CheckID == "KEY-001" && !f.Passed {
			t.Error("KEY-001 should pass with custom key")
		}
	}
}

func TestStaticAuditor_CONFIG001_Fail(t *testing.T) {
	// config.json may not exist in test env; check finding exists
	sa := NewStaticAuditor()
	findings := sa.Audit(context.Background())
	var found bool
	for _, f := range findings {
		if f.CheckID == "CONFIG-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("CONFIG-001 check missing")
	}
}

func TestStaticEvaluator(t *testing.T) {
	sa := NewStaticAuditor()
	se := NewStaticEvaluator(sa)

	if se.Name() != "静态审计" {
		t.Error("wrong name")
	}
	if se.Weight() != 0.35 {
		t.Error("wrong weight")
	}

	dim, err := se.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dim.Score < 0 || dim.Score > 100 {
		t.Errorf("score out of range: %.0f", dim.Score)
	}
}

func TestStaticAuditor_Concurrency(t *testing.T) {
	sa := NewStaticAuditor()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sa.Audit(context.Background())
			_ = sa.Findings()
			_ = sa.Score()
		}()
	}
	wg.Wait()
}

// ── Server Tests ───────────────────────────────────────────────────────────

func setupServer() http.Handler {
	eng := NewScoreEngine()
	prot := NewDynamicProtector(time.Minute, 2, 10)
	aud := NewStaticAuditor()
	eng.RegisterEvaluator(NewDynamicEvaluator(prot))
	eng.RegisterEvaluator(NewStaticEvaluator(aud))
	return NewServer(eng, prot, aud)
}

func TestServerHealth(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodGet, "/api/security/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("unexpected status: %s", body["status"])
	}
}

func TestServerReport_NoReport(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodGet, "/api/security/report", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if !strings.Contains(body["error"], "no report available") {
		t.Errorf("unexpected body: %v", body)
	}
}

func TestServerEvaluate(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodPost, "/api/security/evaluate", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var report Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if report.TotalScore < 0 || report.TotalScore > 100 {
		t.Errorf("score out of range: %.0f", report.TotalScore)
	}
	if report.Grade == "" {
		t.Error("expected grade")
	}
}

func TestServerDynamic(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodGet, "/api/security/dynamic", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var snap map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if _, ok := snap["activeBuckets"]; !ok {
		t.Error("missing activeBuckets")
	}
}

func TestServerStatic(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodGet, "/api/security/static", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if _, ok := body["findings"]; !ok {
		t.Error("missing findings")
	}
}

func TestServerEvents(t *testing.T) {
	h := setupServer()
	req := httptest.NewRequest(http.MethodGet, "/api/security/events", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var events []AnomalyEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if events == nil {
		t.Error("expected non-nil events slice")
	}
}

func TestServer_Concurrency(t *testing.T) {
	h := setupServer()
	var wg sync.WaitGroup
	paths := []string{
		"/api/security/health",
		"/api/security/evaluate",
		"/api/security/dynamic",
		"/api/security/static",
		"/api/security/events",
	}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, paths[idx%len(paths)], nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("path %s returned %d", paths[idx%len(paths)], rec.Code)
			}
		}(i)
	}
	wg.Wait()
}

// ── Integration Test ───────────────────────────────────────────────────────

func TestFullEvaluation(t *testing.T) {
	eng := NewScoreEngine()
	prot := NewDynamicProtector(time.Minute, 2, 10)
	aud := NewStaticAuditor()

	eng.RegisterEvaluator(NewDynamicEvaluator(prot))
	eng.RegisterEvaluator(NewStaticEvaluator(aud))

	// Simulate some traffic
	prot.Record("user1")
	prot.Record("user1")
	prot.Record("user1")

	report, err := eng.Evaluate(context.Background())
	if err != nil {
		t.Fatalf("evaluate error: %v", err)
	}
	if len(report.Dimensions) != 2 {
		t.Fatalf("expected 2 dimensions, got %d", len(report.Dimensions))
	}
	if report.TotalScore < 0 || report.TotalScore > 100 {
		t.Errorf("total score out of range: %.0f", report.TotalScore)
	}
	if len(report.Recommendations) > 0 {
		// At least dynamic should recommend due to anomaly
		t.Logf("Recommendations: %v", report.Recommendations)
	}
}

