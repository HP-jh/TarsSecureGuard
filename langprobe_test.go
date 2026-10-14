package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Python 3.11.4\n", "3.11.4"},
		{"PowerShell 7.4.2\n", "7.4.2"},
		{"v18.17.0\n", "18.17.0"},
		{"GNU bash, version 5.1.16(1)-release\n", "5.1.16(1)-release"},
		{"", "unknown"},
		{"some text without version", "unknown"},
	}
	for _, c := range cases {
		got := parseVersion(c.in)
		if got != c.want {
			t.Errorf("parseVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSelectBestLangs(t *testing.T) {
	avail := []LangCapability{
		{Lang: "python3", Score: 95, Features: []string{"linux-firewall", "process-monitor", "log-parser"}},
		{Lang: "bash", Score: 60, Features: []string{"shell-script", "unix-pipe", "log-rotate"}},
	}
	m := selectBestLangs(avail)
	if m["firewall"] != "python3" {
		t.Errorf("firewall should select python3, got %s", m["firewall"])
	}
	if m["logging"] != "python3" {
		t.Errorf("logging should select python3, got %s", m["logging"])
	}

	// 无可用时回退 go
	empty := selectBestLangs(nil)
	if empty["firewall"] != "go" {
		t.Errorf("fallback should be go, got %s", empty["firewall"])
	}
}

func TestGenerateInstallTips(t *testing.T) {
	r := &CapabilityReport{
		Available: []LangCapability{{Lang: "bash", Score: 60}},
		Missing:   []string{"python3", "node"},
	}
	tips := generateInstallTips(r)
	if len(tips) == 0 {
		t.Fatal("expected some install tips")
	}
	// 第一个应该是 Python（优先级 1）
	if tips[0].Lang != "Python" {
		t.Errorf("first tip should be Python, got %s", tips[0].Lang)
	}
	if tips[0].Priority != 1 {
		t.Errorf("Python priority should be 1, got %d", tips[0].Priority)
	}
}

func TestScriptSandbox(t *testing.T) {
	sb := &ScriptSandbox{Timeout: 2 * time.Second, MaxOutput: 1024}
	ctx := context.Background()

	// 测试 echo
	var out []byte
	var err error
	if runtime.GOOS == "windows" {
		out, err = sb.RunScript(ctx, "cmd", "/c", "echo", "hello")
	} else {
		out, err = sb.RunScriptStdin(ctx, "sh", "echo hello")
	}
	if err != nil {
		t.Fatalf("sandbox run failed: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Errorf("expected hello in output, got %q", string(out))
	}
}

func TestRenderTemplate(t *testing.T) {
	tpl := `echo "{{.Name}}"`
	script, err := renderTemplate(tpl, map[string]interface{}{"Name": "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "test") {
		t.Errorf("expected test in script, got %q", script)
	}
}

func TestHasFeature(t *testing.T) {
	if !hasFeature([]string{"a", "b"}, "b") {
		t.Error("expected hasFeature true")
	}
	if hasFeature([]string{"a", "b"}, "c") {
		t.Error("expected hasFeature false")
	}
}

func TestLangProbeTargetsNotEmpty(t *testing.T) {
	if len(langProbeTargets) == 0 {
		t.Fatal("langProbeTargets should not be empty")
	}
	// 当前平台至少应该有 bash/sh
	found := false
	for _, t := range langProbeTargets {
		if t.Name == "bash" || t.Name == "sh" {
			found = true
			break
		}
	}
	if !found {
		t.Error("should have bash or sh in targets")
	}
}

func TestRunLangProbe(t *testing.T) {
	// 实际运行探测（不缓存）
	rep := runLangProbe()
	if rep == nil {
		t.Fatal("runLangProbe returned nil")
	}
	// 当前系统至少有 shell
	if len(rep.Available) == 0 && len(rep.Missing) == 0 {
		t.Error("expected some available or missing languages")
	}
	// Selected 应有映射
	if rep.Selected == nil {
		t.Error("Selected map should not be nil")
	}
}

func TestDoctorLangProbeChecks(t *testing.T) {
	checks := doctorLangProbeChecks()
	if len(checks) == 0 {
		t.Fatal("expected doctor checks")
	}
	if checks[0].Category != "语言探测" {
		t.Errorf("category should be 语言探测, got %s", checks[0].Category)
	}
}
