package tripwire

import (
	"strings"
	"testing"
)

// TestV4201FalsePositiveRate 误报率基准测试：确保正常文本误报率 < 5%
// 覆盖中文、英文、代码、URL、Markdown 等常见场景
func TestV4201FalsePositiveRate(t *testing.T) {
	normalTexts := []string{
		"Hello world, this is a normal message.",
		"你好，这是一段正常的对话内容。",
		"The quick brown fox jumps over the lazy dog.",
		"今天的天气真不错，适合出去散步。",
		"func main() { fmt.Println(\"hello\") }",
		"package main\nimport \"fmt\"\nfunc main() {}",
		"https://example.com/path?query=value&foo=bar",
		"请访问 https://github.com/HP-jh/TarsSecureGuard 获取更多信息",
		"# Title\n\nThis is a markdown document with [link](https://example.com).",
		"- Item 1\n- Item 2\n- Item 3",
		"User login: admin, password: mySecurePass123!",
		"Contact us at support@example.com or call +1-234-567-8900",
		"API key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
		"The SHA256 hash is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"Hex value: 0xdeadbeef or 0xCAFEBABE",
		"UUID: 550e8400-e29b-41d4-a716-446655440000",
		"Color code: #FF5733 or rgb(255,87,51)",
		"npm install lodash --save-dev",
		"git commit -m \"feat: add new feature\" && git push origin main",
		"SELECT id, name FROM users WHERE active = 1 LIMIT 10",
		"curl -X POST https://api.example.com/v1/data -H \"Content-Type: application/json\" -d '{\"key\":\"value\"}'",
		"Base64: SGVsbG8gV29ybGQh",
		"Percent-encoded: %E4%BD%A0%E5%A5%BD%E4%B8%96%E7%95%8C",
		"JSON: {\"name\":\"test\",\"value\":123,\"enabled\":true}",
		"XML: <root><item>value</item></root>",
		"SQL injection is a security issue we should prevent.",
		"The system prompt shows the current configuration.",
		"Please ignore the previous message and start fresh.",
		"Simulate a user typing in the chat interface.",
		"Role: assistant, Mode: helpful, Language: auto-detect",
		"---\ntitle: Document\nauthor: User\n---\n\nContent here",
		"| Name | Value |\n|------|-------|\n| A    | 1     |",
		"```go\nfunc hello() {\n  return \"world\"\n}\n```",
		"$HOME/.config/app/settings.json",
		"export PATH=$PATH:/usr/local/bin",
		"sudo apt-get update && sudo apt-get install -y golang-go",
	}

	cfg := DefaultScanConfig()
	fpCount := 0
	for _, text := range normalTexts {
		res := Scan(text, cfg)
		if len(res.Findings) > 0 {
			fpCount++
			t.Logf("FP on: %q -> findings=%d", strings.TrimSpace(text[:min(60, len(text))]), len(res.Findings))
		}
	}

	rate := float64(fpCount) / float64(len(normalTexts)) * 100
	t.Logf("False positive rate: %.1f%% (%d/%d)", rate, fpCount, len(normalTexts))
	if rate > 5.0 {
		t.Fatalf("False positive rate %.1f%% exceeds 5%% threshold", rate)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
